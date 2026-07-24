// SPDX-License-Identifier: GPL-2.0
/*
 * loader — userspace control tool for natpool_filter.bpf.o.
 *
 *   loader load <prefixes_file>   load the program, pin everything under
 *                                 /sys/fs/bpf/natpool, populate the prefix trie,
 *                                 set count-only mode (nothing dropped)
 *   loader attach <ifname>        attach the pinned program to an interface
 *                                 (XDP native/driver mode). Use bond0.
 *   loader detach <ifname>        detach from an interface
 *   loader set <k=v> ...          set cfg flags: drop_natpool, drop_routed,
 *                                 record_routed (0/1)
 *   loader stats                  print per-CPU counters (summed)
 *   loader unload                 remove all pins (detach interfaces first)
 *
 * The pinned maps let bpftool inspect/prog-run the program independently.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "natpool_filter.h"

#define PIN_DIR   "/sys/fs/bpf/natpool"
#define OBJ_NAME  "natpool_filter.bpf.o"

/* Absolute path to the BPF object, resolved next to this executable so the
 * loader works from any CWD (e.g. init.d/firewall calling it by full path).
 * Follows symlinks via /proc/self/exe, so a symlinked install dir works too. */
static char obj_path[PATH_MAX + 32];

static void resolve_obj_path(void)
{
	char self[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);

	if (n > 0) {
		self[n] = '\0';
		char *slash = strrchr(self, '/');
		if (slash)
			*slash = '\0';
		snprintf(obj_path, sizeof(obj_path), "%s/%s", self, OBJ_NAME);
	} else {
		snprintf(obj_path, sizeof(obj_path), "%s", OBJ_NAME);
	}
}

static const char *stat_names[__ST_MAX] = {
	[ST_PKTS]         = "packets_total",
	[ST_SYNACK]       = "synack_seen",
	[ST_NATPOOL_HIT]  = "natpool_ct_hit",
	[ST_NATPOOL_MISS] = "natpool_ct_miss",
	[ST_NATPOOL_DROP] = "natpool_dropped",
	[ST_ROUTED_HIT]   = "routed_lru_hit",
	[ST_ROUTED_MISS]  = "routed_lru_miss",
	[ST_ROUTED_DROP]  = "routed_dropped",
	[ST_RECORDED]     = "outbound_syn_recorded",
	[ST_NOCLASS]      = "synack_no_class_pass",
	[ST_MISS_UNIQUE]  = "miss_unique_flows",
	[ST_MISS_REPEAT]  = "miss_retransmissions",
	[ST_NATPOOL_UDP_SEEN] = "natpool_udp_seen",
	[ST_NATPOOL_UDP_HIT]  = "natpool_udp_hit",
	[ST_NATPOOL_UDP_MISS] = "natpool_udp_miss",
	[ST_NATPOOL_UDP_DROP] = "natpool_udp_dropped",
	[ST_UDP_ENGAGE_TICKS] = "udp_engage_ticks",
	[ST_BADFLAGS_SEEN]    = "tcp_badflags_seen",
	[ST_BADFLAGS_DROP]    = "tcp_badflags_dropped",
};

static int map_fd(const char *name)
{
	char path[256];

	snprintf(path, sizeof(path), "%s/%s", PIN_DIR, name);
	int fd = bpf_obj_get(path);
	if (fd < 0)
		fprintf(stderr, "open pinned map %s: %s\n", path, strerror(errno));
	return fd;
}

/* Remove the pins this loader owns (maps + program) but deliberately KEEP any
 * bpf_link pins. The link holds a reference to the currently attached program,
 * so it keeps filtering while the new object is loaded; a following 'attach'
 * then swaps the new program into that same link atomically. That is what makes
 * 'load + attach' a gapless upgrade instead of detach/attach. */
static void clear_object_pins(void)
{
	DIR *d = opendir(PIN_DIR);
	struct dirent *e;
	char path[512];

	if (!d)
		return;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.' || !strncmp(e->d_name, "link_", 5))
			continue;
		snprintf(path, sizeof(path), "%s/%s", PIN_DIR, e->d_name);
		unlink(path);
	}
	closedir(d);
}

static int do_load(const char *prefixes)
{
	struct bpf_object *obj;
	int err;

	/* Fresh-load defaults: count-only, outbound-SYN recording on, UDP detector
	 * armed but cheap (engage off), per-IP threshold at a conservative default. */
	struct config c = { .drop_natpool = 0, .drop_routed = 0,
			    .record_routed = 1, .measure_amp = 1,
			    .drop_natpool_udp = 0, .udp_engage = 0,
			    .udp_auto = 1, .drop_bad_flags = 0,
			    .udp_pps_threshold = 200000 };
	int carried = 0;

	/* Upgrade path: carry the RUNNING policy over instead of reverting to the
	 * defaults. Read the old cfg before its pin is cleared, so 'load + attach'
	 * swaps the program without ever dropping back to count-only. udp_engage is
	 * deliberately reset — it is detector state, and the new program starts with
	 * empty rate counters; the timer re-derives it within a tick. */
	{
		int oldcfg = bpf_obj_get(PIN_DIR "/cfg");

		if (oldcfg >= 0) {
			__u32 z = 0;
			struct config prev;

			if (!bpf_map_lookup_elem(oldcfg, &z, &prev)) {
				c = prev;
				c.udp_engage = 0;
				carried = 1;
			}
			close(oldcfg);
		}
	}

	obj = bpf_object__open_file(obj_path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed: %s\n", obj_path, strerror(errno));
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %s\n", strerror(-err));
		return 1;
	}

	if (mkdir(PIN_DIR, 0755) && errno != EEXIST) {
		fprintf(stderr, "mkdir %s: %s\n", PIN_DIR, strerror(errno));
		return 1;
	}
	clear_object_pins();
	err = bpf_object__pin(obj, PIN_DIR);
	if (err) {
		fprintf(stderr, "pin to %s failed: %s\n", PIN_DIR, strerror(-err));
		return 1;
	}

	int cfg = map_fd("cfg");
	if (cfg < 0)
		return 1;
	__u32 zero = 0;
	bpf_map_update_elem(cfg, &zero, &c, BPF_ANY);

	/* populate prefix_class */
	int pref = map_fd("prefix_class");
	if (pref < 0)
		return 1;
	FILE *f = fopen(prefixes, "r");
	if (!f) {
		fprintf(stderr, "open %s: %s\n", prefixes, strerror(errno));
		return 1;
	}
	char line[128];
	unsigned long n = 0;
	while (fgets(line, sizeof(line), f)) {
		char *h = strchr(line, '#');
		if (h)
			*h = '\0';
		char addr[64];
		int plen, cls;
		if (sscanf(line, "%63[^/]/%d %d", addr, &plen, &cls) != 3)
			continue;
		struct lpm_key k = { .prefixlen = (unsigned)plen };
		if (inet_pton(AF_INET, addr, &k.addr) != 1) {
			fprintf(stderr, "bad addr: %s\n", addr);
			continue;
		}
		__u8 v = (__u8)cls;
		if (bpf_map_update_elem(pref, &k, &v, BPF_ANY)) {
			fprintf(stderr, "add %s/%d: %s\n", addr, plen, strerror(errno));
			continue;
		}
		n++;
	}
	fclose(f);
	printf("loaded, pinned to %s, %lu prefixes, %s\n", PIN_DIR, n,
	       carried ? "carried over running config" : "count-only mode");
	return 0;
}

/* Path of the pinned bpf_link for an interface. The link (not the legacy netlink
 * attachment) owns the XDP program, which buys two things: an upgrade can swap
 * the program atomically with bpf_link_update (no detach/attach gap where the
 * filter is off), and no other process can clobber our attachment. */
static void link_path(char *buf, size_t sz, const char *ifname)
{
	snprintf(buf, sz, "%s/link_%s", PIN_DIR, ifname);
}

static int do_attach(const char *ifname)
{
	int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "no such interface: %s\n", ifname);
		return 1;
	}
	char progpath[256], linkpath[256];
	snprintf(progpath, sizeof(progpath), "%s/natpool_filter", PIN_DIR);
	link_path(linkpath, sizeof(linkpath), ifname);

	int prog = bpf_obj_get(progpath);
	if (prog < 0) {
		fprintf(stderr, "open pinned prog %s: %s\n", progpath, strerror(errno));
		return 1;
	}

	/* An existing pinned link means the filter is already attached: swap the new
	 * program into it in place. Traffic never sees a moment without the filter. */
	int lfd = bpf_obj_get(linkpath);
	if (lfd >= 0) {
		int err = bpf_link_update(lfd, prog, NULL);
		close(lfd);
		close(prog);
		if (err) {
			fprintf(stderr, "swap program on %s failed: %s\n",
				ifname, strerror(errno));
			return 1;
		}
		printf("program swapped in place on %s (bpf_link, no traffic gap)\n", ifname);
		return 0;
	}

	/* First attach: create the link and pin it. */
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = XDP_FLAGS_DRV_MODE);
	lfd = bpf_link_create(prog, ifindex, BPF_XDP, &opts);
	if (lfd < 0) {
		fprintf(stderr, "attach to %s (bpf_link, drv mode) failed: %s\n",
			ifname, strerror(errno));
		if (errno == EBUSY)
			fprintf(stderr, "  (an XDP program is already attached the legacy "
					"way — run '%s detach %s' first)\n", "loader", ifname);
		close(prog);
		return 1;
	}
	if (bpf_obj_pin(lfd, linkpath)) {
		fprintf(stderr, "pin link %s: %s\n", linkpath, strerror(errno));
		close(lfd);
		close(prog);
		return 1;
	}
	close(lfd);
	close(prog);
	printf("attached to %s (bpf_link, driver mode)\n", ifname);
	return 0;
}

static int do_detach(const char *ifname)
{
	char linkpath[256];
	link_path(linkpath, sizeof(linkpath), ifname);

	/* Dropping the pin releases the last reference to the link, which detaches
	 * the program. Falls back to the legacy netlink detach for a filter that was
	 * attached by an older loader build. */
	int lfd = bpf_obj_get(linkpath);
	if (lfd >= 0) {
		close(lfd);
		if (unlink(linkpath)) {
			fprintf(stderr, "unpin link %s: %s\n", linkpath, strerror(errno));
			return 1;
		}
		printf("detached from %s (bpf_link removed)\n", ifname);
		return 0;
	}

	int ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "no such interface: %s\n", ifname);
		return 1;
	}
	int err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	if (err) {
		fprintf(stderr, "detach from %s failed: %s\n", ifname, strerror(-err));
		return 1;
	}
	printf("detached from %s (legacy netlink)\n", ifname);
	return 0;
}

static int do_set(int argc, char **argv)
{
	int fd = map_fd("cfg");
	if (fd < 0)
		return 1;
	__u32 zero = 0;
	struct config c = {};
	if (bpf_map_lookup_elem(fd, &zero, &c)) {
		fprintf(stderr, "read cfg: %s\n", strerror(errno));
		return 1;
	}
	for (int i = 0; i < argc; i++) {
		int v;
		if (sscanf(argv[i], "drop_natpool=%d", &v) == 1)
			c.drop_natpool = !!v;
		else if (sscanf(argv[i], "drop_routed=%d", &v) == 1)
			c.drop_routed = !!v;
		else if (sscanf(argv[i], "record_routed=%d", &v) == 1)
			c.record_routed = !!v;
		else if (sscanf(argv[i], "measure_amp=%d", &v) == 1)
			c.measure_amp = !!v;
		else if (sscanf(argv[i], "drop_natpool_udp=%d", &v) == 1)
			c.drop_natpool_udp = !!v;
		else if (sscanf(argv[i], "udp_engage=%d", &v) == 1)
			c.udp_engage = !!v;
		else if (sscanf(argv[i], "udp_auto=%d", &v) == 1)
			c.udp_auto = !!v;
		else if (sscanf(argv[i], "drop_bad_flags=%d", &v) == 1)
			c.drop_bad_flags = !!v;
		else if (sscanf(argv[i], "udp_pps_threshold=%d", &v) == 1)
			c.udp_pps_threshold = (v < 0) ? 0 : (__u32)v;
		else {
			fprintf(stderr, "unknown setting: %s\n", argv[i]);
			return 1;
		}
	}
	if (bpf_map_update_elem(fd, &zero, &c, BPF_ANY)) {
		fprintf(stderr, "write cfg: %s\n", strerror(errno));
		return 1;
	}
	printf("cfg: drop_natpool=%d drop_routed=%d record_routed=%d measure_amp=%d "
	       "drop_natpool_udp=%d udp_engage=%d udp_auto=%d drop_bad_flags=%d "
	       "udp_pps_threshold=%u\n",
	       c.drop_natpool, c.drop_routed, c.record_routed, c.measure_amp,
	       c.drop_natpool_udp, c.udp_engage, c.udp_auto, c.drop_bad_flags,
	       c.udp_pps_threshold);
	return 0;
}

static int do_stats(void)
{
	int fd = map_fd("stats");
	if (fd < 0)
		return 1;
	int ncpu = libbpf_num_possible_cpus();
	if (ncpu < 0)
		ncpu = 1;
	__u64 *vals = calloc(ncpu, sizeof(__u64));
	if (!vals)
		return 1;
	for (__u32 i = 0; i < __ST_MAX; i++) {
		if (bpf_map_lookup_elem(fd, &i, vals))
			continue;
		__u64 sum = 0;
		for (int c = 0; c < ncpu; c++)
			sum += vals[c];
		printf("%-24s %llu\n", stat_names[i] ? stat_names[i] : "?",
		       (unsigned long long)sum);
	}
	free(vals);
	return 0;
}

int main(int argc, char **argv)
{
	resolve_obj_path();

	if (argc < 2)
		goto usage;

	if (!strcmp(argv[1], "load") && argc == 3)
		return do_load(argv[2]);
	if (!strcmp(argv[1], "attach") && argc == 3)
		return do_attach(argv[2]);
	if (!strcmp(argv[1], "detach") && argc == 3)
		return do_detach(argv[2]);
	if (!strcmp(argv[1], "set") && argc >= 3)
		return do_set(argc - 2, argv + 2);
	if (!strcmp(argv[1], "stats") && argc == 2)
		return do_stats();
	if (!strcmp(argv[1], "unload") && argc == 2) {
		char cmd[256];
		snprintf(cmd, sizeof(cmd), "rm -rf %s", PIN_DIR);
		return system(cmd);
	}
usage:
	fprintf(stderr,
		"usage:\n"
		"  %s load <prefixes_file>\n"
		"  %s attach <ifname>\n"
		"  %s detach <ifname>\n"
		"  %s set drop_natpool=0|1 drop_routed=0|1 record_routed=0|1 measure_amp=0|1\n"
		"      [drop_natpool_udp=0|1] [udp_engage=0|1] [udp_auto=0|1]\n"
		"      [drop_bad_flags=0|1] [udp_pps_threshold=N]\n"
		"  %s stats\n"
		"  %s unload\n",
		argv[0], argv[0], argv[0], argv[0], argv[0], argv[0]);
	return 1;
}
