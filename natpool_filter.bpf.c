// SPDX-License-Identifier: GPL-2.0
/*
 * natpool_filter — XDP filter that protects CGNAT / NAT-pool addresses on a
 * router against SYN/ACK-reflection carpet floods (plus UDP amplification and
 * bogus TCP flag combinations). Attach it to the uplink ingress; if that is a
 * bond, the kernel bonding driver delegates the program to the active slaves,
 * so it sees ingress traffic on every VLAN carried over the bond.
 *
 * When the router carries symmetric transit for a range (both the outbound
 * client SYN and the returning SYN/ACK traverse this ingress hook), one program
 * can both RECORD outbound SYNs and FILTER returning SYN/ACKs, with no separate
 * tc-egress program.
 *
 * Two traffic classes, keyed by destination address (prefix_class LPM trie):
 *   CLASS_NATPOOL — CGNAT/SNAT pool prefixes (tracked). A legit reply always has
 *                   a kernel conntrack entry; we look it up via bpf_xdp_ct_lookup
 *                   and drop SYN/ACKs with none. No own state — reuses the kernel.
 *   CLASS_ROUTED  — routed public client prefixes that are notrack in nftables
 *                   (kernel keeps NO state). We keep a minimal LRU of outbound
 *                   client SYN 4-tuples and drop SYN/ACKs that match none. This
 *                   class only works where inbound traffic is symmetric (enters
 *                   through this hook); it is off by default.
 *
 * Default (cfg all-zero) is count-only: nothing is dropped, only counters and
 * the LRU are maintained. Rollback is a plain detach from the interface.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "natpool_filter.h"

char _license[] SEC("license") = "GPL";

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
/* struct udphdr comes from vmlinux.h. IP fragment-offset mask (13 low bits of
 * frag_off, network order): nonzero => a non-first fragment (no L4 header). */
#define IP_FRAG_OFFSET_MASK 0x1FFF
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif
#define UDP_RATE_INTERVAL_NS 1000000000ULL /* detector tick ~1s; udp_pps = count/tick */
#define UDP_PPS_THRESHOLD_DEFAULT 200000   /* per-IP pps to engage; tune below your scrubber's UDP ban level */

/* bpf_ct_opts normally lives in the nf_conntrack module BTF, so it is absent
 * from vmlinux.h; on kernels with nf_conntrack built-in it IS in vmlinux.h.
 * Define a local copy under a CO-RE "flavor" name (the ___local suffix is
 * ignored for BTF matching, same pattern as kernel selftests) so both cases
 * compile. 16-byte layout (netns_id, error, l4proto, dir, ct_zone_id,
 * ct_zone_dir, reserved[3]); opts__sz passed to the kfunc must equal
 * sizeof(this). */
struct bpf_ct_opts___local {
	__s32 netns_id;
	__s32 error;
	__u8  l4proto;
	__u8  dir;
	__u16 ct_zone_id;
	__u8  ct_zone_dir;
	__u8  reserved[3];
};

/* Unstable CT lookup kfuncs (netfilter, kernel >= 5.19). Provided by the
 * nf_conntrack module BTF; the verifier resolves them at load time. */
struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *xdp_ctx,
				  struct bpf_sock_tuple *bpf_tuple,
				  __u32 tuple__sz,
				  struct bpf_ct_opts___local *opts,
				  __u32 opts__sz) __ksym;
void bpf_ct_release(struct nf_conn *ct) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key);
	__type(value, __u8);
	__uint(max_entries, 8192);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} prefix_class SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, __u64);
	__uint(max_entries, 1048576); /* ~1M outbound SYNs; ample RTT-scale history */
} syn_seen SEC(".maps");

/* Measurement-only: SYN/ACK 4-tuples that missed state, with a repeat counter.
 * A repeat = the same reflector retransmitting => amplification signal. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct flow_key);
	__type(value, __u32);
	__uint(max_entries, 1048576);
} synack_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct config);
	__uint(max_entries, 1);
} cfg SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, __ST_MAX);
} stats SEC(".maps");

/* Per-pool-IP UDP packet counter for the auto-detector: incremented per inbound
 * UDP-to-pool packet, scanned & reset every ~1s by the bpf_timer. A single pool
 * IP over the threshold => udp_engage. ~3072 pool IPs -> 4096 slots. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __be32);
	__type(value, __u64);
	__uint(max_entries, 4096);
} udp_pps SEC(".maps");

struct tmr_val {
	struct bpf_timer t;
	__u64 last_max_pps;   /* observability: max per-IP pps seen in the last tick */
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct tmr_val);
	__uint(max_entries, 1);
} tmr SEC(".maps");

static __u64 timer_armed;   /* one-shot guard for lazy timer arming (.bss; 64-bit CAS) */

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&stats, &idx);
	if (v)
		(*v)++;
}

/* Measurement: record a missing-state SYN/ACK by its own 4-tuple and count
 * retransmissions (repeat sightings). Runs before the drop decision so it also
 * measures under DROP mode. Keyed by the SYN/ACK as received (server->client). */
static __always_inline void measure_miss(struct iphdr *ip, struct tcphdr *tcp)
{
	struct flow_key k = {
		.saddr = ip->saddr,
		.daddr = ip->daddr,
		.sport = tcp->source,
		.dport = tcp->dest,
	};
	__u32 *seen = bpf_map_lookup_elem(&synack_seen, &k);

	if (seen) {
		(*seen)++;
		bump(ST_MISS_REPEAT);
	} else {
		__u32 one = 1;

		bpf_map_update_elem(&synack_seen, &k, &one, BPF_ANY);
		bump(ST_MISS_UNIQUE);
	}
}

/* Longest-prefix classify of a single address. Query key length is always /32;
 * the trie returns the most specific matching entry (routed /32 wins over a
 * pool /24 should they ever overlap — they are generated disjoint). */
static __always_inline __u8 classify(__be32 addr)
{
	struct lpm_key k = { .prefixlen = 32, .addr = addr };
	__u8 *c = bpf_map_lookup_elem(&prefix_class, &k);

	return c ? *c : 0;
}

/* Shared conntrack-lookup primitive for the NAT-pool class, used by both the
 * TCP (SYN/ACK) and UDP paths. Returns 1 if a kernel conntrack entry exists for
 * the given tuple (legit reply), 0 if none (unsolicited). The gating — which
 * packets even reach this — differs per protocol and stays in the caller. */
static __always_inline __u8 natpool_ct_found(struct xdp_md *ctx,
					     __be32 saddr, __be32 daddr,
					     __be16 sport, __be16 dport,
					     __u8 l4proto)
{
	struct bpf_sock_tuple tup = {};

	tup.ipv4.saddr = saddr;
	tup.ipv4.daddr = daddr;
	tup.ipv4.sport = sport;
	tup.ipv4.dport = dport;

	struct bpf_ct_opts___local opts = {
		.netns_id = -1,
		.l4proto = l4proto,
	};
	struct nf_conn *ct = bpf_xdp_ct_lookup(ctx, &tup, sizeof(tup.ipv4),
					       &opts, sizeof(opts));
	if (ct) {
		bpf_ct_release(ct);
		return 1;
	}
	return 0;
}

/* Stateless TCP flag sanity. These combinations are never produced by a valid
 * stack — they are scans (null/XMAS), evasion, or forgery. Pure ALU on flag bits,
 * no map access, so the caller can run it on every TCP packet for free. */
static __always_inline __u8 bad_tcp_flags(const struct tcphdr *t)
{
	if (!t->syn && !t->fin && !t->rst && !t->psh && !t->ack && !t->urg)
		return 1; /* null scan */
	if (t->syn && t->fin)
		return 1; /* SYN+FIN */
	if (t->syn && t->rst)
		return 1; /* SYN+RST */
	if (t->fin && t->psh && t->urg)
		return 1; /* XMAS */
	if (t->fin && !t->ack)
		return 1; /* FIN without ACK */
	return 0;
}

/* Detector callbacks (auto UDP engage). scan_cb finds the max per-IP count in
 * the current interval and resets each counter; rate_tick (bpf_timer, ~1s) sets
 * udp_engage if any pool IP exceeded udp_pps_threshold, then re-arms. */
struct scan_ctx { __u64 max; };

static long scan_cb(struct bpf_map *map, const void *key, void *value, void *ctx)
{
	__u64 *val = value;
	struct scan_ctx *sc = ctx;

	if (*val > sc->max)
		sc->max = *val;
	*val = 0;
	return 0;
}

static int rate_tick(void *map, __u32 *key, struct tmr_val *tv)
{
	struct scan_ctx sc = { .max = 0 };

	bpf_for_each_map_elem(&udp_pps, scan_cb, &sc, 0);
	tv->last_max_pps = sc.max;

	__u32 z = 0;
	struct config *c = bpf_map_lookup_elem(&cfg, &z);
	if (c && c->udp_auto) {
		__u32 thr = c->udp_pps_threshold ? c->udp_pps_threshold
						 : UDP_PPS_THRESHOLD_DEFAULT;
		__u8 eng = (sc.max >= thr) ? 1 : 0;

		c->udp_engage = eng;
		if (eng)
			bump(ST_UDP_ENGAGE_TICKS);
	}
	bpf_timer_start(&tv->t, UDP_RATE_INTERVAL_NS, 0);
	return 0;
}

SEC("xdp")
int natpool_filter(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	bump(ST_PKTS);

	/* Lazy one-shot arm of the detector timer (first packet after load). */
	if (!timer_armed) {
		__u32 z = 0;
		struct tmr_val *tv = bpf_map_lookup_elem(&tmr, &z);

		if (tv && __sync_val_compare_and_swap(&timer_armed, 0, 1) == 0) {
			bpf_timer_init(&tv->t, &tmr, CLOCK_MONOTONIC);
			bpf_timer_set_callback(&tv->t, rate_tick);
			bpf_timer_start(&tv->t, UDP_RATE_INTERVAL_NS, 0);
		}
	}

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	__u16 h_proto = eth->h_proto;
	void *cursor = (void *)(eth + 1);

	/* Tolerate 0..2 VLAN tags. With rx-vlan-offload the tag is stripped into
	 * metadata and invisible here, so an untagged frame is normal too. */
#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto != bpf_htons(ETH_P_8021Q) &&
		    h_proto != bpf_htons(ETH_P_8021AD))
			break;
		struct vlan_hdr {
			__be16 h_vlan_TCI;
			__be16 h_vlan_encapsulated_proto;
		} *vh = cursor;
		if ((void *)(vh + 1) > data_end)
			return XDP_PASS;
		h_proto = vh->h_vlan_encapsulated_proto;
		cursor = (void *)(vh + 1);
	}

	if (h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = cursor;
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	__u32 ihl = ip->ihl * 4;
	if (ihl < sizeof(*ip))
		return XDP_PASS;

	__u32 zero = 0;
	struct config *c = bpf_map_lookup_elem(&cfg, &zero);

	/* UDP — only the NAT pool (class 1). Public routed clients (class 2) may
	 * receive UDP initiated from outside and are asymmetric anyway, so UDP is
	 * pool-only. Peacetime is cheap: bump a counter and PASS; the conntrack
	 * lookup runs only when udp_engage is set (rate detector / manual).
	 * Fragments (variant a): non-first fragments have no L4 header, so we PASS
	 * them — dropping the first fragment orphans the rest (kernel defrag never
	 * completes) and we must not blind-drop non-first frags (legit fragmented
	 * DNS/EDNS0 responses). */
	if (ip->protocol == IPPROTO_UDP) {
		if (classify(ip->daddr) != CLASS_NATPOOL)
			return XDP_PASS;
		bump(ST_NATPOOL_UDP_SEEN);
		/* Cheap per-IP rate signal for the detector (scanned by bpf_timer).
		 * This is the only per-packet work in peacetime — no conntrack. */
		__be32 dip = ip->daddr;
		__u64 *pc = bpf_map_lookup_elem(&udp_pps, &dip);
		if (pc) {
			__sync_fetch_and_add(pc, 1);
		} else {
			__u64 one = 1;
			bpf_map_update_elem(&udp_pps, &dip, &one, BPF_NOEXIST);
		}
		if (!c || !c->udp_engage)
			return XDP_PASS;
		if (ip->frag_off & bpf_htons(IP_FRAG_OFFSET_MASK))
			return XDP_PASS;
		struct udphdr *udp = (void *)ip + ihl;
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		if (natpool_ct_found(ctx, ip->saddr, ip->daddr,
				     udp->source, udp->dest, IPPROTO_UDP)) {
			bump(ST_NATPOOL_UDP_HIT);
			return XDP_PASS;
		}
		bump(ST_NATPOOL_UDP_MISS);
		if (c->drop_natpool_udp) {
			bump(ST_NATPOOL_UDP_DROP);
			return XDP_DROP;
		}
		return XDP_PASS;
	}

	if (ip->protocol != IPPROTO_TCP)
		return XDP_PASS;

	struct tcphdr *tcp = (void *)ip + ihl;
	if ((void *)(tcp + 1) > data_end)
		return XDP_PASS;

	/* Never-legitimate TCP flag combinations aimed at the pool. Checked before
	 * the SYN paths so a SYN+FIN can't be recorded as an outbound client SYN.
	 * bad_tcp_flags() is pure ALU on flag bits we already loaded; the LPM
	 * classify() runs only for the (vanishingly rare) bad packet, so the common
	 * path pays nothing and this can stay always-on. */
	if (bad_tcp_flags(tcp) && classify(ip->daddr) == CLASS_NATPOOL) {
		bump(ST_BADFLAGS_SEEN);
		if (c && c->drop_bad_flags) {
			bump(ST_BADFLAGS_DROP);
			return XDP_DROP;
		}
		return XDP_PASS;
	}

	/* Outbound client SYN (pure SYN): record it so we can later recognise the
	 * matching return SYN/ACK. Only for routed /32 clients (notrack class). */
	if (tcp->syn && !tcp->ack) {
		if ((!c || c->record_routed) && classify(ip->saddr) == CLASS_ROUTED) {
			struct flow_key k = {
				.saddr = ip->saddr,
				.daddr = ip->daddr,
				.sport = tcp->source,
				.dport = tcp->dest,
			};
			__u64 now = bpf_ktime_get_ns();

			bpf_map_update_elem(&syn_seen, &k, &now, BPF_ANY);
			bump(ST_RECORDED);
		}
		return XDP_PASS;
	}

	/* From here we only care about SYN+ACK. */
	if (!(tcp->syn && tcp->ack))
		return XDP_PASS;
	bump(ST_SYNACK);

	__u8 dc = classify(ip->daddr);

	if (dc == CLASS_NATPOOL) {
		if (natpool_ct_found(ctx, ip->saddr, ip->daddr,
				     tcp->source, tcp->dest, IPPROTO_TCP)) {
			bump(ST_NATPOOL_HIT);
			return XDP_PASS;
		}
		bump(ST_NATPOOL_MISS);
		if (!c || c->measure_amp)
			measure_miss(ip, tcp);
		if (c && c->drop_natpool) {
			bump(ST_NATPOOL_DROP);
			return XDP_DROP;
		}
		return XDP_PASS;
	}

	if (dc == CLASS_ROUTED) {
		/* Reverse the SYN/ACK back to the outbound SYN tuple we recorded. */
		struct flow_key k = {
			.saddr = ip->daddr,
			.daddr = ip->saddr,
			.sport = tcp->dest,
			.dport = tcp->source,
		};
		if (bpf_map_lookup_elem(&syn_seen, &k)) {
			bump(ST_ROUTED_HIT);
			return XDP_PASS;
		}
		bump(ST_ROUTED_MISS);
		if (!c || c->measure_amp)
			measure_miss(ip, tcp);
		if (c && c->drop_routed) {
			bump(ST_ROUTED_DROP);
			return XDP_DROP;
		}
		return XDP_PASS;
	}

	bump(ST_NOCLASS);
	return XDP_PASS;
}
