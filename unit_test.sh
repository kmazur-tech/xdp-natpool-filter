#!/bin/bash
# Unit / integration tests for natpool_filter via BPF_PROG_TEST_RUN (bpftool).
# Run on a host with the program already loaded (loader load ...); a standby /
# lab box is ideal. Builds synthetic packets, runs them through the pinned prog,
# and asserts the XDP verdict plus the relevant per-CPU counter deltas. Also
# creates a real conntrack entry to exercise the CLASS_NATPOOL ct_lookup hit path.
#
# Addresses below are RFC 5737 (documentation) / RFC 6598 (CGNAT) — they must be
# consistent with the example pools.conf / client_ranges.conf shipped in the repo.
#
# Nothing here attaches or detaches: the reload below refreshes only the object
# pins (maps/prog) and deliberately leaves the bpf_link alone, so a filter that
# is attached keeps running the previously loaded program throughout. Afterwards,
# './loader attach <ifname>' swaps the freshly loaded program into that link.
set -u

PROG=/sys/fs/bpf/natpool/natpool_filter
DIR=/tmp/natpool_test
mkdir -p "$DIR"

NATPOOL_IP=192.0.2.10      # inside 192.0.2.0/24 (class 1, a NAT pool)
ROUTED_IP=203.0.113.2      # inside 203.0.113.0/24 (class 2, a routed client range)
SERVER_IP=198.51.100.10    # "internet" peer (neither class)
OTHER_IP=198.18.0.1        # neither class (RFC 2544 benchmarking range)
CT_POOL_DPORT=54321        # reply dport of the synthetic conntrack entry

PASS=2
DROP=1
fail=0

# --- packet builder (python3) --------------------------------------------
gen_pkt() {
	# gen_pkt <outfile> <ethertype_hex> <vlan_count> <saddr> <daddr> <sport> <dport> <flags>
	# flags: comma list of syn,ack,rst
	python3 - "$@" <<'PY'
import sys, struct, socket
out, eth_t, vlanc, s, d, sp, dp, flags = sys.argv[1:9]
vlanc=int(vlanc); sp=int(sp); dp=int(dp)
fl=set(flags.split(',')) if flags else set()
def ipv4(a): return socket.inet_aton(a)
eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566")
l2 = eth
proto_after = int(eth_t,16)
# push VLAN tags if requested (outer ethertype becomes 0x8100)
tags=b""
if vlanc>0:
    for i in range(vlanc):
        # each tag: TCI(2)=vlan 100, then inner ethertype
        inner = 0x0800 if i==vlanc-1 else 0x8100
        tags += struct.pack("!HH", 100, inner)
    l2 = eth + struct.pack("!H", 0x8100) + tags
    # remove: the first ethertype is 0x8100 (set above), inner chain set
else:
    l2 = eth + struct.pack("!H", proto_after)
tcp_flags = ((0x02 if 'syn' in fl else 0)|(0x10 if 'ack' in fl else 0)|(0x04 if 'rst' in fl else 0)
            |(0x01 if 'fin' in fl else 0)|(0x08 if 'psh' in fl else 0)|(0x20 if 'urg' in fl else 0))
tcp = struct.pack("!HHIIBBHHH", sp,dp,0,0,(5<<4),tcp_flags,8192,0,0)
tot = 20+len(tcp)
ip = struct.pack("!BBHHHBBH", 0x45,0,tot,1,0,64,6,0)+ipv4(s)+ipv4(d)
pkt = l2+ip+tcp
open(out,"wb").write(pkt)
PY
}

run() {
	# run <pktfile> ; echo retval
	bpftool -j prog run pinned "$PROG" data_in "$1" data_out "$DIR/out.bin" repeat 1 2>/dev/null \
		| grep -oE '"retval":[0-9]+' | grep -oE '[0-9]+'
}

stat() { ./loader stats 2>/dev/null | awk -v k="$1" '$1==k{print $2}'; }

check() {
	# check <name> <got_retval> <want_retval> <counter> <want_delta> <before>
	local name="$1" got="$2" want="$3" ctr="$4" wantd="$5" before="$6"
	local after delta; after=$(stat "$ctr"); delta=$((after-before))
	if [ "$got" = "$want" ] && [ "$delta" = "$wantd" ]; then
		printf "  PASS  %-28s retval=%s %s+%s\n" "$name" "$got" "$ctr" "$delta"
	else
		printf "  FAIL  %-28s retval=%s(want %s) %s+%s(want %s)\n" \
			"$name" "$got" "$want" "$ctr" "$delta" "$wantd"
		fail=1
	fi
}

# Fresh reload so the run is idempotent — the LRU maps (synack_seen) persist
# across runs, and the amplification test (T10) needs a clean first-sighting.
# 'load' alone is enough: it clears the map/prog pins but keeps any bpf_link, so
# this never detaches a live filter (unlike 'unload', which removes the link too).
./loader load prefixes.conf >/dev/null 2>&1 || { echo "load failed (need prefixes.conf in CWD)"; exit 1; }
# Pin the starting policy explicitly: 'load' now carries the RUNNING config over
# (so a production upgrade never reverts to count-only), which means the tests
# must not assume load's fresh-install defaults.
./loader set drop_natpool=0 drop_routed=0 record_routed=1 measure_amp=1 	drop_natpool_udp=0 udp_engage=0 udp_auto=0 drop_bad_flags=0 >/dev/null

echo "=== building packets ==="
gen_pkt "$DIR/t1_sa_pool.bin"      0800 0 "$SERVER_IP" "$NATPOOL_IP" 80 "$CT_POOL_DPORT" syn,ack
gen_pkt "$DIR/t3_syn_routed.bin"   0800 0 "$ROUTED_IP" "$SERVER_IP"  12345 80 syn
gen_pkt "$DIR/t4_sa_routed.bin"    0800 0 "$SERVER_IP" "$ROUTED_IP"  80 12345 syn,ack
gen_pkt "$DIR/t5_sa_routed2.bin"   0800 0 "$SERVER_IP" "$ROUTED_IP"  80 55555 syn,ack
gen_pkt "$DIR/t6_vlan_pool.bin"    0800 1 "$SERVER_IP" "$NATPOOL_IP" 80 40000 syn,ack
gen_pkt "$DIR/t7_udp_like.bin"     0800 0 "$SERVER_IP" "$NATPOOL_IP" 80 40000 ack
gen_pkt "$DIR/t8_noclass.bin"      0800 0 "$SERVER_IP" "$OTHER_IP"   80 40000 syn,ack
gen_pkt "$DIR/t10_fresh_miss.bin"  0800 0 "$SERVER_IP" "$ROUTED_IP"  80 44444 syn,ack

echo "=== T1: SYN/ACK -> NAT pool, no conntrack, count-only => PASS + ct_miss ==="
b=$(stat natpool_ct_miss); r=$(run "$DIR/t1_sa_pool.bin")
check "natpool miss/pass" "$r" "$PASS" natpool_ct_miss 1 "$b"

echo "=== T2: same, drop_natpool=1 => DROP + dropped ==="
./loader set drop_natpool=1 >/dev/null
b=$(stat natpool_dropped); r=$(run "$DIR/t1_sa_pool.bin")
check "natpool drop" "$r" "$DROP" natpool_dropped 1 "$b"
./loader set drop_natpool=0 >/dev/null

echo "=== T3: outbound SYN from routed client => PASS + recorded ==="
b=$(stat outbound_syn_recorded); r=$(run "$DIR/t3_syn_routed.bin")
check "routed syn record" "$r" "$PASS" outbound_syn_recorded 1 "$b"

echo "=== T4: matching SYN/ACK back to routed client => PASS + lru_hit ==="
b=$(stat routed_lru_hit); r=$(run "$DIR/t4_sa_routed.bin")
check "routed lru hit" "$r" "$PASS" routed_lru_hit 1 "$b"

echo "=== T5: SYN/ACK to routed client, no recorded SYN, drop_routed=1 => DROP ==="
./loader set drop_routed=1 >/dev/null
b=$(stat routed_dropped); r=$(run "$DIR/t5_sa_routed2.bin")
check "routed drop" "$r" "$DROP" routed_dropped 1 "$b"
./loader set drop_routed=0 >/dev/null

echo "=== T6: VLAN-tagged SYN/ACK -> pool => parsed, counted as synack ==="
b=$(stat synack_seen); r=$(run "$DIR/t6_vlan_pool.bin")
check "vlan parse synack" "$r" "$PASS" synack_seen 1 "$b"

echo "=== T7: pure ACK (not SYN/ACK) -> pool => PASS, synack NOT counted ==="
b=$(stat synack_seen); r=$(run "$DIR/t7_udp_like.bin")
check "non-synack ignored" "$r" "$PASS" synack_seen 0 "$b"

echo "=== T8: SYN/ACK to unclassified dst => PASS + no_class ==="
b=$(stat synack_no_class_pass); r=$(run "$DIR/t8_noclass.bin")
check "no-class pass" "$r" "$PASS" synack_no_class_pass 1 "$b"

echo "=== T9: CLASS_NATPOOL conntrack HIT (real conntrack entry) ==="
conntrack -D -s 100.64.0.5 >/dev/null 2>&1
if conntrack -I -p tcp -t 120 --state ESTABLISHED \
	-s 100.64.0.5 -d "$SERVER_IP" --sport 40000 --dport 80 \
	-r "$SERVER_IP" -q "$NATPOOL_IP" --reply-port-src 80 --reply-port-dst "$CT_POOL_DPORT" \
	>/dev/null 2>&1; then
	b=$(stat natpool_ct_hit); r=$(run "$DIR/t1_sa_pool.bin")
	check "natpool ct hit" "$r" "$PASS" natpool_ct_hit 1 "$b"
	conntrack -D -s 100.64.0.5 >/dev/null 2>&1
else
	echo "  SKIP  could not insert synthetic conntrack entry"
fi

echo "=== T10: amplification measurement — repeated miss SYN/ACK => retransmission ==="
# fresh 4-tuple never seen before: first sighting = unique flow, second identical
# packet = a retransmission (the amplification signal).
bu=$(stat miss_unique_flows); r=$(run "$DIR/t10_fresh_miss.bin")
check "miss first=unique" "$r" "$PASS" miss_unique_flows 1 "$bu"
br=$(stat miss_retransmissions); r=$(run "$DIR/t10_fresh_miss.bin")
check "miss repeat=retrans" "$r" "$PASS" miss_retransmissions 1 "$br"

gen_udp() {
	# gen_udp <outfile> <saddr> <daddr> <sport> <dport> <frag_off>
	python3 - "$@" <<'PY'
import sys, struct, socket
out, s, d, sp, dp, frag = sys.argv[1:7]
sp=int(sp); dp=int(dp); frag=int(frag)
eth = bytes.fromhex("aabbccddeeff") + bytes.fromhex("112233445566") + struct.pack("!H", 0x0800)
udp = struct.pack("!HHHH", sp, dp, 8, 0)
ip  = struct.pack("!BBHHHBBH", 0x45,0,28,1,frag,64,17,0)+socket.inet_aton(s)+socket.inet_aton(d)
open(out,"wb").write(eth+ip+udp)
PY
}

# udp_auto=0 for the manual UDP tests: the bpf_timer detector otherwise drives
# udp_engage itself and would overwrite the value each test sets (~1s ticks).
echo "=== T11: UDP -> pool, peacetime (udp_engage=0) => seen++, no ct lookup ==="
./loader set udp_auto=0 udp_engage=0 drop_natpool_udp=0 >/dev/null
gen_udp "$DIR/u_pool.bin"  "$SERVER_IP" "$NATPOOL_IP" 53 45000 0
gen_udp "$DIR/u_pool2.bin" "$SERVER_IP" "$NATPOOL_IP" 53 45001 0
gen_udp "$DIR/u_frag.bin"  "$SERVER_IP" "$NATPOOL_IP" 53 45002 1
gen_udp "$DIR/u_class2.bin" "$SERVER_IP" "$ROUTED_IP" 53 45003 0
b=$(stat natpool_udp_seen); r=$(run "$DIR/u_pool.bin")
check "udp peacetime seen" "$r" "$PASS" natpool_udp_seen 1 "$b"

echo "=== T12: engage=1, UDP -> pool without conntrack => miss (count-only, PASS) ==="
./loader set udp_engage=1 drop_natpool_udp=0 >/dev/null
b=$(stat natpool_udp_miss); r=$(run "$DIR/u_pool.bin")
check "udp engaged miss" "$r" "$PASS" natpool_udp_miss 1 "$b"

echo "=== T13: engage=1 drop=1, UDP -> pool without conntrack => DROP ==="
./loader set udp_engage=1 drop_natpool_udp=1 >/dev/null
b=$(stat natpool_udp_dropped); r=$(run "$DIR/u_pool2.bin")
check "udp drop" "$r" "$DROP" natpool_udp_dropped 1 "$b"

echo "=== T14: engage=1 drop=1, UDP -> pool NON-FIRST FRAGMENT => PASS, not dropped ==="
b=$(stat natpool_udp_dropped); r=$(run "$DIR/u_frag.bin")
check "udp frag pass" "$r" "$PASS" natpool_udp_dropped 0 "$b"

echo "=== T15: engage=1, UDP -> pool with a real conntrack entry => hit ==="
./loader set udp_engage=1 drop_natpool_udp=0 >/dev/null
conntrack -D -s 100.64.48.5 >/dev/null 2>&1
if conntrack -I -p udp -t 30 -s 100.64.48.5 -d "$SERVER_IP" --sport 40000 --dport 53 \
	-r "$SERVER_IP" -q "$NATPOOL_IP" --reply-port-src 53 --reply-port-dst 45000 \
	>/dev/null 2>&1; then
	b=$(stat natpool_udp_hit); r=$(run "$DIR/u_pool.bin")
	check "udp ct hit" "$r" "$PASS" natpool_udp_hit 1 "$b"
	conntrack -D -s 100.64.48.5 >/dev/null 2>&1
else
	echo "  SKIP  could not insert synthetic UDP conntrack entry"
fi

echo "=== T16: UDP -> class 2 (not the pool) => not counted (seen+0), PASS ==="
b=$(stat natpool_udp_seen); r=$(run "$DIR/u_class2.bin")
check "udp non-pool ignored" "$r" "$PASS" natpool_udp_seen 0 "$b"

echo "=== T17: TCP SYN+FIN -> pool, count-only (drop_bad_flags=0) => PASS + badflags_seen ==="
./loader set drop_bad_flags=0 >/dev/null
gen_pkt "$DIR/t17_synfin.bin"       0800 0 "$SERVER_IP" "$NATPOOL_IP" 1234 80 syn,fin
gen_pkt "$DIR/t18_null.bin"         0800 0 "$SERVER_IP" "$NATPOOL_IP" 1234 80 ""
gen_pkt "$DIR/t19_synfin_other.bin" 0800 0 "$SERVER_IP" "$OTHER_IP"   1234 80 syn,fin
b=$(stat tcp_badflags_seen); r=$(run "$DIR/t17_synfin.bin")
check "badflags count-only" "$r" "$PASS" tcp_badflags_seen 1 "$b"

echo "=== T18: null scan -> pool, drop_bad_flags=1 => DROP ==="
./loader set drop_bad_flags=1 >/dev/null
b=$(stat tcp_badflags_dropped); r=$(run "$DIR/t18_null.bin")
check "badflags drop (null)" "$r" "$DROP" tcp_badflags_dropped 1 "$b"

echo "=== T19: SYN+FIN outside the pool => untouched (seen+0, PASS) — blast radius ==="
b=$(stat tcp_badflags_seen); r=$(run "$DIR/t19_synfin_other.bin")
check "badflags non-pool ignored" "$r" "$PASS" tcp_badflags_seen 0 "$b"

./loader set udp_auto=1 udp_engage=0 drop_natpool_udp=0 drop_bad_flags=0 >/dev/null   # reset: detector on, count-only

echo
[ "$fail" = 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $fail
