/* Shared definitions between the BPF program (natpool_filter.bpf.c) and the
 * userspace loader (loader.c). Keep struct layouts in sync on both sides. */
#ifndef __NATPOOL_FILTER_H
#define __NATPOOL_FILTER_H

/* Traffic classes stored as the value of the prefix_class LPM trie. */
#define CLASS_NATPOOL 1 /* CGNAT SNAT pool (12x /24) -> kernel conntrack lookup */
#define CLASS_ROUTED  2 /* routed public client /32   -> syn_seen LRU lookup    */

/* LRU key: the 4-tuple of an OUTBOUND client SYN, as recorded on ingress.
 * saddr/daddr/sport/dport are in network byte order. */
struct flow_key {
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
};

/* LPM trie key: standard {prefixlen, address} used by BPF_MAP_TYPE_LPM_TRIE. */
struct lpm_key {
	__u32 prefixlen;
	__be32 addr;
};

/* Runtime configuration (cfg array, single entry). Drop flags zero = count-only
 * mode: nothing is ever dropped, the program only maintains counters and LRUs. */
struct config {
	__u8 drop_natpool;      /* 1 = XDP_DROP SYN/ACK to NAT pool with no conntrack entry */
	__u8 drop_routed;       /* 1 = XDP_DROP SYN/ACK to routed /32 with no recorded SYN   */
	__u8 record_routed;     /* 1 = record outbound client SYNs into syn_seen (default on) */
	__u8 measure_amp;       /* 1 = track SYN/ACK-miss retransmissions in synack_seen LRU  */
	__u8 drop_natpool_udp;  /* 1 = XDP_DROP UDP to NAT pool with no conntrack (else count) */
	__u8 udp_engage;        /* 1 = do the UDP conntrack lookup; 0 = peacetime cheap pass.
				 * When udp_auto=1 the detector (bpf_timer) drives this flag. */
	__u8 udp_auto;          /* 1 = bpf_timer rate detector manages udp_engage (default);
				 * 0 = udp_engage is manual (testing / operator force)         */
	__u8 drop_bad_flags;    /* 1 = XDP_DROP never-legitimate TCP flag combos to the pool
				 * (null scan / SYN+FIN / SYN+RST / XMAS / FIN-no-ACK).
				 * Stateless: no conntrack lookup, so it is always-on cheap. */
	__u8 drop_natpool_syn;  /* 1 = XDP_DROP inbound pure SYN (syn && !ack) to the NAT pool.
				 * Pools host no services -> a SYN opening a connection TO the
				 * pool is junk (flood/scan). Stateless: a new SYN has no
				 * conntrack entry anyway. NB: kills active-FTP data channels
				 * (server->client SYN), deliberately unsupported. Pool only;
				 * class 2 (routed clients) may run services -> never here. */
	__u8 pad[3];            /* explicit pad to the u32 boundary (keep layout deterministic) */
	__u32 udp_pps_threshold; /* per-IP UDP-to-pool pps that trips udp_engage (detector) */
};

/* Per-CPU counters. Order must match stat_names[] in loader.c. */
enum stat_idx {
	ST_PKTS = 0,      /* every packet entering the XDP hook */
	ST_SYNACK,        /* SYN+ACK packets examined */
	ST_NATPOOL_HIT,   /* SYN/ACK to pool, conntrack entry found -> pass */
	ST_NATPOOL_MISS,  /* SYN/ACK to pool, no conntrack entry (drop candidate) */
	ST_NATPOOL_DROP,  /* SYN/ACK to pool actually dropped */
	ST_ROUTED_HIT,    /* SYN/ACK to routed /32, matching recorded SYN -> pass */
	ST_ROUTED_MISS,   /* SYN/ACK to routed /32, no recorded SYN (drop candidate) */
	ST_ROUTED_DROP,   /* SYN/ACK to routed /32 actually dropped */
	ST_RECORDED,      /* outbound client SYN recorded into the LRU */
	ST_NOCLASS,       /* SYN/ACK whose dst is in neither class -> pass */
	ST_MISS_UNIQUE,   /* first sighting of a missing-state SYN/ACK 4-tuple */
	ST_MISS_REPEAT,   /* repeated sighting = reflector retransmission */
	ST_NATPOOL_UDP_SEEN, /* every inbound UDP to a pool addr (cheap rate signal, always) */
	ST_NATPOOL_UDP_HIT,  /* UDP to pool, conntrack found (only when engaged) -> pass */
	ST_NATPOOL_UDP_MISS, /* UDP to pool, no conntrack (engaged) = unsolicited/amp */
	ST_NATPOOL_UDP_DROP, /* UDP to pool actually dropped (drop_natpool_udp) */
	ST_UDP_ENGAGE_TICKS, /* timer ticks where a pool IP was over threshold (engaged) */
	ST_BADFLAGS_SEEN,    /* TCP to pool with a never-legitimate flag combo */
	ST_BADFLAGS_DROP,    /* ...actually dropped (drop_bad_flags) */
	ST_NATPOOL_SYN_SEEN, /* inbound pure SYN (syn && !ack) to a pool addr */
	ST_NATPOOL_SYN_DROP, /* ...actually dropped (drop_natpool_syn) */
	ST_NATPOOL_FRAG_SEEN,/* non-first IP fragment to a pool addr (measurement only) */
	__ST_MAX
};

/* Amplification factor of would-be-dropped SYN/ACKs (how much reflectors
 * retransmit): (miss_unique + miss_repeat) / miss_unique.
 * ~1.0 => reflectors don't retransmit (SYN cookies) => RST would not help.
 * Count-only mode is a LOWER BOUND: an active client suppresses retransmission
 * by RST-ing the passed-through SYN/ACK, so only unused-address targets
 * retransmit. Under DROP every target behaves like an unused address (the
 * client never sees the SYN/ACK), so the count-only figure for unused targets
 * predicts the DROP-mode amplification. Also a lower bound at very high miss
 * rates, where LRU eviction can drop a tuple before its retransmission. */

#endif /* __NATPOOL_FILTER_H */
