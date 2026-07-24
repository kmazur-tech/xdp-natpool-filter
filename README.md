# xdp-natpool-filter

*Read this in: [English](README.md) | [polski](README.pl.md)*

An XDP filter that protects the **NAT/CGNAT pool** addresses of a router against
attacks whose victim is the pool itself and whose cost is the router's CPU, the
BRASes and the conntrack table. Three protections, all for pool addresses:

1. **TCP SYN/ACK reflection** (always-on) — unsolicited SYN/ACK packets
   (reflection/DDoS backscatter).
2. **UDP amplification** (reactive, per-IP auto-detector) — UDP floods
   (SSDP/NTP/DNS/CLDAP etc.) aimed at pool addresses.
3. **Bogus TCP flags** (stateless, always-on) — combinations a valid stack never
   emits (null scan, SYN+FIN, SYN+RST, XMAS, FIN without ACK).

The filter attaches to the **ingress** of the uplink interface, uses the
**kernel conntrack** as the source of truth (it keeps no state of its own for
the pool) and passes legitimate traffic unmodified. It is not a
bump-in-the-wire — it does not forward packets; it only classifies and
(optionally) drops at the NIC, otherwise the packet takes the normal kernel
path.

Operator's guide: [OPERATORS.md](OPERATORS.md).

## Why kernel conntrack instead of own state

A router doing NAT/CGNAT **already owns** the authoritative connection state
(it sets up the translations itself). For pool addresses a legitimate inbound
packet is always a reply to a connection a subscriber initiated — i.e. **it has
a conntrack entry**. Instead of building a parallel, less accurate state table
in BPF, the filter asks `bpf_xdp_ct_lookup()`: entry exists → pass, none →
unsolicited → (optionally) drop. Zero own state, zero risk of drifting away
from reality.

## What it actually protects — two classes

Classification is by **destination address** (LPM trie `prefix_class`).
Prefixes come from two static files (see
[Prefix configuration](#prefix-configuration)):

| Class | Contents | Verification | Default |
|-------|----------|--------------|---------|
| `CLASS_NATPOOL` (1) | NAT/SNAT pools (CGNAT) | `bpf_xdp_ct_lookup()` into kernel conntrack | **protected** once drop is enabled |
| `CLASS_ROUTED` (2) | routed public client prefixes (notrack) | LRU of outbound SYNs | **dormant** (see below) |

**Class 1** works because CGNAT traffic is **symmetric** — both directions must
traverse the NAT router, so a reflected SYN/ACK to the pool enters through this
hook. The pools host no services (pure SNAT), so an unsolicited packet to the
pool is **always** junk → dropping is safe.

**Class 2** exists to protect clients with their own public, routed (notrack)
addresses — but **only if their inbound traffic is symmetric**, i.e. enters
through the same interface. If inbound to those clients **bypasses** the hook
(asymmetric routing: straight from your edge/BGP to the access layer), the
filter never sees the attack and class 2 does nothing. That is why it is
**disabled by default** (`drop_routed=0`); enable it only after verifying the
inbound path. Note: only **IPv4** is supported.

## How it works

One XDP program on the **ingress** of the uplink interface (e.g. `bond0`). If
that is a bond, the kernel delegates the program to the active slaves, so it
sees traffic on all VLANs carried over the bond. The parser tolerates 0–2 VLAN
tags; the logic keys on the destination address, not the VLAN ID (with
rx-vlan-offload the tag is stripped anyway).

- **Class 1 — bogus TCP flags:** combinations a valid stack never emits (null
  scan, SYN+FIN, SYN+RST, XMAS, FIN without ACK) → drop. Stateless, no lookup;
  `classify()` runs only for the (vanishingly rare) bad packet, so the common
  path pays nothing. Checked BEFORE the SYN branches, so a SYN+FIN can never be
  recorded in the LRU as an "outbound client SYN". Cfg flag `drop_bad_flags`.
- **Class 1 — TCP SYN/ACK:** lookup in the kernel conntrack. Entry exists
  (reply to a client connection) → PASS; none → unsolicited → drop (in blocking
  mode). Always-on (SYN/ACK is rare, the lookup is cheap). Flag `drop_natpool`.
- **Class 1 — UDP amplification:** UDP is bulk traffic (QUIC/DNS/gaming), so in
  peacetime the filter **only counts** UDP to the pool (a cheap per-IP counter)
  and passes it — **without** a conntrack lookup. A `bpf_timer` (scan every
  ~1 s) sets `udp_engage=1` when UDP to a single pool address exceeds
  `udp_pps_threshold`; only then does the datapath do the UDP lookup → miss =
  drop (in blocking mode). When the attack subsides the detector clears
  `udp_engage` by itself. Fragments: non-first fragments (offset>0) are passed
  (the kernel defragmenter will abandon them); the first fragment carries L4
  and is checked normally. This protects the router CPU **and the conntrack
  table** (unsolicited UDP to the pool, if the firewall tracks it, creates junk
  entries). Flag `drop_natpool_udp`; detector controls: `udp_auto` (1 = the
  timer drives `udp_engage`), `udp_pps_threshold`.
- **Class 2:** a 4-tuple LRU fed by outbound client SYNs; a returning SYN/ACK
  with no recorded SYN → drop (when `drop_routed=1`). Flag `record_routed`
  enables recording.
- An address in neither class → unconditional PASS.

**The `udp_engage` gate is only a CPU optimisation — correctness is always
decided by conntrack.** Even a threshold set too low will not drop legitimate
replies (they have an entry → hit → pass); only unsolicited misses are cut. The
threshold merely decides WHEN to spend CPU on lookups.

**Fail-open:** the filter is an allowlist of PROTECTION, not a blocklist. An
address in neither class is passed; a forgotten pool = no protection for it
(same as without the filter), zero outage. Detaching the program = traffic
keeps flowing unfiltered.

## Modes (the `cfg` map)

Everything is switchable at runtime via `loader set`:

| Flag | Meaning | Default |
|------|---------|---------|
| `drop_natpool` | drop SYN/ACK to the pool with no conntrack entry | 0 (count-only) |
| `drop_natpool_udp` | drop UDP to the pool with no entry while the detector is engaged | 0 |
| `drop_bad_flags` | drop bogus TCP flag combinations to the pool | 0 |
| `drop_routed` | drop SYN/ACK to class 2 with no recorded SYN | 0 |
| `record_routed` | record outbound class-2 SYNs into the LRU | 1 |
| `measure_amp` | track miss retransmissions (amplification) | 1 |
| `udp_auto` | the `bpf_timer` detector drives `udp_engage` | 1 |
| `udp_pps_threshold` | per-IP pps threshold that engages UDP protection | 200000 |

The default state (fresh `load`) is **count-only** — nothing is dropped, only
counters and LRUs are maintained. Safe to observe before arming.

## Prefix configuration

Two static files, edited for your own network (the shipped values are RFC 5737
documentation ranges — **replace them**):

- `nat_pools.conf` — NAT/SNAT pools (class 1). Keep in sync with the SNAT
  source set in your firewall.
- `client_ranges.conf` — routed client ranges (class 2). Static aggregates.

`gen_prefixes.sh` combines them into `prefixes.conf` (format: `CIDR class`),
with no dependency on the routing table.

## Build and manual operation

Required: `clang`, `llvm`, `libbpf-dev`, `libelf`, `bpftool`. Kernel **≥ 5.19**
(the `bpf_xdp_ct_lookup`/`bpf_ct_release` kfuncs; `bpf_timer` ≥ 5.15).
`vmlinux.h` is generated from the running kernel's BTF — **build on the target
machine**.

```sh
make                                   # natpool_filter.bpf.o + loader (+ vmlinux.h from BTF)
./gen_prefixes.sh nat_pools.conf client_ranges.conf > prefixes.conf
./loader load prefixes.conf            # load + pin under /sys/fs/bpf/natpool (count-only)
./loader attach bond0                  # XDP driver mode (bpf_link)
./loader set drop_natpool=1 drop_natpool_udp=1 drop_bad_flags=1   # >>> blocking <<<
./loader set drop_natpool=0 drop_natpool_udp=0 drop_bad_flags=0   # count-only
./loader set udp_pps_threshold=200000  # UDP detector sensitivity (pps per IP)
./loader stats                         # counters (per-CPU sums)
./loader detach bond0                  # instant rollback
./loader unload
./unit_test.sh                         # tests (TCP/synack + UDP + bad-flags)
```

### Choosing the UDP threshold

`udp_pps_threshold` is pps towards a **single pool address**. Set it:
- **well above** the legitimate UDP peak of a single subscriber (so the
  detector sleeps in peacetime — otherwise needless lookups), and
- **at/below** the level at which your anti-DDoS system bans a host by UDP pps
  (so XDP starts cutting before/when the external scrubber reacts).

Peek at the current per-IP peak: `bpftool map lookup pinned
/sys/fs/bpf/natpool/tmr key 0 0 0 0` (field `last_max_pps`).

## bpf_link attachment and gapless upgrade

The program is attached via a **`bpf_link`** (not the legacy netlink
`bpf_xdp_attach`), and the link is pinned as `link_<ifname>`. This buys:

- **Gapless upgrade:** `loader load` loads the new program and clears the
  map/program pins but **deliberately keeps the link pin** — the old program
  keeps filtering because the link holds it. A following `loader attach <if>`
  performs `bpf_link_update()`, i.e. an **atomic in-place swap** (same
  `link id`, new `prog id`, not a single packet without the filter). Without
  this, every upgrade would be `detach→load→attach` = a fail-open window.
- **Policy carry-over:** `load` reads the running configuration from the old
  `cfg` map and carries it into the new one, so an upgrade never reverts
  blocking modes to count-only. `udp_engage` is reset (it is detector state —
  the timer re-derives it within a tick).
- **Resistance to accidental removal:** a legacy `bpftool net detach` bounces
  off the link (`Can't replace active BPF XDP link`).

`unload` is a full teardown (it also removes the link pin ⇒ detaches the
filter) — **do not use it for upgrades**. `unit_test.sh` uses `load` alone, so
it never detaches a live filter.

## Autostart (example, init.d)

```sh
if [ -x /opt/xdp-natpool-filter/loader ]; then
    /opt/xdp-natpool-filter/gen_prefixes.sh /opt/xdp-natpool-filter/nat_pools.conf \
        /opt/xdp-natpool-filter/client_ranges.conf > /opt/xdp-natpool-filter/prefixes.conf 2>/dev/null
    /opt/xdp-natpool-filter/loader load /opt/xdp-natpool-filter/prefixes.conf 2>/dev/null \
        || { rm -f /opt/xdp-natpool-filter/vmlinux.h; \
             make -C /opt/xdp-natpool-filter >/dev/null 2>&1 && \
             /opt/xdp-natpool-filter/loader load /opt/xdp-natpool-filter/prefixes.conf 2>/dev/null; }
    /opt/xdp-natpool-filter/loader attach bond0 2>/dev/null
    /opt/xdp-natpool-filter/loader set drop_natpool=1 drop_natpool_udp=1 drop_bad_flags=1 2>/dev/null
fi
```

Everything is wrapped in `2>/dev/null` — fail-open: should build/load/attach
fail, the router keeps forwarding without the filter (no protection, zero
outage). `loader` finds its `.o` relative to `/proc/self/exe`, so it works from
a full path without `cd`.

## Amplification measurement (for the DROP vs XDP_TX RST decision)

A dropped SYN/ACK makes the reflector retransmit (unless it uses SYN cookies —
then it holds no state and does not retransmit). The filter measures this live:
every stateless SYN/ACK (miss) goes into the `synack_seen` LRU; first sighting
= `miss_unique_flows`, a repeat = `miss_retransmissions`.

**Amplification = (miss_unique_flows + miss_retransmissions) /
miss_unique_flows.** ≈1.0 → reflectors don't retransmit → RST would achieve
nothing. ≫1 → RST would cut retransmissions at the source — but it only pays
off once the flood genuinely chokes the NIC (RST means `XDP_TX`, i.e. we start
emitting packets/backscatter). Default: DROP; RST is deliberately out of scope
for this version.

## Kernel upgrades

Layers that survive a kernel update:
- **`loader` (binary)** — userspace (libbpf/libc), kernel-independent.
- **`.o` on a new kernel** — libbpf does CO-RE (struct offset relocations) and
  resolves the kfuncs against the running kernel's BTF at load time; a typical
  update needs no rebuild.
- **Self-heal (when load fails)** — `rm -f vmlinux.h; make`: forces a regen of
  `vmlinux.h` from the fresh `/sys/kernel/btf/vmlinux` (the Makefile rule has
  no prerequisites — without the `rm`, `make` would NOT refresh the BTF), then
  rebuilds the `.o` and retries.
- **Kfunc signature changes** — no rebuild can fix that (requires a code edit);
  fail-open then guarantees no outage until the manual fix. `bpf_ct_opts` is
  defined by hand as 16 bytes (it is absent from vmlinux BTF) — if the kernel
  changes its layout, `.bpf.c` needs updating.

## Limitations

- **IPv4 only.** IPv6 is neither classified nor filtered.
- **Class 2 requires symmetric** inbound traffic (see above) — under asymmetry
  it protects nothing.
- **Encapsulations** other than plain IPv4/802.1Q (PPPoE, MPLS etc.) are not
  parsed — such traffic hits the unconditional PASS. The filter assumes an IPv4
  header after (at most two) VLAN tags.
- The class-2 LRU does not count evictions; under extreme outbound traffic a
  recorded SYN could be evicted before its SYN/ACK arrives (rare).

## Files

- `natpool_filter.bpf.c` / `natpool_filter.h` — the BPF program + shared structs
- `loader.c` — control tool: load/pin, attach/detach (bpf_link), set, stats, unload
- `nat_pools.conf` / `client_ranges.conf` — class 1 / 2 prefixes (examples, RFC 5737)
- `gen_prefixes.sh` — combines the above into `prefixes.conf`
- `unit_test.sh` — tests via `bpftool prog run` (synthetic packets + real conntrack)
- `Makefile` — build (clang → `.o`, cc → `loader`); `vmlinux.h` from BTF, not committed
- `OPERATORS.md` — operator's guide ([polska wersja](OPERATORS.pl.md))

## Author

Kamil Mazur (kmazur@goodhost.eu)

## License

GPL-2.0 — the BPF program uses GPL-only kernel helpers, so the BPF license
section is declared as `GPL`. See [LICENSE](LICENSE).
