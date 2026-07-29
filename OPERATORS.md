# XDP NAT-pool filter — operator's guide

*Read this in: [English](OPERATORS.md) | [polski](OPERATORS.pl.md)*

## What this is
An XDP program attached to `bond0` (or another uplink interface) of the router.
It protects the **NAT/CGNAT pool** addresses against several attack types while
passing legitimate traffic untouched. It offloads the router CPU, the BRASes
and the conntrack table.

Three protections, all for NAT pool addresses:
1. **TCP SYN/ACK reflection** — unsolicited SYN/ACK packets (reflection/DDoS
   backscatter).
2. **UDP amplification** — unsolicited UDP floods (SSDP/NTP/DNS/CLDAP etc.).
3. **Bogus TCP flags** — combinations a valid stack never sends (null scan,
   XMAS, SYN+FIN, SYN+RST, FIN without ACK). Checked without touching
   conntrack, so they cost next to nothing and are always active.
4. **Inbound TCP SYN floods** - pure SYNs trying to open connections TO pool
   addresses (the pools host no services, so these are junk). Off by default;
   caveat: also cuts active FTP, see the README before arming.

## How it works (in short)
For **NAT pool** addresses an inbound packet is checked against the conntrack
table — is it a reply to a connection the client itself established:
- **entry exists → legitimate → pass**
- **no entry → unsolicited → count; in blocking mode: drop at the NIC**

NAT pools host no services, so an unsolicited packet to the pool is always
junk — blocking never touches legitimate traffic (replies have a conntrack
entry → they pass).

### TCP vs UDP difference — IMPORTANT
- **TCP (SYN/ACK): always-on.** Every SYN/ACK to the pool is always checked
  (SYN/ACK is a rare packet, the check is cheap).
- **UDP: automatic, reactive.** UDP is bulk traffic (QUIC/443, DNS, gaming),
  so in peacetime the filter **only counts** UDP to the pool — it does NOT
  query conntrack (to spare the CPU). A built-in **auto-detector** (scan every
  ~1 s) turns UDP checking+blocking on **by itself** when UDP towards a single
  pool address exceeds `udp_pps_threshold`. When the attack subsides it turns
  itself off. **The operator does not have to do anything during a UDP attack —
  it is automatic.**

Clients with **routed public** addresses (class 2) are protected only if their
inbound traffic is symmetric (enters through this interface). Class 2 is
disabled by default — see the README.

---

## Commands
Run as `root`. The project usually lives in `/opt/xdp-natpool-filter`. `loader`
finds its `.o` relative to its own location, so it works from a full path
without `cd`.

### Check whether the filter is attached and in which mode
```sh
bpftool net show | grep bond0                            # a line with "id N" = filter attached
/opt/xdp-natpool-filter/loader set drop_natpool=1        # sets AND PRINTS the full cfg
```
The cfg line shows all modes, among them:
- `drop_natpool=1` — **TCP** SYN/ACK to the pool: BLOCKS (0 = count only)
- `drop_natpool_udp=1` — **UDP** to the pool: BLOCKS while the detector is engaged (0 = count only)
- `drop_bad_flags=1` — bogus TCP flags to the pool: BLOCKS (0 = count only)
- `drop_natpool_syn=1` - inbound pure SYN to the pool: BLOCKS (0 = count only)
- `udp_auto=1` — UDP auto-detector enabled (drives `udp_engage` itself)
- `udp_engage=0/1` — **is a UDP attack happening right now**: 0 = peacetime, **1 = the detector spotted a flood and is cutting**
- `udp_pps_threshold` — per-IP pps threshold that engages UDP protection

### Statistics (totals since the filter was loaded)
```sh
/opt/xdp-natpool-filter/loader stats
```
The most important counters:
| Counter | Meaning |
|---|---|
| `natpool_ct_hit` | legitimate TCP replies (grows constantly) |
| `natpool_ct_miss` | **unsolicited SYN/ACKs to the pool** (drop candidates) |
| `natpool_dropped` | SYN/ACKs actually dropped |
| `natpool_udp_seen` | all UDP to the pool (grows constantly, big numbers = normal) |
| `natpool_udp_miss` | **unsolicited UDP to the pool** — counted only while the detector is engaged |
| `natpool_udp_dropped` | UDP actually dropped (grows only during a UDP attack) |
| `udp_engage_ticks` | how many times (seconds) the UDP detector was engaged — **>0 = there was a UDP attack** |
| `tcp_badflags_seen` / `tcp_badflags_dropped` | TCP to the pool with bogus flags / how many dropped |
| `natpool_syn_seen` | **inbound pure SYNs to the pool** (junk/scan/flood, drop candidates) |
| `natpool_syn_dropped` | of those, actually dropped (`drop_natpool_syn`) |
| `natpool_frag_seen` | non-first IP fragments to the pool (measurement ONLY, nothing dropped) |
| `miss_retransmissions` / `miss_unique_flows` | SYN/ACK amplification = (unique+retrans)/unique |

### Current rate (packets/s) — paste and run
```sh
L=/opt/xdp-natpool-filter/loader; A=$($L stats); sleep 20; B=$($L stats)
paste <(echo "$A") <(echo "$B") | awk '{printf "%-24s %+d/s\n",$1,($4-$2)/20}'
```

### Peek at the per-IP UDP peak (is the detector close to the threshold)
```sh
bpftool map lookup pinned /sys/fs/bpf/natpool/tmr key 0 0 0 0 | grep last_max_pps
#   last_max_pps = highest pps towards a single pool address in the last ~1 s.
#   Once it exceeds udp_pps_threshold, the detector enables UDP blocking itself.
```

---

## Changing settings

```sh
L=/opt/xdp-natpool-filter/loader
$L set drop_natpool=1      # / =0        TCP SYN/ACK: block / count only
$L set drop_natpool_udp=1  # / =0        UDP: block during an attack / count only
$L set drop_bad_flags=1    # / =0        bogus TCP flags: block / count only
$L set drop_natpool_syn=1  # / =0        inbound SYN to the pool: block / count only (FTP caveat)
$L set udp_pps_threshold=300000          # UDP detector sensitivity (pps per IP)
$L set udp_auto=0 udp_engage=1           # FORCE UDP blocking (bypasses the detector)
$L set udp_auto=1                        # back to automatic
```

### Upgrading the filter WITHOUT a protection gap
The filter is attached via a `bpf_link`, so the new program is swapped in
**atomically** — traffic never sees a moment without the filter, and settings
are carried over automatically:
```sh
/opt/xdp-natpool-filter/loader load /opt/xdp-natpool-filter/prefixes.conf
/opt/xdp-natpool-filter/loader attach bond0        # prints "program swapped in place ... no traffic gap"
```
**Do not use `unload` for upgrades** — it is a full teardown (detaches the
filter).

### Emergency / instant rollback (fully detach the filter)
```sh
/opt/xdp-natpool-filter/loader detach bond0
```
Traffic keeps flowing without the filter immediately. Re-attach with
`... loader attach bond0`.

---

## How to recognise an attack
**Peacetime baseline:** `natpool_ct_miss` low (tens per second), hit ratio ~99%;
UDP: `udp_engage=0`, `udp_engage_ticks` not growing, `last_max_pps` well below
the threshold.

- **SYN/ACK attack (TCP):** `natpool_ct_miss` jumps to hundreds of
  thousands–millions per second, `natpool_dropped` grows. The filter cuts
  automatically (blocking is always-on).
- **UDP amplification attack:** `udp_engage` flips to **1**, `udp_engage_ticks`
  grows, `natpool_udp_dropped` grows. The detector engages and cuts **by
  itself**. After the attack `udp_engage` returns to 0.

**Blocking is safe to keep enabled permanently** — the pools host no services;
UDP is cut only during a real flood above the threshold, and legitimate replies
have a conntrack entry and pass anyway.

## Note after a failover / restart
If the router has just taken over traffic, wait until the conntrack state
settles — freshly synchronised sessions may briefly show up as misses. The
filter comes up automatically from autostart (see the README) in blocking mode.
