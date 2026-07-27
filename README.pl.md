# xdp-natpool-filter

[![CI](https://github.com/kmazur-tech/xdp-natpool-filter/actions/workflows/natpool-ci.yml/badge.svg)](https://github.com/kmazur-tech/xdp-natpool-filter/actions/workflows/natpool-ci.yml)

*Wersje językowe: [English](README.md) | [polski](README.pl.md)*

Filtr XDP chroniący adresy **puli NAT/CGNAT** na routerze przed atakami, których
ofiarą jest sama pula, a kosztem — CPU routera, BRAS-ów i tablica conntrack. Trzy
ochrony na adresy puli:

1. **TCP SYN/ACK-reflection** (always-on) — nieproszone pakiety SYN/ACK (odbicia
   reflection/DDoS).
2. **UDP-amplification** (reaktywnie, auto-detektor per-IP) — floody UDP
   (SSDP/NTP/DNS/CLDAP itd.) do adresów puli.
3. **Niepoprawne flagi TCP** (bezstanowo, always-on) — kombinacje, których poprawny
   stos nigdy nie emituje (null scan, SYN+FIN, SYN+RST, XMAS, FIN bez ACK).

Filtr podpina się na **ingressie** interfejsu wyjściowego, korzysta z **kernelowego
conntracka** jako źródła prawdy (dla puli nie trzyma własnego stanu) i przekazuje
legalny ruch bez modyfikacji. Nie jest bump-in-the-wire — nie forwarduje pakietów,
tylko klasyfikuje i (opcjonalnie) dropuje na karcie; poza tym pakiet leci normalną
ścieżką kernela.

Logika filtra jest przetestowana produkcyjnie: działa w sieciach ISP, chroniąc
żywe pule CGNAT, i cięła realne floody SYN/ACK-reflection oraz UDP-amplification.

Instrukcja obsługi dla operatorów: [OPERATORS.pl.md](OPERATORS.pl.md)
(wersja angielska: [OPERATORS.md](OPERATORS.md)).

## Dlaczego kernelowy conntrack, a nie własny stan

Router robiący NAT/CGNAT **już jest** właścicielem autorytatywnego stanu połączeń
(sam zestawia translacje). Dla adresów puli legalny pakiet przychodzący to zawsze
odpowiedź na połączenie, które abonent zainicjował — czyli **ma wpis w conntracku**.
Zamiast budować równoległą, mniej dokładną tablicę stanu w BPF, filtr pyta
`bpf_xdp_ct_lookup()`: jest wpis → przepuść, brak → nieproszone → (opcjonalnie) drop.
Zero własnego stanu, zero ryzyka rozjechania się z rzeczywistością.

## Co realnie chroni — dwie klasy

Klasyfikacja po **adresie docelowym** (trie LPM `prefix_class`). Prefiksy z dwóch
statycznych plików (patrz [Konfiguracja](#konfiguracja-prefiksów)):

| Klasa | Zawartość | Weryfikacja | Domyślnie |
|-------|-----------|-------------|-----------|
| `CLASS_NATPOOL` (1) | pule NAT/SNAT (CGNAT) | `bpf_xdp_ct_lookup()` w kernelowy conntrack | **chroniona** przy włączonym dropie |
| `CLASS_ROUTED` (2) | routowane publiczne prefiksy klienckie (notrack) | LRU wychodzących SYN-ów | **dormant** (patrz niżej) |

**Klasa 1** działa, bo ruch CGNAT jest **symetryczny** — oba kierunki muszą przejść
przez router NAT, więc odbity SYN/ACK do puli wchodzi przez ten hook. Pule nie
hostują usług (czysty SNAT), więc nieproszony pakiet do puli jest **zawsze**
śmieciem → drop bezpieczny.

**Klasa 2** jest po to, żeby chronić klientów z własnymi publicznymi adresami
(routowanymi, notrack) — ale **tylko jeśli ich ruch przychodzący jest symetryczny**,
czyli wchodzi przez ten sam interfejs. Jeśli inbound do tych klientów **omija** hook
(routing asymetryczny: z edge/BGP prosto do warstwy dostępowej), filtr nie widzi
ataku i klasa 2 nic nie robi. Dlatego jest **wyłączona domyślnie** (`drop_routed=0`);
włączać tylko po sprawdzeniu ścieżki inbound. Uwaga: obsługiwany jest tylko **IPv4**.

## Zasada działania

Jeden program XDP na **ingressie** interfejsu wyjściowego (np. `bond0`). Jeśli to
bond, kernel deleguje program na aktywne slave'y, więc widzi ruch na wszystkich
VLAN-ach niesionych przez bond. Parser toleruje 0–2 tagi VLAN; logika jest po
adresie docelowym, nie po VLAN ID (przy rx-vlan-offload tag i tak jest zdjęty).

- **Klasa 1 — niepoprawne flagi TCP:** kombinacje, których poprawny stos nigdy nie
  emituje (null scan, SYN+FIN, SYN+RST, XMAS, FIN bez ACK) → drop. Bezstanowe, bez
  lookupu; `classify()` odpala się dopiero dla (skrajnie rzadkiego) złego pakietu,
  więc ścieżka wspólna nic nie płaci. Sprawdzane PRZED gałęziami SYN, żeby SYN+FIN
  nie trafił do LRU jako „wychodzący SYN klienta". Flaga cfg `drop_bad_flags`.
- **Klasa 1 — TCP SYN/ACK:** lookup w kernelowym conntracku. Jest wpis (odpowiedź
  na połączenie klienta) → PASS; brak → nieproszone → drop (w trybie blokowania).
  Always-on (SYN/ACK jest rzadki, lookup tani). Flaga `drop_natpool`.
- **Klasa 1 — UDP-amp:** UDP to ruch masowy (QUIC/DNS/gry), więc w czasie pokoju
  filtr **tylko liczy** UDP do puli (tani licznik per-IP) i przepuszcza — **bez**
  lookupu conntracka. `bpf_timer` (skan co ~1 s) ustawia `udp_engage=1`, gdy UDP do
  pojedynczego adresu puli przekroczy `udp_pps_threshold`; dopiero wtedy datapath
  robi lookup UDP → miss = drop (w trybie blokowania). Po ustaniu ataku detektor sam
  wyłącza `udp_engage`. Fragmenty: nie-pierwsze (offset>0) przepuszczane (kernelowy
  defragmenter je porzuci); pierwszy fragment ma L4 i jest sprawdzany normalnie.
  Chroni CPU routera **i tablicę conntrack** (nieproszony UDP do puli, jeśli firewall
  go trackuje, tworzy śmieciowe wpisy). Flaga `drop_natpool_udp`, sterowanie
  detektorem: `udp_auto` (1 = timer steruje `udp_engage`), `udp_pps_threshold`.
- **Klasa 2:** LRU 4-tuple, zasilana wychodzącymi SYN-ami klientów; wracający SYN/ACK
  bez zapisanego SYN → drop (gdy `drop_routed=1`). Flaga `record_routed` włącza zapis.
- Adres spoza obu klas → bezwarunkowy PASS.

**Brama `udp_engage` to tylko optymalizacja CPU — poprawność zawsze rozstrzyga
conntrack.** Nawet zbyt niski próg nie zdropuje legalnych odpowiedzi (mają wpis →
hit → pass); cięte są wyłącznie nieproszone miss-y. Próg decyduje jedynie, KIEDY
wydawać CPU na lookupy.

**Fail-open:** filtr to allowlista OCHRONY, nie blocklista. Adres nieujęty w żadnej
klasie jest przepuszczany; zapomniana pula = brak ochrony dla niej (stan jak bez
filtra), zero outage. Odpięcie programu = ruch płynie dalej bez filtracji.

## Tryby (mapa `cfg`)

Wszystko przełączane w locie przez `loader set`:

| Flaga | Znaczenie | Default |
|-------|-----------|---------|
| `drop_natpool` | drop SYN/ACK do puli bez wpisu conntrack | 0 (count-only) |
| `drop_natpool_udp` | drop UDP do puli bez wpisu, gdy detektor zaangażowany | 0 |
| `drop_bad_flags` | drop niepoprawnych kombinacji flag TCP do puli | 0 |
| `drop_routed` | drop SYN/ACK do klasy 2 bez zapisanego SYN | 0 |
| `record_routed` | zapisuj wychodzące SYN-y klasy 2 do LRU | 1 |
| `measure_amp` | mierz retransmisje missów (amplifikacja) | 1 |
| `udp_auto` | detektor `bpf_timer` steruje `udp_engage` | 1 |
| `udp_pps_threshold` | próg pps/IP odpalający ochronę UDP | 200000 |

Domyślny stan (świeży `load`) to **count-only** — nic nie jest dropowane, tylko
liczniki i LRU. Bezpieczne do obserwacji przed uzbrojeniem.

## Konfiguracja prefiksów

Dwa statyczne pliki, edytowane pod własną sieć (wartości domyślne to zakresy
dokumentacyjne RFC 5737 — **do podmiany**):

- `nat_pools.conf` — pule NAT/SNAT (klasa 1). Trzymać w zgodzie ze zbiorem źródeł
  SNAT w firewallu.
- `client_ranges.conf` — routowane zakresy klienckie (klasa 2). Statyczne agregaty.

`gen_prefixes.sh` składa z nich `prefixes.conf` (format: `CIDR klasa`), bez żadnej
zależności od tablicy routingu.

## Build i obsługa ręczna

Wymagane: `clang`, `llvm`, `libbpf-dev`, `libelf`, `bpftool`. Kernel **≥ 5.19**
(kfunci `bpf_xdp_ct_lookup`/`bpf_ct_release`; `bpf_timer` ≥ 5.15). `vmlinux.h`
generowany z BTF działającego kernela — **budować na maszynie docelowej**.

```sh
make                                   # natpool_filter.bpf.o + loader (+ vmlinux.h z BTF)
./gen_prefixes.sh nat_pools.conf client_ranges.conf > prefixes.conf
./loader load prefixes.conf            # load + pin do /sys/fs/bpf/natpool (count-only)
./loader attach bond0                  # XDP driver mode (bpf_link)
./loader set drop_natpool=1 drop_natpool_udp=1 drop_bad_flags=1   # >>> blokowanie <<<
./loader set drop_natpool=0 drop_natpool_udp=0 drop_bad_flags=0   # tylko liczenie
./loader set udp_pps_threshold=200000  # prog czulosci detektora UDP (pps/IP)
./loader stats                         # liczniki (suma per-CPU)
./loader detach bond0                  # natychmiastowy rollback
./loader unload
./unit_test.sh                         # testy (TCP/synack + UDP + bad-flags)
```

### Dobór progu UDP

`udp_pps_threshold` to pps na **pojedynczy adres puli**. Ustawić:
- **grubo powyżej** szczytu legalnego UDP pojedynczego abonenta (żeby detektor spał
  w czasie pokoju — inaczej niepotrzebne lookupy), oraz
- **na/poniżej** progu, przy którym Twój system anty-DDoS banuje host po UDP pps
  (żeby XDP zaczął ciąć zanim/gdy zewnętrzny scrubber zareaguje).

Podgląd bieżącego szczytu per-IP: `bpftool map lookup pinned /sys/fs/bpf/natpool/tmr
key 0 0 0 0` (pole `last_max_pps`).

## Podpięcie przez bpf_link i bezprzerwowa aktualizacja

Program podpinany jest **`bpf_link`iem** (nie starym netlinkowym `bpf_xdp_attach`),
a link jest pinowany jako `link_<ifname>`. Daje to:

- **Aktualizacja bez luki:** `loader load` wczytuje nowy program i czyści piny
  map/programu, ale **celowo zostawia pin linku** — stary program dalej filtruje,
  bo trzyma go link. Następne `loader attach <if>` robi `bpf_link_update()`, czyli
  **atomową podmianę w miejscu** (ten sam `link id`, nowy `prog id`, zero pakietów
  bez filtra). Bez tego każdy upgrade to `detach→load→attach` = okno fail-open.
- **Przeniesienie polityki:** `load` odczytuje działającą konfigurację ze starej
  mapy `cfg` i przenosi ją do nowej, więc aktualizacja nie cofa trybów blokowania do
  count-only. `udp_engage` jest resetowany (to stan detektora — timer odtworzy go w
  ciągu ticku).
- **Odporność na przypadkowe zdjęcie:** legacy `bpftool net detach` odbija się od
  linku (`Can't replace active BPF XDP link`).

`unload` to pełny demontaż (usuwa też pin linku ⇒ odpina filtr) — **nie używać do
aktualizacji**. `unit_test.sh` używa samego `load`, więc nie odpina żywego filtra.

## Autostart (przykład, init.d)

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

Całość owinięta `2>/dev/null` — fail-open: gdyby build/load/attach padł, router
forwarduje dalej bez filtra (brak ochrony, zero outage). `loader` znajduje swój `.o`
względem `/proc/self/exe`, więc działa z pełnej ścieżki bez `cd`.

## Pomiar amplifikacji (do decyzji DROP vs XDP_TX RST)

Dropnięty SYN/ACK skłania reflektor do retransmisji (chyba że używa SYN cookies —
wtedy nie trzyma stanu i nie retransmituje). Filtr mierzy to na żywo: każdy SYN/ACK
bez stanu (miss) trafia do LRU `synack_seen`; pierwszy raz = `miss_unique_flows`,
powtórka = `miss_retransmissions`.

**Amplifikacja = (miss_unique_flows + miss_retransmissions) / miss_unique_flows.**
≈1.0 → reflektory nie retransmitują → RST nic nie da. ≫1 → RST ucinałby retransmisje
u źródła — ale opłaca się dopiero, gdy flood realnie dławi kartę (RST to `XDP_TX`,
czyli zaczynamy emitować pakiety/backscatter). Domyślnie: DROP; RST jest świadomie
poza zakresem tej wersji.

## Upgrade kernela

Warstwy przetrwania aktualizacji kernela:
- **`loader` (binarka)** — userspace (libbpf/libc), kernel-niezależny.
- **`.o` na nowym kernelu** — libbpf robi CO-RE (relokacje offsetów struktur) i
  rozwiązuje kfunci względem BTF działającego kernela przy load; typowy update nie
  wymaga przebudowy.
- **Self-heal (gdy load padnie)** — `rm -f vmlinux.h; make`: wymusza regen
  `vmlinux.h` ze świeżego `/sys/kernel/btf/vmlinux` (reguła w Makefile nie ma
  prereq — bez `rm` `make` NIE odświeżyłby BTF), potem rebuild `.o`, retry.
- **Zmiana sygnatur kfunców** — tego żaden rebuild nie naprawi (wymaga edycji kodu);
  wtedy fail-open zapewnia brak outage do ręcznej naprawy. `bpf_ct_opts` zdefiniowana
  ręcznie jako 16 B (nie ma jej w vmlinux BTF) — przy zmianie layoutu w kernelu
  wymaga aktualizacji w `.bpf.c`.

## Ograniczenia

- **Tylko IPv4.** IPv6 nie jest klasyfikowany ani filtrowany.
- **Klasa 2 wymaga symetrii** ruchu przychodzącego (patrz wyżej) — przy asymetrii nic
  nie chroni.
- **Enkapsulacje** poza czystym IPv4/802.1Q (PPPoE, MPLS itd.) nie są parsowane —
  taki ruch trafia w bezwarunkowy PASS. Filtr zakłada, że po (maks. dwóch) tagach
  VLAN jest nagłówek IPv4.
- LRU klasy 2 nie liczy evictionów; pod ekstremalnym ruchem wychodzącym możliwe
  wyparcie zapisanego SYN-a przed jego SYN/ACK-iem (rzadkie).

## Pliki

- `natpool_filter.bpf.c` / `natpool_filter.h` — program BPF + współdzielone struktury
- `loader.c` — narzędzie: load/pin, attach/detach (bpf_link), set, stats, unload
- `nat_pools.conf` / `client_ranges.conf` — prefiksy klasy 1 / 2 (przykładowe, RFC 5737)
- `gen_prefixes.sh` — składa `prefixes.conf` z powyższych
- `unit_test.sh` — testy przez `bpftool prog run` (pakiety syntetyczne + realny conntrack)
- `Makefile` — build (clang → `.o`, cc → `loader`); `vmlinux.h` z BTF, niecommitowany
- `OPERATORS.md` / `OPERATORS.pl.md` — instrukcja dla operatorów (EN / PL)

## Autor

Kamil Mazur (kmazur@goodhost.eu)

## Licencja

GPL-2.0 — program BPF używa kernelowych helperów GPL-only, więc sekcja licencji BPF
jest zadeklarowana jako `GPL`. Patrz [LICENSE](LICENSE).
