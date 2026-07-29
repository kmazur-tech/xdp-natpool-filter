# Filtr XDP na pule NAT — instrukcja dla operatorów

*Wersje językowe: [English](OPERATORS.md) | [polski](OPERATORS.pl.md)*

## Co to jest
Program XDP podpięty na `bond0` (lub innym interfejsie wyjściowym) routera. Chroni
adresy **puli NAT/CGNAT** przed kilkoma rodzajami ataków, przepuszczając bez tknięcia
legalny ruch. Odciąża CPU routera, BRAS-y i tablicę conntrack.

Trzy ochrony, wszystkie na adresy puli NAT:
1. **TCP SYN/ACK-reflection** — nieproszone pakiety SYN/ACK (odbicia reflection/DDoS).
2. **UDP-amplification** — nieproszone floody UDP (SSDP/NTP/DNS/CLDAP itd.).
3. **Niepoprawne flagi TCP** — kombinacje, których poprawny stos nigdy nie wysyła
   (skan null, XMAS, SYN+FIN, SYN+RST, FIN bez ACK). Sprawdzane bez zaglądania do
   conntracka, więc kosztują tyle co nic i działają zawsze.
4. **Przychodzące floody TCP SYN** - czyste SYN-y próbujące otworzyć połączenie
   DO adresów puli (pule nie hostują usług, więc to śmieć). Domyślnie wyłączone;
   zastrzeżenie: tnie też aktywny FTP, patrz README przed uzbrojeniem.

## Jak działa (w skrócie)
Dla adresów **puli NAT** przychodzący pakiet jest sprawdzany w tablicy conntrack —
czy to odpowiedź na połączenie, które klient sam zestawił:
- **jest wpis → legalne → przepuść**
- **brak wpisu → nieproszone → policz; w trybie blokowania: odrzuć na karcie**

Pule NAT nie hostują usług, więc nieproszony pakiet do puli to zawsze śmieć —
blokowanie nie tyka legalnego ruchu (odpowiedzi mają wpis w conntracku → przechodzą).

### Różnica TCP vs UDP — WAŻNE
- **TCP (SYN/ACK): always-on.** Każdy SYN/ACK do puli jest sprawdzany zawsze
  (SYN/ACK to rzadki pakiet, sprawdzanie jest tanie).
- **UDP: automatyczne, reaktywne.** UDP to ruch masowy (QUIC/443, DNS, gry), więc
  w czasie pokoju filtr **tylko liczy** UDP do puli — NIE sprawdza conntracka (żeby
  nie obciążać CPU). Wbudowany **auto-detektor** (skan co ~1 s) włącza
  sprawdzanie+blokowanie UDP **sam**, gdy ruch UDP do pojedynczego adresu puli
  przekroczy `udp_pps_threshold`. Po ustaniu ataku sam się wyłącza. **Operator nie
  musi nic robić przy ataku UDP — to działa automatycznie.**

Klienci z adresami **publicznymi routowanymi** (klasa 2) są chronieni tylko jeśli
ich ruch przychodzący jest symetryczny (wchodzi przez ten interfejs). Domyślnie
klasa 2 jest wyłączona — patrz README.

---

## Komendy
Uruchamiać jako `root`. Projekt zwykle w `/opt/xdp-natpool-filter`. `loader` znajduje
swój `.o` względem własnej lokalizacji, więc działa z pełnej ścieżki bez `cd`.

### Sprawdzić, czy filtr działa i w jakim trybie
```sh
bpftool net show | grep bond0                            # linia z "id N" = filtr podpięty
/opt/xdp-natpool-filter/loader set drop_natpool=1        # ustawia i DRUKUJE pełny cfg
```
Linia cfg pokazuje wszystkie tryby, m.in.:
- `drop_natpool=1` — **TCP** SYN/ACK do puli: BLOKUJE (0 = tylko liczy)
- `drop_natpool_udp=1` — **UDP** do puli: BLOKUJE gdy detektor zaangażowany (0 = tylko liczy)
- `drop_bad_flags=1` — niepoprawne flagi TCP do puli: BLOKUJE (0 = tylko liczy)
- `drop_natpool_syn=1` - przychodzący czysty SYN do puli: BLOKUJE (0 = tylko liczy)
- `udp_auto=1` — auto-detektor UDP włączony (steruje `udp_engage` sam)
- `udp_engage=0/1` — **czy właśnie trwa atak UDP**: 0 = pokój, **1 = detektor wykrył flood i tnie**
- `udp_pps_threshold` — próg pps/IP odpalający ochronę UDP

### Statystyki (sumy od załadowania filtra)
```sh
/opt/xdp-natpool-filter/loader stats
```
Najważniejsze liczniki:
| Licznik | Znaczenie |
|---|---|
| `natpool_ct_hit` | legalne odpowiedzi TCP (rośnie stale) |
| `natpool_ct_miss` | **nieproszone SYN/ACK do puli** (kandydaci do dropa) |
| `natpool_dropped` | ile SYN/ACK realnie odrzucono |
| `natpool_udp_seen` | cały UDP do puli (rośnie stale, duże liczby = normalne) |
| `natpool_udp_miss` | **nieproszony UDP do puli** — liczony tylko gdy detektor zaangażowany |
| `natpool_udp_dropped` | ile UDP realnie odrzucono (rośnie tylko podczas ataku UDP) |
| `udp_engage_ticks` | ile razy (sekund) detektor UDP był zaangażowany — **>0 = był atak UDP** |
| `tcp_badflags_seen` / `tcp_badflags_dropped` | TCP do puli z niepoprawnymi flagami / ile odrzucono |
| `natpool_syn_seen` | **przychodzące czyste SYN-y do puli** (śmieć/skan/flood, kandydaci do dropa) |
| `natpool_syn_dropped` | ile z nich realnie odrzucono (`drop_natpool_syn`) |
| `natpool_frag_seen` | nie-pierwsze fragmenty IP do puli (tylko POMIAR, nic nie tnie) |
| `miss_retransmissions` / `miss_unique_flows` | amplifikacja SYN/ACK = (unique+retrans)/unique |

### Bieżący rate (pakiety/s) — wklej i uruchom
```sh
L=/opt/xdp-natpool-filter/loader; A=$($L stats); sleep 20; B=$($L stats)
paste <(echo "$A") <(echo "$B") | awk '{printf "%-24s %+d/s\n",$1,($4-$2)/20}'
```

### Podejrzeć szczyt UDP per-IP (czy detektor blisko progu)
```sh
bpftool map lookup pinned /sys/fs/bpf/natpool/tmr key 0 0 0 0 | grep last_max_pps
#   last_max_pps = najwyższy pps na pojedynczy adres puli w ostatnim ~1 s.
#   Gdy przekroczy udp_pps_threshold, detektor sam włącza blokowanie UDP.
```

---

## Zmiana ustawień

```sh
L=/opt/xdp-natpool-filter/loader
$L set drop_natpool=1      # / =0        TCP SYN/ACK: blokuj / tylko licz
$L set drop_natpool_udp=1  # / =0        UDP: blokuj gdy atak / tylko licz
$L set drop_bad_flags=1    # / =0        niepoprawne flagi TCP: blokuj / tylko licz
$L set drop_natpool_syn=1  # / =0        przychodzący SYN do puli: blokuj / tylko licz (FTP!)
$L set udp_pps_threshold=300000          # próg czułości detektora UDP (pps/IP)
$L set udp_auto=0 udp_engage=1           # WYMUŚ blokowanie UDP (pomija detektor)
$L set udp_auto=1                        # wróć do automatu
```

### Aktualizacja filtra BEZ przerwy w ochronie
Filtr jest podpięty przez `bpf_link`, więc nowy program podmienia się **atomowo** —
ruch nie ma ani chwili bez filtra, a ustawienia są przenoszone automatycznie:
```sh
/opt/xdp-natpool-filter/loader load /opt/xdp-natpool-filter/prefixes.conf
/opt/xdp-natpool-filter/loader attach bond0        # wypisze "program swapped in place ... no traffic gap"
```
**Nie używać `unload` do aktualizacji** — to pełny demontaż (odpina filtr).

### Awaria / natychmiastowy rollback (całkowite odpięcie filtra)
```sh
/opt/xdp-natpool-filter/loader detach bond0
```
Ruch płynie dalej bez filtra od razu. Ponowne podpięcie: `... loader attach bond0`.

---

## Jak rozpoznać atak
**Baseline czasu pokoju:** `natpool_ct_miss` niski (kilkadziesiąt/s), hit ~99%; UDP
`udp_engage=0`, `udp_engage_ticks` nie rośnie, `last_max_pps` znacznie poniżej progu.

- **Atak SYN/ACK (TCP):** `natpool_ct_miss` skacze w setki tysięcy–miliony/s,
  `natpool_dropped` rośnie. Filtr tnie automatycznie (blokowanie always-on).
- **Atak UDP-amp:** `udp_engage` przeskakuje na **1**, `udp_engage_ticks` rośnie,
  `natpool_udp_dropped` rośnie. Detektor włącza się i tnie **sam**. Po ataku
  `udp_engage` wraca na 0.

**Blokowanie jest bezpieczne do trzymania na stałe** — pule nie hostują usług; UDP
tnie tylko przy realnym floodzie powyżej progu, a legalne odpowiedzi i tak mają wpis
w conntracku i przechodzą.

## Uwaga po failoverze / restarcie
Jeśli router właśnie przejął ruch, poczekaj aż stan conntrack się ustabilizuje —
świeżo zsynchronizowane sesje mogą przez chwilę pokazywać się jako miss. Filtr wstaje
automatycznie z autostartu (patrz README) w trybie blokowania.
