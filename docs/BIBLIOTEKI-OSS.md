# Biblioteki i narzędzia OSS dla Attack Surface Intelligence (Go + PostgreSQL)

> Research z 2026-11-21. Każdy fakt pochodzi ze źródła pierwotnego (repo GitHub, plik LICENSE, oficjalna dokumentacja, pkg.go.dev / proxy.golang.org, nmap.org). Metadane repo (licencja, `pushed_at`, gwiazdki, ostatni release) pobrano przez `gh api repos/OWNER/REPO` i `gh api repos/OWNER/REPO/releases/latest`, a wersje modułów Go przez `https://proxy.golang.org/<moduł>/@latest`.
> Fragmenty oznaczone **niezweryfikowane** to wnioski lub praktyka, których nie potwierdziłem w źródle pierwotnym.
> Uwagi licencyjne nie są poradą prawną. Przy przenoszeniu praw autorskich na AGH warto je pokazać prawnikowi uczelni.

Kontekst: [WYMAGANIA.md](WYMAGANIA.md) (plan: nmap przez exec, chi + templ/htmx, goose + sqlc + pgx, kolejka SKIP LOCKED, pgcrypto).

---

## 0. Najważniejsze wnioski (TL;DR)

1. **Wykrywanie hostów bez roota:** nieuprzywilejowany `nmap -sn` wysyła tylko `connect()` na porty 80 i 443. Nie wysyła ICMP ani ARP. Rekomendacja: własny, czysto Go-wy **TCP-connect discovery** na liście portów od AGH (np. 22, 80, 443, 3389, 8080, 8443…). Jako opcjonalny dodatek **ICMP echo przez nieuprzywilejowane gniazdo `udp4`** (`golang.org/x/net/icmp` albo `pro-bing`). Docker domyślnie ustawia w kontenerze `net.ipv4.ping_group_range = "0 2147483647"`, więc działa to bez `CAP_NET_RAW`. Potem `nmap -sV` (connect scan, `-sT -Pn`) tylko na żywych hostach i otwartych portach.
2. **Jeśli wolno użyć uprawnień w kontenerze:** Docker domyślnie daje `NET_RAW`. Kontener uruchomiony jako root może więc robić `nmap -sS` i ICMP bez `--privileged`. Kontener jako zwykły użytkownik potrzebuje file capabilities (`setcap`) i `nmap --privileged`.
3. **Licencja nmapa (NPSL 0.95) to ryzyko przy przeniesieniu praw.** NPSL uznaje za utwór zależny program „zaprojektowany specjalnie do uruchamiania nmapa i parsowania wyników”. Wtedy przy *dystrybucji* całość musi iść na NPSL. Rekomendacja: nmap jako **wymienny, opcjonalny backend** za interfejsem. Rdzeń (discovery, porty, HTTP/TLS, sygnatury) w czystym Go na licencjach MIT/BSD/Apache. Import XML nmapa od użytkownika NPSL wprost dopuszcza.
4. **wappalyzergo:** kod jest MIT, ale wbudowana baza `fingerprints_data.json` pochodzi z repozytoriów na **GPL-3.0** (enthec/webappanalyzer, HTTPArchive/wappalyzer). To ryzyko licencyjne. Bezpieczniej trzymać własne sygnatury YAML.
5. **Nie używać:** masscan (AGPL-3.0), RustScan (GPL-3.0), godojo (GPL-3.0), go-ping/ping (porzucone), robfig/cron (ostatni commit 2021), hdm/jarm-go i fingerprintx (zarchiwizowane), gorilla/csrf (niezałatana CVE-2025-47909). Szczegóły w sekcji 7.

---

## 1. Wykrywanie hostów bez roota i bez ICMP

### 1.1. Co dokładnie robi nmap (dokumentacja nmap.org)

Źródło: <https://nmap.org/book/man-host-discovery.html>

| Sytuacja | Zachowanie nmapa (cytat / parafraza z dokumentacji) |
|---|---|
| `-sn`, użytkownik **uprzywilejowany** | „The default host discovery done with `-sn` consists of an ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request.” |
| `-sn`, użytkownik **nieuprzywilejowany** | „only SYN packets are sent (using a `connect` call) to ports 80 and 443 on the target.” Bez ICMP i bez ARP. |
| Lokalny Ethernet | „When a privileged user tries to scan targets on a local ethernet network, ARP requests are used unless `--send-ip` was specified.” ARP to tryb dla uprzywilejowanych. Strona nie mówi wprost, że ARP *wymaga* roota, ale łączy go z użytkownikiem uprzywilejowanym. W kontenerze na sieci bridge cele i tak nie leżą w tym samym segmencie L2, więc ARP nie gra roli. |
| `-PS<porty>` bez uprawnień | „For unprivileged users, a workaround is automatically employed whereby the `connect` system call is initiated against each target port.” Host jest „up”, gdy `connect` szybko się powiedzie albo zwróci ECONNREFUSED (czyli przyszedł SYN/ACK albo RST). |
| `-PA<porty>` bez uprawnień | Używa tego samego obejścia `connect`. Dokumentacja zaznacza: „This workaround is imperfect because `connect` is actually sending a SYN packet rather than an ACK.” |
| `-PU`, `-PE`/`-PP`/`-PM` | Strona nie podaje wymagań wprost. Mówi tylko ogólnie, że „only the privileged user root is generally able to send and receive raw TCP packets”. To, że `-PU`/`-PE` wymagają surowych gniazd, jest **wnioskiem (niezweryfikowane wprost w man page)**. |
| `-Pn` | „skips the host discovery stage altogether”. nmap skanuje wtedy każdy adres. Przy >10k IP i kilku portach to nadal wykonalne w trybie connect. |

Skanowanie portów (<https://nmap.org/book/man-port-scanning-techniques.html>): `-sS` wymaga „proper privileges to send raw packets (requires root access on Unix)”. `-sT` to „the default TCP scan type when SYN scan is not an option”. Oraz: „unprivileged users can only execute connect and FTP bounce scans”. Wynika z tego, że `-sU` wymaga uprawnień.

### 1.2. `--privileged`, `--unprivileged` i capabilities Linuksa

Źródło: <https://nmap.org/book/man-misc-options.html>

- `--privileged`: „Tells Nmap to simply assume that it is privileged enough to perform raw socket sends, packet sniffing…”. Domyślnie „Nmap quits if such operations are requested but `geteuid` is not zero”. Opcja jest „useful with Linux kernel capabilities”. Działa też zmienna `NMAP_PRIVILEGED`.
- `--unprivileged` (lub `NMAP_UNPRIVILEGED`) wymusza tryb bez surowych gniazd. Przydaje się do testów.
- Wiki twórców nmapa (<https://secwiki.org/w/Running_nmap_as_an_unprivileged_user>): `sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap`, a potem `nmap --privileged -sS …`. Ostrzeżenie: „WARNING: This is dangerous”, bo skrypty NSE mogą sniffować i zmieniać konfigurację sieci, co może prowadzić do eskalacji do roota.

### 1.3. Docker: co jest domyślnie dostępne

- Domyślne capabilities kontenera (<https://docs.docker.com/engine/containers/run/>) obejmują `NET_RAW` i `NET_BIND_SERVICE`. **`NET_ADMIN` nie jest domyślne**, dodaje się je przez `--cap-add=NET_ADMIN` (lub `cap_add:` w compose).
- Moby (źródło: [`daemon/oci_linux.go`](https://github.com/moby/moby/blob/master/daemon/oci_linux.go)) dla kontenerów z własną przestrzenią sieciową ustawia domyślnie:
  - `net.ipv4.ping_group_range = "0 2147483647"` z komentarzem „allow unprivileged ICMP echo sockets without CAP_NET_RAW”,
  - `net.ipv4.ip_unprivileged_port_start = "0"`.
  Nie robi tego przy `network_mode: host`, przy dołączaniu do cudzej przestrzeni sieciowej ani przy user namespaces (więc również nie w rootless Dockerze). Poprawka detekcji userns: [moby#43084](https://github.com/moby/moby/pull/43084) (release notes 20.10).
- Domyślna wartość jądra to `"1 0"`: „nobody (not even root) may create ping sockets” (<https://docs.kernel.org/networking/ip-sysctl.html>). Na hoście bez Dockera trzeba więc ustawić sysctl.

Wnioski praktyczne:
- Kontener jako **root** (domyślnie) z domyślnymi capabilities: `geteuid()==0`, a `NET_RAW` jest efektywne. `nmap -sS` i `-PE` powinny działać bez `--privileged` w Dockerze. To, czy nmap nie potrzebuje do tego dodatkowo `NET_ADMIN`, jest **niezweryfikowane** (secwiki podaje go w zestawie dla setcap).
- Kontener jako **użytkownik nie-root** (zalecane): efektywne capabilities znikają. Trzeba `setcap cap_net_raw…+eip` na binarce nmapa w obrazie i `NMAP_PRIVILEGED=1`, albo zostać przy trybie connect.
- Podman domyślnie usuwa `NET_RAW` (wynik wyszukiwania, **niezweryfikowane** w dokumentacji Podmana). Nie zakładajmy, że jury uruchomi to w Dockerze z domyślnymi capabilities.

### 1.4. Alternatywy

| Narzędzie | Repo / licencja (plik LICENSE) | Aktywność | Bez roota? | cgo / libpcap | Ocena dla nas |
|---|---|---|---|---|---|
| **naabu** | <https://github.com/projectdiscovery/naabu>, MIT | v2.7.0 (2026-10-28), ~6.4k★, push 2026-11-21 | Tak, tryb **CONNECT** (`-scan-type c` jest domyślny; README: „Running CONNECT scan with non root privileges”). Host discovery (`-sn`, `-wn`, `-ps`, `-pa`, `-pe`, `-pp`, `-pm`, `-arp`, `-nd`) korzysta z surowych pakietów. Kod sprawdza uprawnienia przez `CAP_NET_RAW` albo euid 0 ([pkg/privileges/privileges_linux.go](https://github.com/projectdiscovery/naabu/blob/dev/pkg/privileges/privileges_linux.go)). | **Tak:** README „make sure to install `libpcap`”. `pkg/scan/scan_raw.go` i `pcap_device.go` importują `gopacket/pcap` z build tagiem `linux \|\| darwin \|\| windows`, więc biblioteka ciągnie cgo + libpcap także w trybie connect. | Dobre jako CLI. Jako biblioteka (`pkg/runner`, callback `OnReceive`) wymusza cgo. Do samego connect discovery lepszy własny kod Go (patrz 1.5). |
| **masscan** | <https://github.com/robertdavidgraham/masscan>, **AGPL-3.0** | ostatni release 1.3.2 (2021-01-31), ~26k★ | Nie (surowe pakiety, libpcap) | C, libpcap | **Odrzucić:** AGPL i root. |
| **RustScan** | <https://github.com/bee-san/RustScan>, **GPL-3.0** | 2.4.1 (2025-02-23), ~21k★ | connect scan | Rust | Odrzucić: GPL-3.0 i obcy język. Tylko przekazuje porty do nmapa. |
| **zmap** | <https://github.com/zmap/zmap>, Apache-2.0 | v4.4.0 (2026-05-29), ~6.4k★ | Nie. README: „(requires root privileges)” | C, surowe gniazda | Licencja OK, ale potrzebny root. Przesada przy 10k IP. |
| **fping** | <https://github.com/schweikert/fping>, licencja BSD-podobna (Stanford; plik COPYING, GitHub raportuje NOASSERTION) | v5.5 (2025-12-31) | **Tak.** README: tryb nieuprzywilejowany działa na Linuksie, gdy GID mieści się w `ping_group_range`: „particularly useful for running fping in rootless / unprivileged containers” | C, binarka | Dobra opcja jako zewnętrzny exec do ICMP sweep. Licencja permisywna. |
| **golang.org/x/net/icmp** | <https://github.com/golang/net>, BSD-3-Clause | v0.63.0 (2026-11-17) | **Tak.** `ListenPacket`: „For non-privileged datagram-oriented ICMP endpoints, network must be "udp4" or "udp6"… Currently only Darwin and Linux support this.” (<https://pkg.go.dev/golang.org/x/net/icmp>) | czyste Go | Rekomendowany niskopoziomowy wariant ICMP. |
| **pro-bing** | <https://github.com/prometheus-community/pro-bing>, Apache-2.0 | v0.9.1 (2026-06-29), push 2026-11-20 | **Tak.** README: domyślnie „unprivileged” ping (SOCK_DGRAM + IPPROTO_ICMP, sieć `udp4`). Na Linuksie wymaga `sysctl net.ipv4.ping_group_range`. Alternatywa: `SetPrivileged(true)` + `setcap cap_net_raw=+ep` | czyste Go | Rekomendowany wysokopoziomowy wariant ICMP. Następca `go-ping/ping`. |
| **go-ping/ping** | <https://github.com/go-ping/ping>, MIT | README: „Deprecated… no longer maintained” | n/d | n/d | Odrzucić, zastąpione przez pro-bing. |

### 1.5. Czysty Go TCP-connect probing

Sam stdlib wystarcza: `net.Dialer{Timeout: …}.DialContext(ctx, "tcp", ip:port)`.
- Udane połączenie oznacza otwarty port i host up.
- `errors.Is(err, syscall.ECONNREFUSED)` oznacza zamknięty port, ale host up. To ta sama logika co obejście `connect` w nmapie (RST oznacza, że host żyje).
- Timeout oznacza filtrowanie lub brak hosta.

Zalety: zero cgo, zero uprawnień, pełna kontrola tempa (`golang.org/x/time/rate`) i równoległości. Wynik zapisujemy wprost do Postgresa.

Uwagi (**niezweryfikowane**, praktyka):
- limit deskryptorów (`ulimit -n`),
- tablica conntrack przy NAT/bridge Dockera: przy dużej liczbie równoległych połączeń warto ograniczyć concurrency,
- przy hostach z firewallem DROP na wszystkich portach z listy host będzie wyglądał na „down”. Dlatego warto dołożyć ICMP `udp4`, a w modelu danych rozróżniać `no_response` od `gone`.

### 1.6. Rekomendacja dla naszego stosu

**Domyślny pipeline (działa bez roota i bez dodatkowych capabilities):**
1. `internal/target`: rozwinięcie CIDR (`net/netip`), podział na grupy.
2. **Discovery = czysty Go**: (a) TCP connect na liście portów od AGH (np. `22,80,443,445,3389,8000,8080,8443,…`) z limiterem `rate.Limiter` i semaforem równoległości, (b) opcjonalnie ICMP echo przez `pro-bing`/`x/net/icmp` w trybie `udp4`. Działa od ręki w Dockerze dzięki domyślnemu `ping_group_range`. Host jest żywy, jeśli odpowie którąkolwiek metodą.
3. **Skan portów żywych hostów**: ten sam silnik connect na szerszej liście portów (czysty Go). Opcjonalny backend **`nmap -sT -Pn -sV -oX`** tylko na żywych hostach i otwartych portach, za interfejsem `Scanner` (patrz licencja w 2.1).
4. HTTP/TLS fingerprinting w czystym Go (sekcja 3).

**Tryb „privileged” (opcja konfiguracyjna, gdy AGH pozwoli):** obraz z nmapem, `cap_add: [NET_RAW]` (domyślnie i tak jest) + ewentualnie `NET_ADMIN`, kontener jako root albo `setcap` na nmapie + `NMAP_PRIVILEGED=1`. Daje to `nmap -sn` z ICMP/SYN/ACK oraz `-sS`. To pytanie do mentorów (WYMAGANIA.md, pytanie 2).

---

## 2. Skanowanie portów i wykrywanie usług

### 2.1. nmap: licencja NPSL i co z niej wynika

- Repo: <https://github.com/nmap/nmap>. Najnowszy tag `v7.992`, push 2026-11-20, ~14k★. Plik `LICENSE`: „Nmap Public Source License Version 0.95” (GitHub raportuje NOASSERTION). Przegląd: <https://nmap.org/npsl/>.
- NPSL to GPLv2 plus dodatkowe warunki, które mają pierwszeństwo nad GPL („You may not distribute Covered Software or Derivative Works under plain GPL terms”). Cel licencji według nmap.org: „Prohibit redistribution and use of Nmap within proprietary hardware and software products”. Dla firm przewidziana jest płatna licencja Nmap OEM.
- **Sekcja 3 „Derivative Works”** (cytaty z pliku LICENSE). Za utwór zależny uznawany jest program, który:
  - „Integrates source code from Covered Software”,
  - „Reads or includes Covered Software data files, such as nmap-os-db or nmap-service-probes”,
  - „**Is designed specifically to execute Covered Software and parse the results** (as opposed to typical shell or execution-menu apps…)”,
  - „Links (statically or dynamically) to a library which does any of the above”,
  - „Executes a helper program, module, or script to do any of the above”.
  Dystrybucja takiego utworu „must be under the terms of this license… including the requirements for distributing their source code and allowing royalty-free redistribution”.
- Furtka w tej samej sekcji: licencja nie obejmuje oprogramowania, które nie potrzebuje praw z niej wynikających, np. „the ability to parse Covered Software results provided by an end user or to execute Covered Software that end user may have already installed”, o ile pozwala na to dozwolony użytek.
- **Sekcja 6 „External Deployment”**: system hostowany „designed to execute Nmap scans for users” musi wyświetlać informację, że używa Nmap Security Scanner, z linkiem do <https://nmap.org/>.

**Implikacje dla AGH (moja interpretacja, nie porada prawna):**
- Obowiązki NPSL/GPL powstają przy **dystrybucji**. Wewnętrzne użycie przez zespół AGH nie wymaga udostępniania kodu. Jeśli jednak AGH kiedyś rozpowszechni produkt (np. obraz Dockera z nmapem i naszym wrapperem), interpretacja Nmapa wymaga licencji NPSL dla całości. Kłóci się to z ewentualną komercjalizacją po przeniesieniu praw.
- Nasz kod pozostaje naszą własnością (prawa przechodzą na AGH), ale moduł „uruchom nmapa i sparsuj XML” mieści się w definicji z sekcji 3. Dotyczy to też modułu MIT `Ullaakut/nmap`: jego licencja MIT nie zmienia tego, jak NPSL traktuje *nasz* program.
- **Rekomendacja:** rdzeń bez nmapa (czysty Go). nmap jako opcjonalny, niedystrybuowany backend (użytkownik instaluje go sam), plus import XML nmapa dostarczonego przez użytkownika. Nie wczytywać `nmap-service-probes` (to też wprost utwór zależny). W UI dodać notkę z sekcji 6, jeśli nmap jest włączony.

### 2.2. Wrappery Go dla nmapa

| Biblioteka | Licencja | Aktywność | Uwagi |
|---|---|---|---|
| **github.com/Ullaakut/nmap** (<https://github.com/Ullaakut/nmap>) | MIT | **v4.0.1 (2026-07-26)**, push 2026-11-16, ~1k★. Moduł `github.com/Ullaakut/nmap/v4` (naabu nadal używa v3.0.6) | README: „This library shells out to the `nmap` binary using Go's `exec` package and parses the XML output”. Zgodność z nmap 7.98. „For unprivileged runs, prefer connect scans (e.g. `-sT`)”. Dojrzałe API (builder opcji, struktury XML). Ograniczenia z 2.1. |
| **github.com/lair-framework/go-nmap** (<https://github.com/lair-framework/go-nmap>) | MIT | ostatni commit 2019-12-02 | Tylko parser XML. **Porzucone**, nie używać. |

Na potrzeby **importu** XML nmapa wystarczy kilka własnych struktur z `encoding/xml`.

### 2.3. naabu jako biblioteka

`github.com/projectdiscovery/naabu/v2/pkg/runner`: `runner.Options{Host: …, OnReceive: …}`. README, sekcja „Using naabu as library”: `OnResult` wywołuje się raz po zakończeniu, a `OnReceive` w czasie rzeczywistym. Licencja MIT. Wady opisane w 1.4: cgo i libpcap w buildzie, bardzo duże drzewo zależności ProjectDiscovery. Ma wbudowaną integrację z nmapem (`-nmap-cli`), a README ostrzega: „Naabu allows arbitrary binary execution as a feature”. **Ocena:** zbędne, skoro discovery i porty robimy w kilkudziesięciu liniach Go.

### 2.4. fingerprintx i nerva (praetorian-inc)

- **fingerprintx** (<https://github.com/praetorian-inc/fingerprintx>): Apache-2.0, v1.1.19 (2026-01-01), **repo zarchiwizowane** (`archived: true`).
- **nerva** (<https://github.com/praetorian-inc/nerva>): Apache-2.0, v1.84.5 (2026-11-17), ~380★. README: „Nerva is a maintained fork of fingerprintx”. Ma „170+ Protocol Plugins” (TCP/UDP/SCTP), „76 HTTP Fingerprinters” oraz bibliotekę Go (`github.com/praetorian-inc/nerva/pkg/plugins`, `pkg/scan`). Dobra alternatywa dla `nmap -sV` na permisywnej licencji, działająca przez zwykłe połączenia TCP. Nie sprawdziłem, czy nerva korzysta z danych nmapa (np. `nmap-service-probes`): **niezweryfikowane**. Uwaga: opcja `--misconfigs` wykracza poza „tylko pasywne/bezpieczne” i trzeba ją przejrzeć przed włączeniem.

### 2.5. zgrab2

<https://github.com/zmap/zgrab2>: v1.0.0 (2025-12-04), push 2026-10-22, ~2.2k★. Plik LICENSE: Apache-2.0 dla kodu UMich i ISC dla forków kodu Google. Moduły protokołów (banner grabbing: http, tls, ssh, ftp, …), działa w trybie connect, bez roota. Projektowany głównie jako CLI (stdin → JSON). Jako biblioteka wymaga Go 1.26+. Do naszej skali zbyt ciężki. Przydatny jako referencja, jak grabbować bannery.

---

## 3. Fingerprinting HTTP/TLS i wykrywanie technologii

### 3.1. projectdiscovery/httpx

<https://github.com/projectdiscovery/httpx>: MIT, v1.12.0 (2026-09-08), ~10.6k★. Funkcje: tytuł, status, nagłówki, `-favicon` (mmh3), `-jarm`, `-tls-grab`, `-tech-detect` (wappalyzergo). Biblioteka: README, sekcja „Using httpx as a library”: `Options` → runner → `RunEnumeration`. API jest w praktyce „CLI w strukturze”, a nie czysta biblioteka. Zależności są ogromne. **Rekomendacja:** własny fingerprinter na `net/http` + `crypto/tls` (pełna kontrola: tylko GET/HEAD, limit body, łańcuch przekierowań przez `CheckRedirect`). Z httpx bierzemy algorytm favicon hash (3.3). DefectDojo ma parser „httpx Scan”, więc możemy eksportować nasze wyniki w formacie JSONL httpx (sekcja 5).

### 3.2. projectdiscovery/wappalyzergo

<https://github.com/projectdiscovery/wappalyzergo>: plik `LICENSE.md` = MIT, v0.3.10 (2026-11-15), ~1.1k★, aktywne. API: `wappalyzer.New()` → `Fingerprint(resp.Header, body)` → `map[string]struct{}`. Opcjonalnie `FingerprintWithRuntime` z headless (Rod).

**Skąd pochodzą fingerprinty:** README: „Uses data from https://github.com/enthec/webappanalyzer, https://github.com/HTTPArchive/wappalyzer” oraz „auto-updating database”. Narzędzie `cmd/update-fingerprints/main.go` pobiera `https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/technologies/%s.json` i to samo z HTTPArchive. Wynik ląduje w osadzonym `fingerprints_data.json`.

**Licencje źródeł danych (pliki LICENSE):**
- <https://github.com/enthec/webappanalyzer>: **GPL-3.0**
- <https://github.com/HTTPArchive/wappalyzer>: **GPL-3.0**

**Wniosek:** kod biblioteki jest MIT, ale osadzona baza jest pochodną danych na GPL-3.0. Czy zbiór regexów podlega prawu autorskiemu (i czy wtedy nasz binarny produkt staje się GPL), tego nie rozstrzygam: **niezweryfikowane / do oceny prawnej**. Bezpieczna ścieżka na hackathon: używać wappalyzergo jako opcjonalnego, wyłączalnego modułu (lub tylko w trybie demo). Podstawą są **nasze własne sygnatury YAML** (nagłówek, ciasteczko, regex HTML, favicon mmh3, ścieżka GET), pisane od zera.

### 3.3. Favicon hash (mmh3, styl Shodana)

Algorytm z httpx ([common/stringz/stringz.go](https://github.com/projectdiscovery/httpx/blob/dev/common/stringz/stringz.go)):
```go
b64 := base64.StdEncoding.EncodeToString(data)
b64 = InsertInto(b64, 76, '\n')        // nowa linia co 76 znaków ORAZ na końcu (jak Python base64.encodebytes)
h := murmur3.New32WithSeed(0); h.Write([]byte(b64))
hash := int32(h.Sum32())               // wynik ze znakiem, zgodny z http.favicon.hash w Shodanie
```
Uwaga: `InsertInto` dopisuje separator także na końcu. Bez tego hashe nie będą zgodne.

| Biblioteka | Licencja | Aktywność | Uwagi |
|---|---|---|---|
| github.com/spaolacci/murmur3 | BSD-3-Clause | v1.1.0 (2017-12-10), push 2023 | Używana przez httpx. Stabilna, ale nierozwijana. |
| **github.com/twmb/murmur3** | BSD-3-Clause (plik LICENSE, GitHub: NOASSERTION; fork spaolacci) | tag v1.2.2, push 2026-11-09 | **Rekomendowana:** aktywna, kompatybilne API (`New32WithSeed`, `Sum32`). |

### 3.4. TLS: stdlib, tlsx, JARM, JA3

- **crypto/tls + crypto/x509 (stdlib)**: `tls.ConnectionState` daje wersję, cipher suite, ALPN i `PeerCertificates` (Subject, SAN, Issuer, NotBefore/NotAfter, klucz). Wystarcza w 100% do „TLS cert details”. Do skanowania ustawiamy `InsecureSkipVerify: true`, a weryfikację łańcucha robimy osobno (`x509.Certificate.Verify`), żeby oznaczyć certyfikaty self-signed albo wygasłe.
- **tlsx** (<https://github.com/projectdiscovery/tlsx>): MIT, v1.5.0 (2026-11-18). Tryby `ctls` (stdlib), `ztls` (zmap/zcrypto, stare wersje TLS, ale „TLS v1.3 is not supported by ztls”) i `openssl` (wymaga binarki openssl). JARM i JA3 („display ja3 fingerprint hash (using ztls)”). Biblioteka przez `examples/`. JARM w tlsx pochodzi z `github.com/hdm/jarm-go v0.0.8` (go.mod).
- **hdm/jarm-go** (<https://github.com/hdm/jarm-go>): BSD-3-Clause (LICENSE.txt), **zarchiwizowane** („This project is archived and is now read-only”). Działa (używa go tlsx), ale nie jest rozwijane. Oryginał w Pythonie: <https://github.com/salesforce/jarm> (BSD-3-Clause).
- **JA3** to odcisk *klienta* (ClientHello), więc dla skanera serwerów ma małą wartość. Po stronie serwera liczy się JARM / JA3S. `dreadl0ck/ja3` (BSD-3-Clause, v1.1.0, 2025-10-24) wymaga analizy pcap: nieprzydatne.
- **Rekomendacja:** stdlib na P0. JARM jako P3 przez `hdm/jarm-go` (permisywne, archiwum: nie krytyczne).

### 3.5. nuclei i nuclei-templates

- **nuclei** (<https://github.com/projectdiscovery/nuclei>): MIT, v3.11.1 (2026-08-08), ~33k★. SDK: `github.com/projectdiscovery/nuclei/v3/lib` ([lib/README.md](https://github.com/projectdiscovery/nuclei/blob/dev/lib/README.md)): `nuclei.NewNucleiEngine(...)`, `NewThreadSafeNucleiEngine`, `ExecuteWithCallback`. Opcje ograniczające ([lib/config.go](https://github.com/projectdiscovery/nuclei/blob/dev/lib/config.go)):
  - `WithTemplatesOrWorkflows` (własny katalog szablonów),
  - `WithTemplateFilters{Severity, ExcludeSeverities, ProtocolTypes, Tags, ExcludeTags, IncludeTags, IDs, TemplateCondition}`,
  - `WithGlobalRateLimit`, `WithConcurrency`,
  - `WithSandboxOptions(allowLocalFileAccess, restrictLocalNetworkAccess)`,
  - `WithTemplateUpdateCallback(disableTemplatesAutoUpgrade, …)`.
- Można więc zawęzić do `Severity: "info"`, `ProtocolTypes: "http"`, `Tags: ["tech","panel"]`. **Ale** filtr po tagach nie gwarantuje, że szablon wysyła tylko GET bez payloadów. Szablony „info” mogą zawierać POST lub fuzzing. Wymóg AGH „bez eksploitacji” trzeba zapewnić **własną, przejrzaną listą ID szablonów** albo własnym katalogiem. go.mod nuclei ma ok. 460 linii zależności. Licencji wszystkich zależności przechodnich nie sprawdzałem: **niezweryfikowane**.
- **nuclei-templates** (<https://github.com/projectdiscovery/nuclei-templates>): plik LICENSE = **MIT** („Copyright (c) 2025 ProjectDiscovery, Inc.”), v10.5.2 (2026-11-12).
- **Rekomendacja:** nie wciągać silnika nuclei. Format YAML nuclei (matchers: `word`, `regex`, `status`, `favicon` hash, `part: header/body`) traktować jako wzór naszego formatu sygnatur. Ewentualnie przenieść wybrane szablony `http/technologies` i `http/exposed-panels`: MIT pozwala, trzeba zachować nota copyright.

---

## 4. DNS i cele

| Komponent | Repo / licencja | Aktywność | Do czego / uwagi |
|---|---|---|---|
| **net/netip (stdlib)** | BSD-3 (Go) | n/d | `netip.ParsePrefix`, `Prefix.Masked()`, iteracja `Addr.Next()`. Wystarcza do rozwijania CIDR i dzielenia na grupy (np. /24). Zero zależności. **Rekomendowane.** |
| **projectdiscovery/mapcidr** | <https://github.com/projectdiscovery/mapcidr>, MIT | v1.1.97 (2025-10-28), push 2026-11-21 | „developed to ease load distribution for mass scanning operations; it can be used both as a library and as an independent CLI tool”: slicing po liczbie CIDR i hostów, agregacja, shuffle IP. Przydatne, jeśli nie chcemy pisać dzielenia sami. Shuffle pomaga rozłożyć obciążenie podsieci. |
| **miekg/dns** | <https://github.com/miekg/dns>, BSD-3-Clause | tag v1.1.73, ~8.8k★ | README: „DNS version 2 is now available at https://codeberg.org/miekg/dns… The version here will only see specific fixes… At some point this repo will be archived.” |
| **codeberg.org/miekg/dns** (v2) | BSD-3-Clause (LICENSE na Codebergu) | v0.6.139 (2026-11-21, proxy.golang.org) | Następca. Wersja 0.x, więc API może się zmieniać. Do PTR/A/AAAA wystarczy `net.Resolver` ze stdlib (`LookupAddr`, `LookupHost`). |
| **projectdiscovery/dnsx** | <https://github.com/projectdiscovery/dnsx>, MIT | v1.3.1 (2026-08-31) | Masowe zapytania DNS, filtr wildcard. Biblioteka `libs/dnsx` (README: „Dnsx as a library”). Opcjonalne. |
| **projectdiscovery/subfinder** | <https://github.com/projectdiscovery/subfinder>, MIT | v2.17.0 (2026-10-08), ~14.8k★ | Pasywne subdomeny. Jest SDK (README: „Subfinder Go library”). README: „many sources required API keys to work”. Poza zakresem P0. AGH skanuje własne sieci, więc wartość jest niewielka. |
| **crt.sh** | <https://crt.sh/> (usługa Sectigo) | n/d | Certificate Transparency: zapytanie `https://crt.sh/?q=%25.agh.edu.pl&output=json`. Limity i SLA: **niezweryfikowane**. Usługa bywa przeciążona, więc traktować wyłącznie jako opcjonalny dodatek. |

---

## 5. DefectDojo

- Repo: <https://github.com/DefectDojo/django-DefectDojo>, BSD-3-Clause, release 3.5.202 (2026-11-20).
- **API v2:** routing w [dojo/urls.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/urls.py): `v2_api.register(r"import-scan", ImportScanView)` i `r"reimport-scan"`, czyli `POST /api/v2/import-scan/` oraz `POST /api/v2/reimport-scan/` (multipart). Nagłówek autoryzacji: `Authorization: Token <api_key>` (standard DRF w DefectDojo, **niezweryfikowane w tej sesji**).
- **Pola** ([dojo/api_v2/serializers.py](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/api_v2/serializers.py), `CommonImportScanSerializer` / `ImportScanSerializer` / `ReImportScanSerializer`): `scan_type`, `file`, `engagement` (ID) albo `product_type_name`/`product_name`/`engagement_name` + `auto_create_context`, `test_title`, `scan_date`, `minimum_severity`, `active`, `verified`, `close_old_findings`, `deduplication_on_engagement`, `apply_tags_to_findings`, `service`, `version`, `build_id` itd. Reimport przyjmuje dodatkowo `test` i `do_not_reactivate`.
- **Import vs reimport** (<https://docs.defectdojo.com/import_data/import_scan_files/api_pipeline_modelling/>): `/import` zapisuje „each scan result in a discrete Test object”. `/reimport` porównuje wyniki w obrębie jednego testu i przy „Auto Create Context” może sam utworzyć Test, Engagement i Product. **Dla nas reimport jest naturalny:** każdy przebieg skanu to reimport do tego samego testu, a DefectDojo sam zamyka znaleziska, które zniknęły (`close_old_findings`).
- **Parsery przydatne dla nas** (nazwy `scan_type` z `get_scan_types()` w `dojo/tools/*/parser.py`):

| `scan_type` | Format | Uwagi z dokumentacji parsera |
|---|---|---|
| `Nmap Scan` | XML (`-oX`) | [docs/…/nmap.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/parsers/file/nmap.md) |
| `Nuclei Scan` | JSON nuclei | [nuclei.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/parsers/file/nuclei.md) |
| `httpx Scan` | **JSON Lines** (`httpx -json`), nie tablica | Jedno znalezisko na URL, severity **Info**. „-tech-detect is worth passing”. Rekordy z `"failed": true` są pomijane ([httpx.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/parsers/file/httpx.md)) |
| `Naabu Scan` | JSON Lines | Endpoint `//host:port`, severity zawsze Info, deduplikacja po host+port+protocol ([naabu.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/parsers/file/naabu.md)) |
| `Generic Findings Import` | CSV lub JSON (CSV, gdy nazwa pliku kończy się na `.csv`, inaczej JSON) | Wymagane kolumny CSV: `Date`, `Title`, `Description`, `Severity`. „JSON supports far more fields… Use JSON when you can.” ([generic.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/parsers/file/generic.md)) |

  Istnieją też parsery `masscan`, `whatweb`, `sslyze`, `sslscan`, `testssl`, `zap`, `openvas` (lista katalogu `dojo/tools`).
- **Rekomendacja eksportu:** (1) **Generic Findings Import (JSON)** jako główny format: pełna kontrola nad tytułem, opisem, severity, endpointami i tagami, plus nasze `confidence`/evidence w opisie. (2) Opcjonalnie emitować JSONL zgodny z `Naabu Scan` (porty) i `httpx Scan` (HTTP), żeby DefectDojo pokazał natywne widoki.
- **Klienci Go:** `DefectDojo/godojo` to **GPL-3.0** i według nazwy oraz opisu jest instalatorem DefectDojo, a nie klientem API: nie używać. `truemilk/go-defectdojo` (MIT, ~4★) jest niszowy. **Rekomendacja:** własny klient (~100 linii: `mime/multipart` + `net/http`).

---

## 6. Klocki backendu

Wersje z proxy.golang.org lub GitHub Releases. Licencje sprawdzone w plikach LICENSE.

| Komponent | Biblioteka | Licencja | Wersja / aktywność | Uwagi |
|---|---|---|---|---|
| Sterownik PG | **github.com/jackc/pgx/v5** (<https://github.com/jackc/pgx>) | MIT | v5.13.0 (2026-11-11, proxy), ~14k★ | Standard. `pgxpool`, `COPY`, typy `inet`/`cidr` → `netip`. Czyste Go. |
| Migracje | **github.com/pressly/goose/v3** (<https://github.com/pressly/goose>) | MIT (LICENSE; GitHub: NOASSERTION) | v3.30.1 (2026-11-12) | Migracje SQL lub Go, `embed.FS`. Rekomendowane. |
| Migracje (alt.) | github.com/golang-migrate/migrate/v4 | MIT (LICENSE; GitHub: NOASSERTION) | v4.20.1 (2026-09-09) | Też OK. Przy jednej bazie goose jest prostszy. |
| SQL → Go | **sqlc** (<https://github.com/sqlc-dev/sqlc>) | MIT | v1.31.1 (2026-04-22) | Generator (narzędzie, nie runtime). Obsługuje pgx/v5. |
| Router | **github.com/go-chi/chi/v5** | MIT | v5.5.0 (2026-10-14), ~23k★ | Middleware RBAC per trasa. |
| UI | **templ** (<https://github.com/a-h/templ>) | MIT | v0.3.1118 (2026-11-12) | Wersja 0.x, ale aktywna. Alternatywa bez generatora: `html/template`. |
| UI (JS) | **htmx** (<https://github.com/bigskysoftware/htmx>) | **0BSD** (Zero-Clause BSD; GitHub: NOASSERTION) | v4.0.2 (2026-11-18) | Uwaga: v4 to nowa linia. Przykłady w sieci są zwykle dla v2. Wersję trzeba przypiąć. |
| RBAC | **Apache Casbin** (<https://github.com/apache/casbin>) | Apache-2.0 | v3.11.0 (2026-08-04); moduł `github.com/apache/casbin/v3`. Stary `github.com/casbin/casbin/v2` ma ostatnią wersję v2.135.0 (2025-12-09) | Repo przeniesione do Apache. Przy 4 stałych rolach prostsza jest tabela `role_permissions` i middleware (jak w WYMAGANIA.md). Casbin tylko, jeśli chcemy pokazać politykę ABAC. |
| Scheduler | **github.com/go-co-op/gocron/v2** | MIT | v2.23.2 (2026-11-18) | Cron + interwały, aktywne. |
| Scheduler (odradzane) | github.com/robfig/cron/v3 | MIT | v3.0.1 z **2020-01-04**, ostatni commit 2021-01-06 | Nieutrzymywane. Jako parser wyrażeń cron nadal działa, ale lepiej gocron. |
| Kolejka w PG | **riverqueue/river** (<https://github.com/riverqueue/river>) | **MPL-2.0** | v0.51.2 (2026-11-09), ~5.9k★; sterownik `riverpgxv5` | MPL-2.0 to copyleft *na poziomie pliku*: modyfikacje plików River trzeba udostępnić, nasz kod pozostaje nasz. Użycie bez modyfikacji jest bezpieczne. Wersja 0.x. Alternatywa: własna tabela `jobs` + `SELECT … FOR UPDATE SKIP LOCKED` (plan z WYMAGANIA.md, zero zależności). **Rekomendacja na hackathon: SKIP LOCKED.** |
| Rate limiting | **golang.org/x/time/rate** | BSD-3-Clause | v0.16.0 (2026-08-19) | Token bucket: globalny i per podsieć/host. |
| Szyfrowanie | **crypto/aes + crypto/cipher (GCM), stdlib** | BSD-3 | n/d | AES-256-GCM, losowy nonce 12 B, klucz z env/pliku. Pole `bytea` = nonce‖ciphertext. Wersjonowanie klucza (`key_id`) ułatwi rotację. Alternatywa z planu: `pgcrypto` (rozszerzenie contrib PostgreSQL), ale wtedy klucz trafia do zapytań SQL i potencjalnie do logów PG (**niezweryfikowane**, warto sprawdzić `log_statement`). |
| Szyfrowanie (alt.) | tink-crypto/tink-go | Apache-2.0 | v2.9.0 (2026-10-16) | Keysety i rotacja. Na hackathon to przesada. |
| Hasła | **golang.org/x/crypto/argon2** (lub `bcrypt`) | BSD-3-Clause | x/crypto v0.59.0 (2026-11-11) | argon2id albo bcrypt (bcrypt prostszy: `GenerateFromPassword`/`CompareHashAndPassword`). |
| CSRF | **net/http.CrossOriginProtection (stdlib, Go 1.25+)** | BSD-3 | od go1.25.0 | „rejecting non-safe cross-origin browser requests”, na podstawie `Sec-Fetch-Site` lub porównania `Origin` z `Host` (<https://pkg.go.dev/net/http#CrossOriginProtection>). Zero zależności. **Rekomendowane** razem z ciasteczkiem sesyjnym `SameSite=Lax`. |
| CSRF (alt.) | justinas/nosurf | MIT | v1.2.0 (2025-05-13) | CVE-2025-46721 załatana w 1.2.0 (GHSA-w9hf-35q4-vcjw). OK w wersji ≥1.2.0. |
| CSRF (odradzane) | gorilla/csrf | BSD-3-Clause | v1.7.3 (2025-04-14) | **GHSA-82ff-hg59-8x73 / CVE-2025-47909** („improperly validates TrustedOrigins”): podatne `<= 1.7.3`, **brak wersji z poprawką** (GitHub Advisory DB). |
| Wykresy | **Apache ECharts** (<https://github.com/apache/echarts>) | Apache-2.0 | 6.1.0 (2026-05-19) | Bogatsze (heatmapa por dnia, graf). |
| Wykresy (alt.) | **Chart.js** (<https://github.com/chartjs/Chart.js>) | MIT | v4.6.1 (2026-10-22) | Prostszy. Wystarcza do trendów i słupków. Oba ładujemy lokalnie (vendoring), bez CDN w sieci uczelni. |

---

## 7. Podsumowanie

### 7.1. Rekomendowany stos

| Komponent | Biblioteka / narzędzie | Licencja | Dlaczego |
|---|---|---|---|
| Parsowanie celów, CIDR | `net/netip` (+ opcjonalnie `projectdiscovery/mapcidr`) | BSD-3 / MIT | Zero zależności. mapcidr ma gotowy slicing i shuffle. |
| Host discovery | **własny TCP connect** (`net.Dialer`) + **ICMP `udp4`** (`prometheus-community/pro-bing` lub `golang.org/x/net/icmp`) | BSD-3 / Apache-2.0 | Bez roota, bez cgo. Działa w domyślnym Dockerze (`ping_group_range`). |
| Skan portów | własny TCP connect (ten sam silnik) | (nasz kod) | Pełna kontrola tempa, brak ograniczeń NPSL. |
| Wykrywanie usług | **nerva** (biblioteka) i/lub opcjonalny **nmap -sT -sV** przez `Ullaakut/nmap/v4` | Apache-2.0 / NPSL (zewnętrzny, niedystrybuowany) + MIT | nerva jest permisywna i utrzymywana. nmap tylko jako backend do włączenia. |
| HTTP fingerprint | `net/http` (GET/HEAD, `CheckRedirect`, limit body) | BSD-3 | Gwarancja „bez eksploitacji”. |
| TLS / certyfikaty | `crypto/tls`, `crypto/x509` | BSD-3 | Wszystkie pola certyfikatu. Weryfikacja łańcucha osobno. |
| Favicon hash | `twmb/murmur3` + algorytm z httpx (base64 z `\n` co 76 znaków i na końcu, int32) | BSD-3 | Zgodność z hashami Shodana i nuclei. |
| JARM (P3) | `hdm/jarm-go` | BSD-3 | Permisywne. Archiwum, ale stabilne. |
| Technologie / CMS | **własne sygnatury YAML** (format inspirowany nuclei-templates, MIT); wappalyzergo opcjonalnie | (nasz) / MIT kod + dane GPL-3.0 | Unikamy niejasności licencyjnej danych Wappalyzera. |
| DNS | `net.Resolver` (stdlib); w razie potrzeby `codeberg.org/miekg/dns` | BSD-3 | PTR i A wystarczą. |
| DefectDojo | własny klient multipart → `/api/v2/reimport-scan/`, `scan_type=Generic Findings Import` (+ opcjonalnie `Naabu Scan`/`httpx Scan`) | (nasz) | Reimport sam zamyka zniknięte znaleziska. |
| Baza | `pgx/v5` + `goose/v3` + `sqlc` | MIT | Standard Go + PG. |
| Kolejka zadań | tabela `jobs` + `FOR UPDATE SKIP LOCKED` (alt. `river`, MPL-2.0) | (nasz) / MPL-2.0 | Zero zależności. |
| Scheduler | `go-co-op/gocron/v2` | MIT | Utrzymywany. Okna czasowe przez `context.WithDeadline`. |
| Rate limiting | `golang.org/x/time/rate` | BSD-3 | Token bucket. |
| HTTP / UI | `chi/v5` + `templ` + `htmx` (przypięte v2 lub v4) | MIT / MIT / 0BSD | Szybkie SSR bez SPA. |
| RBAC | własna tabela uprawnień + middleware (alt. Apache Casbin v3) | (nasz) / Apache-2.0 | 4 role to mało, żeby uzasadnić Casbina. |
| Szyfrowanie at rest | AES-256-GCM (stdlib) | BSD-3 | Klucz poza bazą. Gotowe pod KMS. |
| Hasła | `x/crypto/bcrypt` lub `argon2` | BSD-3 | Standard. |
| CSRF | `http.CrossOriginProtection` (Go 1.25+) | BSD-3 | Stdlib, bez znanych CVE. |
| Wykresy | Apache ECharts lub Chart.js | Apache-2.0 / MIT | Permisywne, lokalne pliki JS. |

### 7.2. Czego nie używać

| Co | Powód | Źródło |
|---|---|---|
| **masscan** | **AGPL-3.0** + root + libpcap. Ostatni release 2021. | LICENSE w repo, release 1.3.2 |
| **RustScan** | **GPL-3.0**, Rust. I tak deleguje do nmapa. | LICENSE w repo |
| **zmap** (w naszym przypadku) | Licencja OK (Apache-2.0), ale wymaga roota („requires root privileges”). Projektowany pod Internet-scale. | README |
| **naabu jako biblioteka** | cgo + libpcap w buildzie nawet dla trybu connect. Raw/host discovery tylko z `CAP_NET_RAW`/root. Ogromne drzewo zależności. | README, `pkg/scan/*.go`, `pkg/privileges` |
| **Nmap wbudowany i dystrybuowany z produktem / czytanie `nmap-service-probes`** | NPSL 0.95, sekcja 3: wrapper „designed specifically to execute… and parse the results” to utwór zależny, a dystrybucja wymaga licencji NPSL dla całości. Kłóci się z przeniesieniem praw i ewentualną komercjalizacją przez AGH. Dopuszczalne: opcjonalny backend instalowany przez użytkownika i import XML. | `LICENSE` w nmap/nmap, <https://nmap.org/npsl/> |
| **lair-framework/go-nmap** | Porzucone (ostatni commit 2019). | GitHub API |
| **go-ping/ping** | „Deprecated… no longer maintained”, zastąpione przez pro-bing. | README |
| **praetorian-inc/fingerprintx** | Repo zarchiwizowane. Zamiast niego nerva (oficjalny, utrzymywany fork). | GitHub API, README nervy |
| **hdm/jarm-go** jako zależność krytyczna | Zarchiwizowane. Tylko do opcjonalnego JARM. | README |
| **wappalyzergo jako jedyne źródło detekcji** | Dane fingerprintów z repozytoriów GPL-3.0. Ryzyko licencyjne przy przeniesieniu praw. | `cmd/update-fingerprints/main.go`, LICENSE enthec/HTTPArchive |
| **silnik nuclei** (jako biblioteka) | Ogromne zależności. Szablony „info” nie gwarantują samych GET bez payloadów, a wymóg „bez eksploitacji” wymaga ręcznej kuracji. Format szablonów (MIT) jest wart wzięcia jako inspiracja. | lib/README.md, go.mod |
| **robfig/cron** | Ostatni release 2020, ostatni commit 2021. | proxy.golang.org, GitHub API |
| **gorilla/csrf** | CVE-2025-47909: podatne `<= 1.7.3`, brak poprawki. | GitHub Advisory GHSA-82ff-hg59-8x73 |
| **DefectDojo/godojo** | GPL-3.0 i to instalator, nie klient API. | GitHub API |
| **tlsx w trybie `openssl`** | Zależność od zewnętrznej binarki. `ztls` nie obsługuje TLS 1.3. Wystarczy stdlib. | README tlsx |
| **miekg/dns v1 w nowym kodzie** | Repo w trybie utrzymania, „will be archived”. Jeśli potrzebne, to v2 z Codeberga. Najczęściej wystarczy stdlib. | README |
