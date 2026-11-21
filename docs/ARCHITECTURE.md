# Architektura: Attack Surface Intelligence

Jedno binarium `asi` (`migrate | serve | scan | verify | import | export`) w Go 1.26, PostgreSQL z Percona **pg_tde** (szyfrowanie całej bazy w spoczynku), interfejs WWW renderowany po stronie serwera (`html/template` + htmx).

## Moduły i odpowiedzialność

| Pakiet | Zakres | Interfejs |
|---|---|---|
| `internal/target` | parsowanie IP/CIDR/domen, deduplikacja, podział na chunki, **allowlista** | `Allowlist` |
| `internal/scan` + `internal/runner` | nmap: faza 1 `-sn`, faza 2 usługi z wersjami; pula workerów, `--max-rate R/K`, okna czasowe przez `context` z deadline; kolejka chunków `FOR UPDATE SKIP LOCKED` | `scan.Scanner` |
| `internal/httpfp` | GET/HEAD, ≤5 przekierowań, body ≤2 MB, tytuł, nagłówki, ciasteczka, certyfikat TLS (expired/self-signed/mismatch), favicon mmh3, czas odpowiedzi (`http_obs.response_ms`); timeout `ASI_HTTP_TIMEOUT` (10 s) i `ASI_HTTP_RETRIES` (1) ponowienie po timeoucie lub zerwanym połączeniu | `httpfp.Prober` |
| `internal/sig` | sygnatury YAML (tylko GET/HEAD, ≤3 ścieżki, bez body i nagłówków auth); opcjonalnie `severity`, `outdated` (`below`, `severity`: wyższy poziom dla starszej wersji), `negate` i `version_only` (ścieżka odpytywana tylko po trafieniu, żeby odczytać wersję) | `sig.Matcher` |
| `internal/diff` | porównanie przebiegów po kluczu naturalnym, stany hostów up/down/inactive/unstable; zmiana czasu odpowiedzi HTTP o więcej niż max(300 ms, 2×) jako `changed` z polem `response_ms` | `diff.Compare` (czysta funkcja) |
| `internal/auth` | sesje, bcrypt, RBAC (`Require(perm)` → 403), CSRF: `http.CrossOriginProtection` + `SameSite=Lax`, AES-GCM dla tabeli `secrets` | |
| `internal/dojo`, `internal/export` | DefectDojo Generic Findings JSON (eksport i import), CSV, import XML nmapa | `dojo.Codec` |
| `internal/web` | routing chi; każdy moduł udostępnia `Mount(r, Deps)`; szablony dziedziczą z `web/templates/base.html` | `web.Mounter` |
| `internal/app` | integracja: potok po skanie (fingerprinting HTTP/TLS → sygnatury → `diff.ApplyRun`), router ze wszystkimi modułami, pulpit, strony skanów i wyników, `asi verify` | |
| `web/` (`webassets`) | szablony i pliki statyczne osadzone w binarium (`Templates`, `Static`); wspólna nawigacja ładowana z `/nav` i filtrowana uprawnieniami | |
| `internal/db`, `migrations/` | pula pgx, migracje osadzone (`embed`) zapisywane w `schema_migrations` | |

## Kontrakt danych

- **Klucz naturalny usługi** `model.AssetKey{IP, Port, Proto, VHost}`. Służy do diffu, adnotacji (przetrwają kolejne skany) i do `unique_id_from_tool` w DefectDojo.
- **Schemat**: `migrations/0001_init.sql` (zamrożony). Migracje modułów mają zakresy: 0100 targets, 0200 scan, 0300 fingerprint, 0400 diff, 0500 auth, 0600 dojo/export, 0700 hardening, 0810 czas odpowiedzi HTTP.
- **Uprawnienia**: `targets.read`, `targets.write`, `scans.run`, `results.read`, `results.edit`, `signatures.write`, `export`, `users.admin`. Wbudowane role:

| Rola | Uprawnienia |
|---|---|
| Administracja | wszystkie |
| Dodawanie, usuwanie, modyfikacja | wszystkie poza `users.admin` |
| Modyfikacja i odczyt | `targets.read`, `results.read`, `results.edit`, `export` |
| Odczyt | `targets.read`, `results.read` |

  Administrator tworzy nowe role w interfejsie (checkboxy uprawnień).
- **Host niestabilny/nieaktywny** (konfigurowalne): `inactive` po `ASI_INACTIVE_AFTER_MISSES=3` kolejnych brakach odpowiedzi; `unstable`, gdy w ostatnich `ASI_UNSTABLE_WINDOW=5` przebiegach stan zmienił się co najmniej `ASI_UNSTABLE_IF_FLIPS=2` razy.

## Formaty wymiany (`testdata/`)

- **Import celów**: CSV `value,tags` (tagi rozdzielone `;`) lub JSON `[{"value","tags":[]}]`. Raport: `{"imported","duplicates","errors":[{"line","value","error"}]}`.
- **DefectDojo Generic Findings**: `{"findings":[{"title","severity","description","date","unique_id_from_tool","vuln_id_from_tool","endpoints":[{"host","port","protocol"}],"tags"}]}`.
  - `unique_id_from_tool`: `asi:svc:<ip>:<port>/<proto>` lub `asi:sig:<ip>:<port>:<sig_id>`, unikalne w pliku. Gdy usługa ma wirtualny host, dochodzi sufiks `@<vhost>` (`asi:svc:<ip>:<port>/<proto>@<vhost>`, `asi:sig:<ip>:<port>:<sig_id>@<vhost>`), żeby dwa vhosty na jednym porcie miały różne identyfikatory.
  - `endpoints[].protocol`: schemat URL dla typowych portów WWW (80/8000/8008/8080/8888 `http`, 443/8443/9443 `https`), w pozostałych przypadkach `tcp`/`udp`.
  - **Tytuły deterministyczne** (bez czasu i numeru przebiegu): DefectDojo deduplikuje po hashu z tytułu, severity i endpointów.
  - Usługi mają `Info`, panele administracyjne i środowiska staging `Medium`. Sygnatura może nadpisać poziom polem `severity` (zapisywanym w dowodzie detekcji), np. `High` dla dashboardu Traefika z `api.insecure`, API Toxiproxy, DVWA i Redisa bez hasła, `Medium` dla PostgreSQL/MySQL dostępnych z sieci, `Low` dla FTP i httpbin. Wersja starsza niż `outdated.below` (WordPress < 6.0, vsftpd < 3.0, MySQL < 8.0) podnosi poziom do `High`, a tytuł brzmi `Outdated software detected: <nazwa> <wersja>`.
- **Wzorzec labu** `lab/expected/runN.json` i wynik `asi verify` z precision/recall dla hostów, usług, detekcji i zmian:
  `{"run_id","prev_run_id","expected","duration_ms","hosts":{…},"services":{…},"detections":{…},"changes":{…},"min_score","pass","failures"}`,
  gdzie każda metryka to `{"expected","found","tp","fp","fn","precision","recall","recall_top1000","missing","unexpected"}`.
  `recall_top1000` pomija pozycje na portach spoza top 1000 nmapa. Adresy infrastruktury z `infra` są ignorowane, a nazwy detekcji z wzorca są mapowane na identyfikatory sygnatur (`staging-vhost` → `staging-env`, `login-panel` → `login-page`, `mqtt-anonymous` → `mosquitto-mqtt`, `ip-camera`/`router-login` → `iot-webui`). Detekcje sygnatur spoza słownika labu nie wpływają na precision. `pass` wymaga precision i recall hostów, precision usług, `services.recall_top1000` oraz (od drugiego przebiegu) `changes.recall_top1000` ≥ `-min`.

## Przepływ skanu

1. Cele (IP, CIDR, domeny) → allowlista → podział na chunki /24 w kolejce `scan_chunks`. Rozmiar jest stały, bo chunki powstają w bazie przy tworzeniu przebiegu (wznawianie po oknie i po restarcie liczy się w chunkach). /24 daje 64 chunki na /18, więc K wątków równoważy obciążenie, a pojedynczy chunk z `-sV` mieści się w kilkudziesięciu sekundach przy 250 pps na wątek. Adaptacyjny `target.Sizer`/`Cutter` (EWMA czasu na adres) jest gotowy, ale nie jest jeszcze podpięty do runnera.
2. K wątków pobiera chunki (`FOR UPDATE SKIP LOCKED`), każdy z tempem `max_rate/K` (`max_rate` od 1 do `ASI_MAX_RATE`, domyślnie 5000; nie ma trybu bez limitu): `nmap -sn` (ARP/ICMP/TCP ping), potem `-sS|-sT --top-ports N -sV --version-light` na aktywnych hostach i drugi przebieg po portach spoza top 1000 (MQTT, Redis, Memcached, NATS, MongoDB…). Konfiguracja może podać jawną listę portów (`-p`, wtedy bez drugiego przebiegu), a `ASI_SCAN_PORTS` ogranicza wszystkie skany do dozwolonych portów. Koniec okna przerywa chunk i zwraca go do kolejki. „Zatrzymaj” oznacza przebieg jako zatrzymany: harmonogram go nie wznawia, dopóki użytkownik nie kliknie „Wznów”.
3. Po zakończeniu przebiegu: sondowanie HTTP/HTTPS każdej usługi webowej (także jako vhost dla domen z listy celów), dopasowanie sygnatur, zapis `http_obs`/`detections`, porównanie z poprzednim przebiegiem (`changes`, `host_state`).
4. Import XML nmapa lub Generic Findings (uprawnienie `scans.run`) tworzy przebieg `import`. Hosty spoza `ASI_ALLOWED_CIDRS` są odrzucane. Import porównuje się z ostatnim skanem tylko na hostach z pliku, pomijając pola, których format nie niesie. Import nigdy nie jest punktem odniesienia dla kolejnego skanu ani domyślnym przebiegiem pulpitu, wyników i eksportu.

## Bezpieczeństwo

- **Allowlista sieci** (`ASI_ALLOWED_CIDRS`) sprawdzana przy imporcie celów i ponownie tuż przed uruchomieniem skanera.
- **Szyfrowanie w spoczynku**: pg_tde (AES-256) dla tabel, indeksów, TOAST, sekwencji i WAL.
  - Logowanie treści zapytań wyłączone, `work_mem` ograniczający pliki tymczasowe.
  - `SET STATISTICS 0` dla wszystkich kolumn tekstowych, JSON i adresowych (migracja 0700 czyści też zebrane już próbki), bo `pg_statistic` nie jest szyfrowane.
  - Ograniczenia: nazwy tabel w katalogu systemowym, lokalny keyring. W produkcji klucz w OpenBao/KMIP.
- **Sekrety aplikacji** (token DefectDojo): AES-GCM kluczem `ASI_SECRET_KEY`.
- **DefectDojo push** domyślnie wyłączony.
- **Logowanie**: po 5 nieudanych próbach w ciągu 15 min dla loginu lub adresu kolejne próby dostają 429. Adres klienta to adres połączenia (bez `X-Forwarded-For`).
