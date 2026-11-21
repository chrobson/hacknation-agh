# Attack Surface Intelligence

System do cyklicznego, bezpiecznego skanowania rozległych sieci: wykrywanie hostów i usług, fingerprinting HTTP/TLS i technologii, własne sygnatury, porównywanie przebiegów skanu, RBAC, szyfrowanie danych w spoczynku (Percona pg_tde) i eksport do DefectDojo.

Jedno binarium `asi` w Go, PostgreSQL z pg_tde, interfejs WWW renderowany po stronie serwera (htmx). Architektura: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Szybki start

Wymagania: Docker z Compose v2, `make`, `openssl`.

```sh
make env                 # .env z losowym hasłem bazy, kluczem AES i hasłami 4 użytkowników (gitignored)
make up                  # baza z pg_tde + aplikacja na http://127.0.0.1:8080
grep ASI_SEED_PASSWORD .env   # hasła użytkowników admin / editor / analyst / viewer
```

Skanowanie laboratorium testowego (sieć dockerowa `10.20.0.0/18`, 30 hostów, 3 warianty):

```sh
lab/change.sh run1       # laboratorium w wariancie run1
make up-lab              # aplikacja dołączona do sieci laboratorium (nmap w kontenerze, -sS)
```

Następnie w przeglądarce: **Cele** → dodaj `10.20.0.0/18` i `staging.lab.local`, **Skany** → „Skanuj teraz”.
Kolejne warianty (`lab/change.sh run2`, `run3`) pokazują nowe, znikające i zmienione usługi oraz host niestabilny.

Testy:

```sh
make test                # go vet + go test -race
make e2e-smoke           # laboratorium run1: import, skan, asi verify (precision/recall)
make e2e                 # run1 → run2 → run3, zmiany, host niestabilny, RBAC, DefectDojo, pg_tde
make e2e-agh             # szablon AGH na localhost: znikająca i powracająca usługa (niżej)
```

## Skanowanie usług na tym hoście (localhost)

Usługi opublikowane przez Dockera na hoście (`ports: "8787:80"`) są widoczne pod `127.0.0.1` hosta. Domyślna allowlista obejmuje `127.0.0.0/8` i `::1`, więc cel `localhost` (lub `127.0.0.1`) przechodzi import. Jawne `ASI_ALLOWED_CIDRS` w `.env` zastępuje domyślną listę, więc `.env` z wcześniejszej wersji musi dostać `127.0.0.0/8,::1/128` (jak w `.env.example`). Aplikacja w zwykłym kontenerze widzi jednak tylko własny loopback, dlatego są trzy tryby:

| Tryb | Uruchomienie | Cel do dodania | Kiedy |
|---|---|---|---|
| sieć hosta | `make up-host` (`compose.yml` + `compose.host.yml`, `network_mode: host`) | `localhost` | Linux; także OrbStack. Docker Desktop tylko od 4.34 z włączonym host networking |
| `host.docker.internal` | `make up-hostgw` (`compose.yml` + `compose.hostgw.yml`) | `host.docker.internal` | Docker Desktop (Mac/Windows), OrbStack, Linux |
| natywnie | `make native` (baza w Dockerze na `127.0.0.1:${ASI_DB_PORT:-55432}`, `bin/asi serve` i `nmap` na hoście) | `localhost` | każdy system z zainstalowanym nmapem |

- W trybie `host.docker.internal` nazwa wskazuje bramę do hosta (Docker Desktop `192.168.65.254`, OrbStack `0.250.250.254`, Linux `172.17.0.1`). `compose.hostgw.yml` ustawia `ASI_ALLOW_HOSTS=host.docker.internal`: aplikacja przy starcie rozwiązuje tę nazwę i dopisuje każdy adres do allowlisty. Na Linuksie przez bramę widać tylko porty opublikowane na `0.0.0.0` (nie na `127.0.0.1`).
- W trybie sieci hosta interfejs nasłuchuje na `127.0.0.1:${ASI_PORT:-8080}` hosta, a baza jest opublikowana na `127.0.0.1:${ASI_DB_PORT:-55432}`.
- Natywnie: `asi scan`, `asi import` itd. wymagają `ASI_DATABASE_URL=postgres://asi:<ASI_DB_PASSWORD>@127.0.0.1:55432/asi?sslmode=disable` (cel `make native` ustawia go sam). Bez uprawnień roota nmap używa skanu connect (`-sT`), co dla loopbacku wystarcza.
- `localhost` rozwiązuje się na `127.0.0.1` i `::1`; oba adresy są skanowane (IPv6 osobnym wywołaniem `nmap -6`).
- IP hosta lub sieć LAN: dopisz je do `ASI_ALLOWED_CIDRS` w `.env`, np. `ASI_ALLOWED_CIDRS=10.20.0.0/18,127.0.0.0/8,::1/128,192.168.1.10/32` (lub `192.168.1.0/24`), albo podaj nazwę w `ASI_ALLOW_HOSTS`, po czym zrestartuj aplikację. Pojedyncze adresy, CIDR i nazwy spoza listy są odrzucane przy imporcie i przed uruchomieniem nmapa.

**Profil portów** (formularz konfiguracji skanu): `automatyczny` (domyślny) skanuje wszystkie porty TCP (`-p-`), gdy cele obejmują łącznie najwyżej `ASI_ALL_PORTS_MAX_ADDRS` adresów (domyślnie 16, czyli `localhost` czy /28), a w przeciwnym razie najpopularniejsze porty z dodatkowym przebiegiem; `najpopularniejsze + dodatkowe` (top N, typowe porty infrastruktury i własna lista dodatkowych portów, np. `3001,8787,15432`); `własna lista`; `wszystkie` (`-p-`). Usługi Dockera często siedzą poza top 1000 (8787, 15432, 15673, 3001, 2223), dlatego dla małych celów domyślnie skanowane są wszystkie porty. `ASI_SCAN_PORTS` nadal ogranicza każdy profil.

Test end-to-end na szablonie labu AGH (`docker-compose-custom-network.yml`: httpbin 8888, PostgreSQL 15432, RabbitMQ 5673/15673, Gitea 3001/2223, nginx 8787). Pliki szablonu nie są częścią repozytorium; `ASI_AGH_LAB_DIR` wskazuje katalog z nimi (domyślnie `notes/lab-agh`):

```sh
ASI_AGH_LAB_DIR=/ścieżka/do/lab-agh make e2e-agh                     # tryb domyślny: hostgw (macOS), host (Linux)
ASI_AGH_LAB_DIR=/ścieżka/do/lab-agh E2E_AGH_MODE=native ./scripts/e2e.sh agh-template
```

Skrypt uruchamia stack szablonu, skanuje host (profil automatyczny, `-p-`), zatrzymuje usługę na 8787, skanuje ponownie, przywraca ją i skanuje trzeci raz. Sprawdza, że porty szablonu są wykryte w każdym przebiegu, że 8787 znika w drugim (zmiana `gone`) i wraca w trzecim (zmiana `new`), po czym usuwa stack szablonu (`E2E_KEEP=1` zostawia aplikację).

## Polecenia

| Polecenie | Opis |
|---|---|
| `asi serve` | migracje, użytkownicy startowi, interfejs WWW, harmonogram skanów |
| `asi migrate` | tylko migracje |
| `asi scan [konfiguracja]` | skan synchroniczny z postępem (domyślnie konfiguracja „Wszystkie cele”) |
| `asi import <plik>` | cele CSV/JSON, XML nmapa albo DefectDojo Generic Findings JSON (format rozpoznawany automatycznie) |
| `asi export dojo\|csv\|json [przebieg]` | eksport wyników na stdout |
| `asi verify lab/expected/runN.json [-run N] [-min 0.9]` | porównanie przebiegu z wzorcem laboratorium |
| `asi validate-dojo <plik>` | walidacja pliku Generic Findings offline |

## Role

| Rola | Uprawnienia |
|---|---|
| Administracja | wszystko, w tym użytkownicy, role i dziennik zdarzeń |
| Dodawanie, usuwanie, modyfikacja | cele, skany, adnotacje, sygnatury, eksport |
| Modyfikacja i odczyt | odczyt, adnotacje, eksport |
| Odczyt | odczyt celów i wyników |

Administrator tworzy własne role (checkboxy uprawnień) w **Administracja → Role**.

## Bezpieczeństwo skanowania

- Allowlista sieci `ASI_ALLOWED_CIDRS` sprawdzana przy imporcie celów, przy imporcie wyników i ponownie tuż przed uruchomieniem nmapa. `ASI_SCAN_EXCLUDE` to adresy zawsze pomijane.
- Porty: profil konfiguracji skanu (automatyczny, najpopularniejsze + dodatkowe, własna lista `22,80,8000-8100`, wszystkie `-p-`; zob. wyżej). `ASI_SCAN_PORTS` ogranicza wszystkie skany do listy dozwolonych portów.
- Tempo: `max_rate` pakietów/s na cały skan (1 do `ASI_MAX_RATE`, domyślnie 5000), dzielone równo między wątki. Fingerprinting HTTP jest ograniczony do 20 żądań/s, tylko GET/HEAD, bez prób logowania. Timeout pojedynczego żądania HTTP to `ASI_HTTP_TIMEOUT` (domyślnie `10s`, wystarcza przy opóźnieniu 500 ms+, limitach przepustowości i `slow_close`), a `ASI_HTTP_RETRIES` (domyślnie 1, 0–3) ponawia żądanie po przekroczeniu czasu lub zerwanym połączeniu. Czas odpowiedzi każdej usługi HTTP jest zapisywany i widoczny w wynikach; zmiana o więcej niż max(300 ms, 2×) między przebiegami trafia do diffu.
- Okna czasowe i częstotliwość w konfiguracji skanu: skan przerwany na końcu okna wraca do kolejki i jest wznawiany w następnym oknie. Czas lokalny kontenera ustawia `ASI_TZ` (domyślnie Europe/Warsaw).
- „Zatrzymaj” zatrzymuje przebieg na stałe. Harmonogram wznowi go dopiero po kliknięciu „Wznów”.
- Logowanie: po 5 nieudanych próbach w ciągu 15 minut (na login albo adres) kolejne próby dostają 429.

## DefectDojo

Eksport Generic Findings: strona **Eksport** lub `asi export dojo`. Import (strona **Import**, uprawnienie `scans.run`) porównuje plik z ostatnim skanem tylko na hostach z pliku. Lokalna instancja: `make dojo-up` (szczegóły w [`deploy/defectdojo/README.md`](deploy/defectdojo/README.md)); wysyłka z aplikacji wymaga `ASI_DOJO_URL`, `ASI_DOJO_PUSH=true` i `ASI_DOJO_TOKEN` (albo `ASI_DOJO_USER`/`ASI_DOJO_PASSWORD`).

## Licencje komponentów

nmap (NPSL, instalowany z dystrybucji w obrazie budowanym lokalnie), htmx 2.0.4 (0BSD, `web/static/htmx.LICENSE`), chi, pgx, x/crypto, x/time, yaml.v3 (MIT/BSD/Apache-2.0), Percona Distribution for PostgreSQL z pg_tde (PostgreSQL License).
