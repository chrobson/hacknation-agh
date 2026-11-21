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
```

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
- Porty: domyślnie top N portów TCP plus przebieg po typowych portach infrastruktury. Konfiguracja skanu może podać jawną listę (`22,80,8000-8100`), a `ASI_SCAN_PORTS` ogranicza wszystkie skany do listy dozwolonych portów.
- Tempo: `max_rate` pakietów/s na cały skan (1 do `ASI_MAX_RATE`, domyślnie 5000), dzielone równo między wątki. Fingerprinting HTTP jest ograniczony do 20 żądań/s, tylko GET/HEAD, bez prób logowania. Timeout pojedynczego żądania HTTP to `ASI_HTTP_TIMEOUT` (domyślnie `10s`, wystarcza przy opóźnieniu 500 ms+, limitach przepustowości i `slow_close`), a `ASI_HTTP_RETRIES` (domyślnie 1, 0–3) ponawia żądanie po przekroczeniu czasu lub zerwanym połączeniu. Czas odpowiedzi każdej usługi HTTP jest zapisywany i widoczny w wynikach; zmiana o więcej niż max(300 ms, 2×) między przebiegami trafia do diffu.
- Okna czasowe i częstotliwość w konfiguracji skanu: skan przerwany na końcu okna wraca do kolejki i jest wznawiany w następnym oknie. Czas lokalny kontenera ustawia `ASI_TZ` (domyślnie Europe/Warsaw).
- „Zatrzymaj” zatrzymuje przebieg na stałe. Harmonogram wznowi go dopiero po kliknięciu „Wznów”.
- Logowanie: po 5 nieudanych próbach w ciągu 15 minut (na login albo adres) kolejne próby dostają 429.

## DefectDojo

Eksport Generic Findings: strona **Eksport** lub `asi export dojo`. Import (strona **Import**, uprawnienie `scans.run`) porównuje plik z ostatnim skanem tylko na hostach z pliku. Lokalna instancja: `make dojo-up` (szczegóły w [`deploy/defectdojo/README.md`](deploy/defectdojo/README.md)); wysyłka z aplikacji wymaga `ASI_DOJO_URL`, `ASI_DOJO_PUSH=true` i `ASI_DOJO_TOKEN` (albo `ASI_DOJO_USER`/`ASI_DOJO_PASSWORD`).

## Licencje komponentów

nmap (NPSL, instalowany z dystrybucji w obrazie budowanym lokalnie), htmx 2.0.4 (0BSD, `web/static/htmx.LICENSE`), chi, pgx, x/crypto, x/time, yaml.v3 (MIT/BSD/Apache-2.0), Percona Distribution for PostgreSQL z pg_tde (PostgreSQL License).
