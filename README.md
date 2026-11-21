# Attack Surface Intelligence

[![e2e-agh](https://github.com/chrobson/hacknation-agh/actions/workflows/e2e-agh.yml/badge.svg)](https://github.com/chrobson/hacknation-agh/actions/workflows/e2e-agh.yml)

## 1. Co to jest

System do cyklicznego, bezpiecznego skanowania sieci: wykrywa aktywne hosty i usługi (nmap), robi fingerprinting HTTP/TLS, rozpoznaje technologie, panele administracyjne i środowiska testowe własnymi sygnaturami YAML (wyłącznie GET/HEAD), porównuje kolejne przebiegi skanu i oznacza nowe, znikające, zmienione i niestabilne usługi. Wyniki trafiają do PostgreSQL zaszyfrowanego w całości (Percona pg_tde), dostęp kontroluje RBAC z czterema rolami i rolami tworzonymi przez administratora, a eksport i import używają formatu DefectDojo Generic Findings, także z wysyłką do DefectDojo przez API v2. Całość to jedno binarium `asi` w Go z interfejsem WWW renderowanym po stronie serwera (htmx), uruchamiane przez Docker Compose.

## 2. Szybki start

Wymagania: Docker z pluginem Compose v2 (polecenie `docker compose`), `make`, `openssl`. Pliki Compose nie używają znaczników `!reset`/`!override`, więc nie wymagają Compose 2.24+ (sprawdzone na żywo: Docker Compose 5.5.0 z OrbStack; starszych wersji nie uruchamiano). Tryb natywny wymaga też Go 1.26+ i nmapa na hoście. `make doctor` sprawdza środowisko (Docker i dostęp do demona, Compose v2, `openssl`, wolne porty `ASI_PORT`/`ASI_DB_PORT`) i wskazuje, co poprawić; każde `make up…` uruchamia je samo.

```sh
git clone https://github.com/chrobson/hacknation-agh.git && cd hacknation-agh
make env                        # .env z losowym hasłem bazy, kluczem AES i hasłami 4 użytkowników (gitignored)
grep ASI_SEED_PASSWORD .env     # hasła użytkowników
```

Następnie uruchom aplikację w trybie z sekcji 2a (lab AGH na localhost) albo 2b (własny lab /18). Samo `make up` też startuje bazę i aplikację, ale ze zwykłego kontenera nie widać ani usług hosta, ani sieci labu.

Interfejs po starcie: **http://127.0.0.1:9080** (port zmienia `ASI_PORT` w `.env`; 9080, żeby nie kolidować z usługami labu na 8080).

**Użytkownicy startowi** są tworzeni przy pierwszym starcie na pustej bazie, z hasłami z `.env` (`make env` losuje je do `ASI_SEED_PASSWORD_*`; puste pole oznacza hasło losowe wypisane raz w logu aplikacji, `docker compose logs app`). Zmiana `.env` później nie zmienia haseł istniejących kont.

| Login | Rola | Hasło |
|---|---|---|
| `admin` | Administracja | `ASI_SEED_PASSWORD_ADMIN` |
| `editor` | Dodawanie, usuwanie, modyfikacja | `ASI_SEED_PASSWORD_EDITOR` |
| `analyst` | Modyfikacja i odczyt | `ASI_SEED_PASSWORD_ANALYST` |
| `viewer` | Odczyt | `ASI_SEED_PASSWORD_VIEWER` |

### 2a. Lab AGH na localhost (usługi z `ports:` opublikowane na tym hoście)

Najpierw uruchom stack labu, np. `docker compose -f docker-compose-custom-network.yml up -d`. Aplikacja w zwykłym kontenerze widzi tylko własny loopback, więc wybierz jeden z trzech trybów:

| System | Uruchomienie | Cel skanu |
|---|---|---|
| **Linux** (zalecany) | `make up-host`: aplikacja w sieci hosta (`network_mode: host`) | `localhost` |
| **Docker Desktop (Mac/Windows), OrbStack** | `make up-hostgw`: aplikacja dociera do hosta przez `host.docker.internal` | `host.docker.internal` |
| **dowolny, nmap na hoście** | `make native`: baza w Dockerze, `bin/asi serve` i nmap na hoście (proces na pierwszym planie, Ctrl+C kończy) | `localhost` |

Potem pierwszy skan:

```sh
make seed-demo     # cel (localhost albo host.docker.internal, zależnie od trybu) i konfiguracja skanu "Demo"
```

W przeglądarce: zaloguj się jako `admin` → **Skany** → „Skanuj teraz” przy konfiguracji **Demo**. To samo z wiersza poleceń: `docker compose exec app asi scan Demo` (w trybie natywnym `make native` zajmuje terminal, więc skan uruchom z interfejsu).

Bez `make seed-demo`: **Cele** → wpisz `localhost` (lub `host.docker.internal`) → „Dodaj cele”, potem **Skany** → „Skanuj teraz” przy konfiguracji **Wszystkie cele**. Ta konfiguracja powstaje automatycznie na pustej bazie i obejmuje wszystkie cele (profil portów automatyczny, 1000 pakietów/s). Własną konfigurację (okno czasowe, częstotliwość, tempo, profil portów) dodaje przycisk „Nowa konfiguracja”.

`make seed-demo` jest idempotentne. Inne cele: `SEED_TARGETS="127.0.0.1 192.168.1.10" make seed-demo` (każdy musi przejść allowlistę). Konfiguracja **Demo**: profil portów automatyczny (dla celów do 16 adresów wszystkie porty TCP, `-p-`), 1000 pakietów/s, 4 wątki, uruchamiana ręcznie.

Przebieg ma status „trwa”, potem „przetwarzanie” (sondowanie HTTP, sygnatury, porównanie z poprzednim przebiegiem), a wyniki i zmiany są kompletne przy statusie „zakończony”. Skan `-p-` jednego adresu przy 1000 pakietów/s trwa około 3 minut; `localhost` to dwa adresy (`127.0.0.1` i `::1`), więc około 4 minut.

Scenariusz z szablonu AGH (znikająca i powracająca usługa):

```sh
docker compose -f docker-compose-custom-network.yml stop flask-app    # 8787 znika
# Skanuj teraz → Zmiany: „Zniknięte usługi” z portem 8787
docker compose -f docker-compose-custom-network.yml start flask-app
# Skanuj teraz → Zmiany: „Nowe usługi” i „Niestabilne hosty i usługi” z portem 8787, host pozostaje aktywny
```

Uwagi do trybów:
- **sieć hosta**: `compose.host.yml` to samodzielny plik (nie nakłada się go na `compose.yml`), z tą samą nazwą projektu `asi`, więc `docker compose exec app …`, `make seed-demo` i `make down` działają bez `-f`. Interfejs na `127.0.0.1:9080` hosta, baza na `127.0.0.1:${ASI_DB_PORT:-55432}`. Skan obejmuje też porty samej aplikacji (9080, 55432). Docker Desktop obsługuje sieć hosta tylko od 4.34 po włączeniu tej funkcji; OrbStack obsługuje ją od razu (sprawdzone).
- **`host.docker.internal`**: nazwa wskazuje bramę do hosta (Docker Desktop `192.168.65.254`, OrbStack `0.250.250.254`, Linux `172.17.0.1`). `compose.hostgw.yml` ustawia `ASI_ALLOW_HOSTS=host.docker.internal`, więc aplikacja przy starcie dopisuje ten adres do allowlisty. Na Linuksie przez bramę widać tylko porty opublikowane na `0.0.0.0` (nie na `127.0.0.1`), a zapora (ufw, firewalld) może blokować ruch z mostka Dockera; tam wybierz `make up-host`.
- **dostęp z innej maszyny**: interfejs nasłuchuje domyślnie tylko na `127.0.0.1` hosta (`ASI_BIND=127.0.0.1` w `.env`). Jeśli aplikacja działa na zdalnym serwerze, najprościej użyć tunelu SSH: `ssh -L 9080:127.0.0.1:9080 użytkownik@serwer`, potem http://127.0.0.1:9080 lokalnie. Alternatywnie `ASI_BIND=0.0.0.0` w `.env` i ponowne `make up-…`: interfejs jest wtedy dostępny pod adresem serwera po zwykłym HTTP (ciasteczko sesji dostaje flagę `Secure` tylko przy TLS, więc logowanie działa), a zapora (ufw, firewalld) musi przepuszczać port 9080 tylko z zaufanych adresów. Baza zawsze nasłuchuje wyłącznie na `127.0.0.1`.
- **natywnie**: bez roota nmap używa skanu connect (`-sT`), co dla loopbacku wystarcza. Polecenia CLI wymagają `ASI_DATABASE_URL=postgres://asi:<ASI_DB_PASSWORD>@127.0.0.1:55432/asi?sslmode=disable` (`make native` i `make seed-demo` ustawiają go same).
- **IP hosta lub sieć LAN**: dopisz je do `ASI_ALLOWED_CIDRS` w `.env`, np. `ASI_ALLOWED_CIDRS=10.20.0.0/18,127.0.0.0/8,::1/128,192.168.1.0/24`, i uruchom aplikację ponownie tym samym poleceniem `make up-…`. Jawne `ASI_ALLOWED_CIDRS` zastępuje listę domyślną, więc zostaw w nim `127.0.0.0/8,::1/128`.
- Zmiana trybu: `docker compose down`, potem inne `make up-…`. Baza zostaje; `make seed-demo` przestawia konfigurację **Demo** na cel właściwy dla nowego trybu.

### 2b. Własny lab testowy /18

Repozytorium zawiera lab w Dockerze: sieć `10.20.0.0/18`, 30 hostów (WordPress, phpMyAdmin, Jenkins, Grafana, Tomcat, Gitea, Adminer, HAProxy, vhost staging, „kamera IP” i „router IoT”, SSH, FTP, MQTT, Redis, bazy danych, host niestabilny) w trzech wariantach różniących się usługami. Opis: [`lab/README.md`](lab/README.md).

```sh
lab/change.sh run1                                      # lab w wariancie run1
make up-lab                                             # aplikacja dołączona do sieci labu (nmap -sS w kontenerze)
SEED_TARGETS="10.20.0.0/18 staging.lab.local" make seed-demo
docker compose exec app asi scan Demo                   # albo Skany → „Skanuj teraz”
lab/change.sh run2                                      # zmiana labu, potem kolejny skan; analogicznie run3
docker compose cp lab/expected/run2.json app:/tmp/run2.json
docker compose exec app asi verify /tmp/run2.json      # precision/recall ostatniego przebiegu względem wzorca
```

Skan /18 przy 1000 pakietów/s trwa około 4 minut. Własną sieć skanuje się tak samo: dopisz jej CIDR do `ASI_ALLOWED_CIDRS`, aplikację uruchom w trybie, z którego ta sieć jest osiągalna (`make up-host` na Linuksie widzi wszystko, co widzi host), dodaj cel w **Cele** i uruchom skan.

## 3. Funkcje a wymagania zadania

| Wymaganie | Jak spełnione | Gdzie w UI |
|---|---|---|
| Wczytanie IP, CIDR, domen | formularz (jeden lub wiele wpisów, tagi) oraz plik CSV/JSON; ta sama walidacja, deduplikacja i allowlista; raport błędów per linia | **Cele** |
| Bezpieczny, wielowątkowy skan nmapem, pomiar czasu, podział na podgrupy | cele dzielone na chunki /24 w kolejce w bazie (`FOR UPDATE SKIP LOCKED`), K wątków z tempem `max_rate/K`; czas przebiegu i każdego chunku zapisywany; postęp na żywo | **Skany**, **Pulpit** („Skany w toku”) |
| Aktywne hosty, podstawowe usługi | `nmap -sn`, potem `-sS`/`-sT -sV` (top N + drugi przebieg po typowych portach infrastruktury albo `-p-` dla małych celów); dodatkowe rozpoznanie wersji dla nienazwanych portów | **Wyniki**, **Hosty** |
| HTTP/HTTPS: tytuł, kod, nagłówki, ciasteczka, TLS, przekierowania | sonda GET/HEAD: łańcuch przekierowań, nagłówki, ciasteczka z flagami, certyfikat (wystawca, ważność, self-signed, niezgodność nazwy), favicon mmh3, czas odpowiedzi | **Wyniki** → usługa |
| Technologie: CMS, framework, serwer, IoT | 41 wbudowanych sygnatur YAML (WordPress z wersją, Joomla, Drupal, Jenkins, Grafana, Tomcat, Gitea, RabbitMQ, Traefik, DVWA, Adminer, kamery i routery IoT…) | **Wyniki**, **Pulpit** („Detekcje według kategorii”) |
| Staging i panele administracyjne | sygnatury `staging-env` (vhost, nagłówki, tytuł) i `admin-panel`/`login-page` (`/admin`, `/login`, bez prób logowania); ogólne panele są pomijane, gdy usługę rozpoznała sygnatura produktu (np. Gitea, Jenkins) | **Pulpit** („Panele administracyjne i środowiska testowe”) |
| Porównanie przebiegów; nowe, znikające, zmienione | diff po kluczu (IP, port, protokół, vhost): `new`, `gone`, `changed` (produkt, wersja, tytuł, kod, certyfikat, czas odpowiedzi…) | **Zmiany**, **Pulpit** („Ostatnie zmiany”) |
| Hosty i usługi niestabilne, nieaktywne | jawna, konfigurowalna definicja: `inactive` po 3 kolejnych brakach odpowiedzi, `unstable` po co najmniej 2 zmianach stanu w ostatnich 5 przebiegach (`ASI_INACTIVE_AFTER_MISSES`, `ASI_UNSTABLE_IF_FLIPS`, `ASI_UNSTABLE_WINDOW`) | **Hosty**, **Zmiany** |
| Wizualizacja zmian w czasie, dostępność według pory dnia | wykres zmian w ostatnich 30 przebiegach (słupek na przebieg, linie aktywnych hostów i usług); dostępność hosta i usługi = liczba przebiegów, w których był widoczny, / liczba zakończonych skanów obejmujących jego adres, w rozbiciu na pory dnia 00-06, 06-12, 12-18, 18-24 ze wzorcem „zawsze”, „pora dnia” („odpowiada głównie w godz. 06-18”) lub „nieregularnie”; historia każdego hosta i usługi przebieg po przebiegu | **Zmiany**, **Zmiany** → **Dostępność** |
| Własne sygnatury | edytor YAML z walidacją: nagłówek, ciasteczko, hash favicony, regex HTML, ścieżka GET (≤3), wersja, `severity`, `outdated` | **Sygnatury** |
| RBAC z tworzeniem ról, 4 role z zadania | uprawnienia sprawdzane po stronie serwera (403), role wbudowane i własne (checkboxy uprawnień), dziennik zdarzeń | **Administracja** (użytkownicy, role, dziennik) |
| Edycja wyników zachowywana między skanami | adnotacje (komentarz, tagi, severity, fałszywy alarm) przypięte do klucza usługi, nie do przebiegu | **Adnotacje**, **Wyniki** → usługa, **Zmiany** |
| Dashboard | ostatni przebieg, detekcje, panele i staging, ostatnie zmiany, stany hostów | **Pulpit** |
| Ocena ciekawości i priorytet analityczny | ocena 0–100 liczona przy odczycie jako jawna suma reguł: poziom detekcji × pewność, panel administracyjny, staging, IoT, nieaktualna wersja, odsłonięta baza danych, telnet, API Dockera, problemy TLS, logowanie bez TLS, nowa lub zmieniona usługa; fałszywy alarm zeruje ocenę, poziom analityka ustawia minimum (reguły w [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)) | **Pulpit** („Priorytet analityczny”), **Wyniki** (kolumna i sortowanie), usługa |
| Szyfrowanie w spoczynku | pg_tde dla całej bazy: tabele, indeksy, TOAST, sekwencje, WAL (sekcja 5) | – |
| Okna czasowe, częstotliwość, wznowienie | konfiguracja skanu: okno (także przez północ), co ile minut; chunk przerwany na końcu okna wraca do kolejki i jest kontynuowany w kolejnym oknie | **Skany** → konfiguracja |
| Ograniczanie tempa | `max_rate` pakietów/s na cały przebieg (górny limit `ASI_MAX_RATE`), HTTP ≤20 żądań/s | **Skany** → konfiguracja |
| Import i eksport JSON/CSV | eksport usług CSV/JSON i Generic Findings; import Generic Findings oraz XML nmapa jako przebieg typu `import`; cele CSV/JSON | **Eksport**, **Import**, **Cele** |
| DefectDojo | Generic Findings z deterministycznymi tytułami i `unique_id_from_tool`; wysyłka `import-scan`/`reimport-scan` z `close_old_findings` (sekcja 6) | **Eksport** |
| Tagi, grupowanie | tagi celów (filtr na liście celów) i adnotacji; najczęstsze usługi | **Cele**, **Adnotacje**, **Pulpit** |

## 4. Bezpieczeństwo skanowania

- **Allowlista** `ASI_ALLOWED_CIDRS` (domyślnie lab `10.20.0.0/18`, TEST-NET `192.0.2.0/24`, loopback `127.0.0.0/8` i `::1/128`) sprawdzana przy imporcie celów, przy imporcie wyników i ponownie tuż przed uruchomieniem nmapa. Domeny są rozwiązywane, a każdy adres musi leżeć na liście. `ASI_ALLOW_HOSTS` dopisuje pojedyncze nazwy rozwiązywane przy starcie. `ASI_SCAN_EXCLUDE` to adresy zawsze pomijane.
- **Porty**: profil konfiguracji skanu (automatyczny, najpopularniejsze + dodatkowe, własna lista, wszystkie). `ASI_SCAN_PORTS` ogranicza każdy skan do listy dozwolonych portów.
- **Tempo**: `max_rate` od 1 do `ASI_MAX_RATE` (domyślnie 5000) pakietów/s na cały przebieg, dzielone równo między wątki; nie ma trybu bez limitu. Fingerprinting HTTP: najwyżej 20 żądań/s, timeout `ASI_HTTP_TIMEOUT` (10 s, wystarcza przy opóźnieniu 500 ms+ i `slow_close` z Toxiproxy), jedno ponowienie.
- **Okna czasowe**: skan przerwany na końcu okna wraca do kolejki i jest wznawiany w następnym oknie. „Zatrzymaj” zatrzymuje przebieg na stałe, dopóki użytkownik nie kliknie „Wznów”. Strefa czasowa: `ASI_TZ` (domyślnie Europe/Warsaw).
- **Sygnatury tylko do odczytu**: wyłącznie GET i HEAD, najwyżej 3 ścieżki na sygnaturę, bez body, bez nagłówków uwierzytelniania, bez prób logowania i bez eksploatacji. Walidator odrzuca sygnaturę, która tego nie spełnia.
- **Aplikacja**: hasła bcrypt, sesje w bazie, ochrona CSRF (`CrossOriginProtection` + `SameSite=Lax`), po 5 nieudanych logowaniach w 15 minut odpowiedź 429, interfejs i baza publikowane tylko na `127.0.0.1`.

## 5. Szyfrowanie w spoczynku (pg_tde)

Baza to Percona Distribution for PostgreSQL 18 z rozszerzeniem pg_tde. Przy pierwszej inicjalizacji [`deploy/db/init/01-tde.sql`](deploy/db/init/01-tde.sql) ustawia AES-256, klucz serwera i klucz domyślny, `default_table_access_method = tde_heap`, `pg_tde.enforce_encryption = on` i szyfrowanie WAL. Zaszyfrowane są więc wszystkie tabele, indeksy, TOAST, sekwencje i WAL, a nie tylko wybrane pola. Dodatkowo kolumny tekstowe, JSON i adresowe mają `SET STATISTICS 0` (niezaszyfrowany katalog `pg_statistic` nie dostaje próbek danych), logowanie treści zapytań jest wyłączone, a token DefectDojo w tabeli `secrets` jest dodatkowo szyfrowany AES-GCM kluczem `ASI_SECRET_KEY`.

Dowód na działającej instalacji (tryby `make up-*`):

```sh
docker compose exec db psql -U asi -d asi \
  -c "SELECT count(*) AS tabele, count(*) FILTER (WHERE pg_tde_is_encrypted(c.oid::regclass)) AS zaszyfrowane
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'public' AND c.relkind = 'r'" \
  -c "SHOW pg_tde.wal_encrypt" -c "SHOW default_table_access_method"
# tabele = zaszyfrowane (22 = 22), wal_encrypt = on, tde_heap

# znacznik zapisany w bazie nie występuje w żadnym pliku na dysku (wynik 0):
docker compose exec db psql -U asi -d asi -c "UPDATE targets SET tags = tags || '{tajny-znacznik-7f3a}'" -c CHECKPOINT -c "SELECT pg_switch_wal()"
docker compose exec db sh -c "grep -rlF tajny-znacznik-7f3a /data/db | wc -l"
docker compose exec db psql -U asi -d asi -c "UPDATE targets SET tags = array_remove(tags, 'tajny-znacznik-7f3a')"
```

`make e2e` wykonuje te same sprawdzenia automatycznie.

## 6. DefectDojo

- **Eksport**: **Eksport** → „Pobierz plik DefectDojo (Generic Findings)” albo `docker compose exec app asi export dojo`. Usługi mają severity `Info`, panele administracyjne i staging `Medium`, ryzykowne usługi według sygnatury (np. dashboard Traefika z `api.insecure`, DVWA, Redis bez hasła `High`), przestarzałe wersje (WordPress < 6.0, vsftpd < 3.0, MySQL < 8.0) `High`. Tytuły i opisy są deterministyczne, a `unique_id_from_tool` to `asi:svc:<ip>:<port>/<proto>` i `asi:sig:<ip>:<port>:<sygnatura>`, więc reimport nie tworzy duplikatów. Adnotacje są uwzględniane: fałszywe alarmy są pomijane, a ręcznie zmienione severity trafia do pliku. Walidacja offline: `asi validate-dojo <plik>`.
- **Import**: **Import** (uprawnienie `scans.run`) przyjmuje Generic Findings JSON albo XML nmapa i tworzy przebieg typu `import`. Porównanie z ostatnim skanem dotyczy tylko hostów z pliku, a import nigdy nie staje się punktem odniesienia dla kolejnego skanu.
- **Wysyłka do DefectDojo**: przycisk „Wyślij do DefectDojo” na stronie **Eksport** wykonuje `reimport-scan` z `close_old_findings=true` (przy pierwszej wysyłce test powstaje automatycznie). Domyślnie wyłączona; włączają ją `ASI_DOJO_URL`, `ASI_DOJO_PUSH=true` i `ASI_DOJO_TOKEN` (albo `ASI_DOJO_USER` i `ASI_DOJO_PASSWORD`) w `.env`.
- **Lokalna instancja**: `make dojo-up` uruchamia oficjalny compose DefectDojo 3.5.202 na `http://localhost:8081` (osobny projekt, około 4 GB RAM, pierwszy start kilka minut), hasło administratora: `make dojo-password`. Z kontenera aplikacji instancja jest pod `ASI_DOJO_URL=http://host.docker.internal:8081`, w trybie sieci hosta i natywnym pod `http://localhost:8081`. Jeśli lab zajmuje port 8081 (stack „modern” z phpMyAdmin), zmień `DD_PORT` w `deploy/defectdojo/.env` przed pierwszym `make dojo-up`. Szczegóły: [`deploy/defectdojo/README.md`](deploy/defectdojo/README.md).

Sprawdzone na żywo na lokalnej instancji 3.5.202 (tryb `host.docker.internal`, szablon AGH): pierwsza wysyłka utworzyła 36 aktywnych findingów; po zatrzymaniu `flask-app`, kolejnym skanie i ponownej wysyłce reimport zamknął oba findingi portu 8787 (`active=false`, `is_mitigated=true`), zostawiając 34 aktywne bez duplikatów. Publiczne demo DefectDojo jest współdzielone, więc nie było używane.

## 7. Architektura

Jedno binarium `asi` (`serve`, `scan`, `import`, `export`, `verify`, `seed-demo`, `migrate`, `validate-dojo`) i PostgreSQL z pg_tde w Docker Compose. `serve` udostępnia interfejs WWW (chi, `html/template`, htmx, szablony osadzone w binarium) i uruchamia harmonogram: przebieg skanu dzieli cele na chunki w kolejce w bazie, wątki uruchamiają nmapa z limitem tempa, a po skanie potok wykonuje sondowanie HTTP/TLS, dopasowanie sygnatur i diff z poprzednim przebiegiem. Moduły (`target`, `scan`/`runner`, `httpfp`, `sig`, `diff`, `auth`, `dojo`/`export`, `web`) komunikują się przez bazę i małe interfejsy. Opis modułów, kontraktu danych, przepływu skanu i decyzji: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## 8. Testy i wyniki

```sh
make test          # go vet + go test -race (testy jednostkowe)
make e2e-smoke     # lab /18 run1: import celów, skan, asi verify
make e2e           # lab /18 run1 → run2 → run3: zmiany, host niestabilny, RBAC, DefectDojo, pg_tde
make e2e-agh       # szablon AGH na localhost; pliki szablonu: ASI_AGH_LAB_DIR=/ścieżka/do/lab-agh
```

Testy integracyjne z bazą: `ASI_TEST_DATABASE_URL=postgres://… go test -tags integration ./...`.

**Lab /18** (`make e2e`, 64 chunki /24, 30 hostów, 1000 pakietów/s, 4 wątki, `-sS`): precision i recall 1.0 dla hostów, usług, detekcji i zmian w każdym z trzech przebiegów.

| Przebieg | Czas | Hosty (TP/FP/FN) | Usługi | Detekcje | Zmiany |
|---|---|---|---|---|---|
| run1 | 3 min 54 s | 30/0/0 | 36/0/0 | 19/0/0 | – |
| run2 | 3 min 58 s | 29/0/0 | 35/0/0 | 19/0/0 | 10/0/0 |
| run3 | 3 min 54 s | 30/0/0 | 36/0/0 | 19/0/0 | 5/0/0 |

Ten sam przebieg sprawdza też: host niestabilny po run3, 403 dla roli Odczyt przy POST i dla roli Modyfikacja i odczyt przy imporcie, eksport Generic Findings (77 findingów) z walidacją offline i ponownym importem bez fałszywych zmian, szyfrowanie wszystkich 22 tabel, brak próbek w `pg_statistic` i brak jawnego znacznika na dysku.

**Szablon AGH** (`make e2e-agh`, stack custom-network, profil automatyczny `-p-`): trzy skany hosta, w drugim zatrzymana usługa na 8787. Wynik: porty szablonu (2223, 3001, 5673, 8787, 8888, 15432, 15673) wykryte w każdym przebiegu, w drugim zmiana `gone` dla 8787, w trzecim `new` i `unstable` (flips=2), host pozostaje `up`; `asi verify` trzeciego przebiegu: hosty (1/0/0), detekcje (5/0/0) i zmiany szablonu z precision i recall 1.0. Usługi: 25/1/0 (precision 0,96), a zmiany 2/1/0, bo w trzecim przebiegu na hoście był otwarty dodatkowy port efemeryczny (54114) aplikacji spoza szablonu. Przed poprawką detekcje miały precision 0,71 (5/2/0): strona logowania na Gitei (3001) i na interfejsie samego skanera (18081). Skan jednego adresu `-p-` trwa około 2 min przy 5000 pakietów/s i około 3 min przy 1000 pakietów/s.

Kroki z sekcji 2a zostały wykonane na OrbStack we wszystkich trzech trybach (`make up-hostgw`, `make up-host`, `make native`) z `make seed-demo` i skanem konfiguracji **Demo**: 2 min 52 s dla `host.docker.internal`, około 4 min dla `localhost` (dwa adresy).

## 9. Ograniczenia

- Skanowane są tylko porty TCP; UDP (np. DNS, SNMP) nie jest skanowany.
- Chunki mają stały rozmiar /24. Adaptacyjny dobór rozmiaru (`target.Sizer`) jest zaimplementowany i przetestowany, ale nie jest podpięty do runnera.
- Linux: tryb sieci hosta (`compose.host.yml`, nmap `-sS` jako root w kontenerze, cel `localhost`) jest sprawdzany w GitHub Actions na `ubuntu-24.04` (`.github/workflows/e2e-agh.yml`): `make up-host`, potem `make e2e-agh` (skan, zatrzymanie usługi na 8787, skan, przywrócenie, skan). [Przebieg 44957845776](https://github.com/chrobson/hacknation-agh/actions/runs/44957845776): `asi verify` hosts, services, detections i changes P=1, R=1, dokładnie jedno `gone` dla 8787, wynik `verify_run3.json` w artefakcie `e2e-agh-linux`. Szablonu AGH nie ma w publicznym źródle (licencja nieznana), więc CI używa `ci/agh-custom-network.yml`: te same obrazy na tych samych portach hosta co `docker-compose-custom-network.yml`. Na Linuksie nie były potrzebne żadne poprawki (iptables, uprawnienia nmapa, sieć hosta działają z domyślnymi ustawieniami Dockera). Lokalnie testy wykonywano na macOS z OrbStack; fizycznego hosta z Linuksem poza runnerem CI nie sprawdzano.
- Odporność na awarie: `make e2e-toxi` (`scripts/e2e-toxi.sh`, stos `ci/agh-proxy.yml`: WordPress za Traefikiem za Toxiproxy) dodaje opóźnienie 800 ms ±200 ms, potem toxic `timeout`. Opóźnienie nie daje fałszywych `gone` ani `changed` (tylko zamierzoną zmianę `response_ms`). Przy `timeout` odpowiada sam Traefik (502) i nmap `-sV` rozpoznaje go zamiast Apache, co bez dodatkowej obsługi dałoby 5 wierszy `changed` (product, version, extrainfo, cpe, banner) przy działającym porcie. Diff zamienia je na jeden wiersz `changed` z polem `http_status` (np. `200 -> 502`), gdy status HTTP usługi wchodzi w 502/503/504 albo z niego wychodzi (`internal/diff/gateway.go`). Wynik: 0 fałszywych `gone` i `changed` w dwóch skanach z toxicami, dokładnie jedno `gone` po faktycznym zatrzymaniu Toxiproxy.
- W trybie sieci hosta i natywnym wynik skanu `localhost` zawiera też porty samej aplikacji i inne usługi hosta (np. 9080, 55432, usługi systemowe), bo to faktycznie otwarte porty. Własny interfejs skanera jest rozpoznawany po nagłówku `X-Asi-Instance` i nie dostaje detekcji (strony logowania); inne aplikacje hosta z formularzem logowania (np. lokalny DefectDojo na 8081) są raportowane jak każda inna usługa.
- Klucz pg_tde leży w lokalnym keyringu w wolumenie Dockera na tym samym hoście; produkcyjnie powinien trafić do KMS (OpenBao/Vault, KMIP). Nazwy tabel i kolumn w katalogu systemowym nie są szyfrowane.
- Brak pasywnych źródeł danych (CT logs, DNS).
- Konto użytkownika nie ma zmiany hasła w interfejsie; hasła startowe pochodzą z `.env` przy pierwszym starcie.
- Rozpoznanie wersji zależy od nmapa `-sV` i sygnatur; usługi bez banera (np. httpbin na 8888) mają pusty produkt. Ogólna sygnatura strony logowania jest wyciszana tylko wtedy, gdy na usłudze trafiła sygnatura produktu, więc formularz logowania nieznanej aplikacji jest raportowany jako `login-page`.

## Licencje komponentów

nmap (NPSL, instalowany z dystrybucji w obrazie budowanym lokalnie), htmx 2.0.4 (0BSD, `web/static/htmx.LICENSE`), chi, pgx, x/crypto, x/time, yaml.v3 (MIT/BSD/Apache-2.0), Percona Distribution for PostgreSQL z pg_tde (PostgreSQL License), DefectDojo (BSD-3-Clause, osobny compose w `deploy/defectdojo`).
