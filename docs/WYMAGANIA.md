# Attack Surface Intelligence: architektura, priorytety i plan

## 1. Priorytety (solo, 24h)

| P | Zakres | Kryterium, którego dotyczy |
|---|---|---|
| **P0** | import celów (formularz + CSV/JSON), host discovery + skan usług (nmap), zapis do Postgresa | discovery 30% |
| **P0** | fingerprinting HTTP/TLS (tytuł, kod, nagłówki, ciasteczka, certyfikat, przekierowania) | discovery 30%, fingerprinting 10% |
| **P0** | diff przebiegów: new / gone / changed + dashboard „co się zmieniło” | zmiany 15% |
| **P0** | RBAC (4 role) + szyfrowanie wrażliwych pól (pgcrypto) | role i dane 10% |
| **P1** | sygnatury YAML (nagłówek, ciasteczko, regex HTML, favicon mmh3, ścieżka GET) + edycja w UI | fingerprinting 10% |
| **P1** | edycja wyników zachowywana między skanami (warstwa „overrides”) | wymaganie nr 14 |
| **P1** | rate limiting, chunking CIDR, pomiar czasu, adaptacyjny rozmiar grup | bezpieczeństwo 15% |
| **P1** | eksport JSON/CSV, import wyników | techniczne 20% |
| **P2** | scheduler: okna czasowe, częstotliwość, przerwanie i wznowienie w kolejnym oknie | wymagania dodatkowe |
| **P2** | eksport do DefectDojo (API v2 `import-scan` / findingi informacyjne) | techniczne 20% |
| **P3** | niestabilne hosty (N kolejnych braków odpowiedzi), różnice wg pory dnia, „interest score”, tagi, wykresy | zmiany 15% |

## 2. Architektura (Go)

```
cmd/server     – HTTP: chi + templ/htmx (dashboard, formularze, edycja), sesje (cookie) + RBAC middleware
cmd/worker     – scheduler + pula workerów (kolejka w Postgresie: SELECT … FOR UPDATE SKIP LOCKED)
internal/target   – parsowanie IP/CIDR/domen (net/netip), dzielenie na grupy, deduplikacja
internal/scan     – nmap przez exec (-sn, -sV, -oX) + parser XML; limit równoległości i --max-rate
internal/httpfp   – net/http + crypto/tls: tytuł, nagłówki, ciasteczka, łańcuch przekierowań, certyfikat, favicon mmh3
internal/sig      – sygnatury YAML → dopasowania z confidence; brak żądań innych niż GET/HEAD
internal/diff     – porównanie (host, port, proto, fingerprint) między przebiegami → new/gone/changed/unstable
internal/rbac     – role i uprawnienia (admin, crud, edit+read, read) jako dane w bazie
internal/crypto   – pgp_sym_encrypt/decrypt (pgcrypto), klucz z env (KMS-ready)
internal/dojo     – klient DefectDojo API v2
internal/export   – JSON/CSV
migrations/       – goose; zapytania przez sqlc + pgx/v5
signatures/       – wbudowane sygnatury (WordPress, Joomla, Drupal, phpMyAdmin, Jenkins, Grafana, Tomcat, staging/dev …)
```

### Model danych (szkic)
```
users(id, login, password_hash, role_id) · roles(id, name) · role_permissions(role_id, perm)
targets(id, kind[ip|cidr|domain], value, tags[], note_enc bytea, created_by)
scan_configs(id, name, target_ids[], window_start, window_end, cron, max_rate, parallelism)
scan_runs(id, config_id, started_at, finished_at, status[running|done|paused|aborted], duration_ms, chunk_stats jsonb)
hosts(id, ip inet, hostname, first_seen, last_seen, miss_count, state[up|down|unstable])
services(id, host_id, port, proto, product, version, banner_enc bytea, first_seen, last_seen, run_id)
http_observations(id, service_id, run_id, status, title, headers jsonb, cookies_enc bytea, tls jsonb, redirects jsonb, favicon_hash)
detections(id, service_id, run_id, signature_id, confidence, evidence jsonb)
overrides(id, entity, entity_id, field, value, edited_by, edited_at)   -- edycje użytkownika przetrwają kolejne skany
changes(id, run_id, prev_run_id, entity, entity_id, kind[new|gone|changed], diff jsonb)
signatures(id, name, yaml, enabled, created_by)
audit_log(id, user_id, action, entity, at)
```

### Bezpieczeństwo skanera
- Tylko cele z formularza lub importu; twardy limit tempa (`--max-rate`) i równoległości.
- Moduł sygnatur wysyła wyłącznie GET/HEAD bez danych logowania.
- Okno czasowe: gdy czas się kończy, kontekst zostaje anulowany, a skan wraca do kolejki od nieukończonej grupy.
- Logowanie wszystkich operacji (audit log).

## 3. Demo (scenariusz na pitch)
1. Logowanie jako admin → import CSV z zakresem labu AGH.
2. Uruchomienie skanu: pasek postępu grup i czas trwania.
3. Dashboard: aktywne hosty, usługi, wykryte CMS-y i panele administracyjne, „ciekawe” nagłówki i ciasteczka.
4. Dodanie własnej sygnatury z UI → ponowna analiza.
5. Drugi przebieg (zmiana w labie) → widok „nowe / znikające / zmienione”.
6. Edycja znaleziska (komentarz, tag) → widać, że przetrwała kolejny skan.
7. Przelogowanie na rolę „Odczyt”: brak przycisków edycji, API zwraca 403.
8. Eksport do DefectDojo / CSV.
9. Pokazanie w bazie, że pola wrażliwe są zaszyfrowane (`bytea`).

## 4. Pytania do mentorów AGH
1. Adresacja labu, dozwolone porty i limity ruchu?
2. Czy nmap musi działać w trybie uprzywilejowanym (SYN scan), czy wystarczy connect scan w kontenerze?
3. Format referencyjnego importu/eksportu JSON/CSV i przykładowe sygnatury?
4. Czy dostępna jest testowa instancja DefectDojo (URL, token)?
5. Jak jury będzie zmieniać lab między przebiegami (żeby przetestować diff)?

## 5. Plan startu i ryzyka (uzgodnione z sesją hacknation-0c)

**Kolejność:** draft obu projektów przed 20:00 → (UZP: eval + baseline w 1. godzinie) → **AGH, godz. 1–2:** docker-compose (postgres + app), migracje goose, import celów, `nmap -sV -oX` + parser XML, zapis hostów i usług (pokrywa P0 discovery = 30%) → **godz. 2–3:** fingerprinting HTTP/TLS (net/http + `tls.ConnectionState`, certyfikat, nagłówki, tytuł, favicon hash).

**Gotowe elementy (licencje sprawdzić przed użyciem, bo wygrana oznacza przeniesienie praw):**
- `github.com/Ullaakut/nmap`: struktury XML nmapa,
- `github.com/projectdiscovery/wappalyzergo`: wykrywanie CMS i technologii (podobno MIT, zweryfikować),
- format nuclei-templates jako inspiracja dla YAML sygnatur (tylko GET),
- DefectDojo „Generic Findings Import” (JSON) jako najprostszy format eksportu,
- szyfrowanie: **AES-GCM w Go** zamiast pgcrypto (klucz nie trafia do zapytań SQL).

**Ryzyka i decyzje:**
- **Zakres to największe ryzyko** (~15 funkcji solo). RBAC + szyfrowanie razem to tylko 10% oceny, więc zrobić je minimalnie (middleware z mapą rola → uprawnienia, szyfrowane pola wrażliwe). Dopracować discovery (30%) i diff (15%).
- **nmap w kontenerze:** domyślnie connect scan (`-sT`); SYN (`-sS`, wymaga NET_RAW/root) jako opcja. Dopytać o adresację labu i limity.
- **„Niestabilny” host:** zdefiniować jawnie (np. `miss_count` ≥ N lub liczba zmian stanu w oknie N przebiegów). Wymaga ≥3 przebiegów.
- **Overrides:** osobna tabela z kluczem naturalnym `(ip, port, proto)`, a nie przywiązana do wiersza skanu.
- **Szybkość developmentu:** przy presji czasu `html/template` + htmx zamiast templ, a pgx z ręcznym SQL zamiast sqlc.
- **Oba projekty:** finały mogą się nałożyć (od 15:15). Rano zapytać organizatora o osobne sloty.

**Narzędzia (po restarcie Claude Code):** w dzień grill-me → to-tickets → implement; **w nocy superpowers writing-plans + subagent-driven-development** dla ticketów A6–A11 w worktree, skanując **wyłącznie lokalny mini-lab**. Playwright (screenshoty dashboardu), context7 (pgx, chi), gopls-lsp. Prezentacja ≤10 slajdów. Szczegóły: `../hacknation/PLAN_PRACY.md`.

**Ticket A-lab (wcześnie, przed discovery):** lokalny mini-lab w docker compose (nginx, WordPress, phpMyAdmin, Jenkins/Grafana, vhost staging, SSH) + skrypt `lab-change.sh` zmieniający usługi między przebiegami, do testu diffu. Bez niego nie da się przetestować discovery, diffu ani demo przed dostępem do labu AGH, a nocni agenci potrzebują bezpiecznego celu. Eksport do DefectDojo sprawdzić na `demo.defectdojo.org` tylko danymi z mini-labu.

**Licencje (sprawdzone przez hacknation-0c, 12:40):** Ullaakut/nmap, wappalyzergo, chi, pgx, sqlc, templ, nuclei-templates: MIT. **goose: GitHub zwraca „NOASSERTION”**, przed użyciem przeczytać jego LICENSE albo użyć prostego runnera migracji.

## 6. ODPOWIEDZI MENTORÓW AGH (stoisko, 21.11)

| # | Pytanie (skrót) | Odpowiedź | Decyzja dla kodu |
|---|---|---|---|
| A1 | Adresacja labu, porty, limity, konfiguracja | „Będzie niedługo podane” | do tego czasu własny mini-lab (A-lab); obserwować Discord |
| A2 | Format importu/eksportu | **Format JSON DefectDojo, oparty głównie na findings** | eksport/import = **DefectDojo Generic Findings JSON** jako format natywny; CSV jako dodatek |
| A3 | Zmiany labu między przebiegami | „Mają kilka plików compose” (szczegóły później) | diff testowany przełączaniem compose; nasz `lab-change.sh` robi to samo |
| A4 | Testowa instancja DefectDojo | **Publiczne demo DefectDojo** (demo.defectdojo.org); typ importu bez preferencji | integracja przez API v2 `import-scan` (Generic Findings Import), testy tylko na danych z mini-labu |
| A5 | SYN vs connect scan | Bez preferencji | domyślnie `-sT` (bez roota w kontenerze), `-sS` jako opcja konfiguracyjna |
| A6 | Definicja nieaktywnego/niestabilnego hosta | Brak narzuconej definicji (odpowiedź niejasna) | własna jawna definicja w konfiguracji (np. `inactive_after_misses: 3`, `unstable_if_flips >= 2 w ostatnich N`), opisana w dokumentacji |
| A7 | Szyfrowanie w spoczynku | **Szyfrowanie CAŁEJ bazy** | ⚠️ **ZMIANA PLANU**: szyfrowanie pól nie wystarczy. Opcje: (a) **Percona `pg_tde`** (rozszerzenie open source do PostgreSQL 17, TDE; zweryfikować licencję i obraz Docker), (b) zaszyfrowany wolumen danych Postgresa (LUKS/dm-crypt lub gocryptfs pod `PGDATA`), (c) SQLite + SQLCipher zamiast Postgresa. Rekomendacja: sprawdzić (a) w pierwszej kolejności, fallback (b); do tego zostaje szyfrowanie wrażliwych pól w aplikacji jako druga warstwa |
| A8 | Demo lokalnie podpięte do labu | „Zobaczymy z czasem” | przygotować oba warianty: lokalny i w kontenerze w sieci labu |

**Wpływ na priorytety:** szyfrowanie całej bazy przechodzi do **P0** (decyzja w 1. godzinie, bo wpływa na wybór obrazu i bazy). Format DefectDojo Generic Findings przechodzi do P1 jako format główny eksportu.
