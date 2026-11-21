# Architektura: Attack Surface Intelligence

Jedno binarium `asi` (`migrate | serve | scan | verify | import | export`) w Go 1.26, PostgreSQL z Percona **pg_tde** (szyfrowanie całej bazy w spoczynku), interfejs WWW renderowany po stronie serwera (`html/template` + htmx).

## Moduły i odpowiedzialność

| Pakiet | Zakres | Interfejs |
|---|---|---|
| `internal/target` | parsowanie IP/CIDR/domen, deduplikacja, podział na chunki, **allowlista** | `Allowlist` |
| `internal/scan` + `internal/runner` | nmap: faza 1 `-sn`, faza 2 usługi z wersjami; pula workerów, `--max-rate R/K`, okna czasowe przez `context` z deadline; kolejka chunków `FOR UPDATE SKIP LOCKED` | `scan.Scanner` |
| `internal/httpfp` | GET/HEAD, ≤5 przekierowań, body ≤2 MB, tytuł, nagłówki, ciasteczka, certyfikat TLS (expired/self-signed/mismatch), favicon mmh3 | `httpfp.Prober` |
| `internal/sig` | sygnatury YAML (tylko GET/HEAD, ≤3 ścieżki, bez body i nagłówków auth) | `sig.Matcher` |
| `internal/diff` | porównanie przebiegów po kluczu naturalnym, stany hostów up/down/inactive/unstable | `diff.Compare` (czysta funkcja) |
| `internal/auth` | sesje, bcrypt, RBAC (`Require(perm)` → 403), CSRF: `http.CrossOriginProtection` + `SameSite=Lax`, AES-GCM dla tabeli `secrets` | |
| `internal/dojo`, `internal/export` | DefectDojo Generic Findings JSON (eksport i import), CSV, import XML nmapa | `dojo.Codec` |
| `internal/web` | routing chi; każdy moduł udostępnia `Mount(r, Deps)`; szablony dziedziczą z `web/templates/base.html` | `web.Mounter` |
| `internal/db`, `migrations/` | pula pgx, migracje osadzone (`embed`) zapisywane w `schema_migrations` | |

## Kontrakt danych

- **Klucz naturalny usługi** `model.AssetKey{IP, Port, Proto, VHost}`. Służy do diffu, adnotacji (przetrwają kolejne skany) i do `unique_id_from_tool` w DefectDojo.
- **Schemat**: `migrations/0001_init.sql` (zamrożony). Migracje modułów mają zakresy: 0100 targets, 0200 scan, 0300 fingerprint, 0400 diff, 0500 auth, 0600 dojo/export.
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
  - `unique_id_from_tool`: `asi:svc:<ip>:<port>/<proto>` lub `asi:sig:<ip>:<port>:<sig_id>`, unikalne w pliku.
  - **Tytuły deterministyczne** (bez czasu i numeru przebiegu): DefectDojo deduplikuje po hashu z tytułu, severity i endpointów.
  - Usługi mają `Info`, panele administracyjne i środowiska staging `Medium`.
- **Wzorzec labu** `lab/expected/runN.json` i wynik `asi verify` z precision/recall dla hostów, usług, detekcji i zmian.

## Bezpieczeństwo

- **Allowlista sieci** (`ASI_ALLOWED_CIDRS`) sprawdzana przy imporcie celów i ponownie tuż przed uruchomieniem skanera.
- **Szyfrowanie w spoczynku**: pg_tde (AES-256) dla tabel, indeksów, TOAST, sekwencji i WAL.
  - Logowanie treści zapytań wyłączone, `work_mem` ograniczający pliki tymczasowe.
  - `SET STATISTICS 0` dla kolumn z adresami i banerami, bo `pg_statistic` nie jest szyfrowane.
  - Ograniczenia: nazwy tabel w katalogu systemowym, lokalny keyring. W produkcji klucz w OpenBao/KMIP.
- **Sekrety aplikacji** (token DefectDojo): AES-GCM kluczem `ASI_SECRET_KEY`.
- **DefectDojo push** domyślnie wyłączony.
