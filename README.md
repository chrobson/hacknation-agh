# Attack Surface Intelligence (HackNation 2026, zadanie AGH)

> Narzędzie do cyklicznego skanowania rozległych sieci (powyżej 10 000 adresów IP): wykrywa aktywne hosty, usługi, technologie webowe, CMS-y, charakterystyczne nagłówki i ciasteczka oraz rejestruje zmiany w czasie.
> Partner: **Centrum Bezpieczeństwa Informacji AGH**. Wynagrodzenie: **25 000 zł brutto, umowa o dzieło** z przeniesieniem praw autorskich.
> Stack: **Go + PostgreSQL** (organizator sugeruje Go/Rust/C++).

## Podsumowanie zadania

Prototyp systemu „discovery scan” dużej infrastruktury dla zespołu bezpieczeństwa. Ma:
- bezpiecznie skanować tysiące adresów,
- identyfikować, co faktycznie działa pod adresem (aplikacja webowa, panel administracyjny, CMS, staging, IoT),
- porównywać kolejne przebiegi skanu (nowe, znikające i zmienione usługi, hosty niestabilne),
- przechowywać wyniki bezpiecznie (szyfrowanie, role użytkowników),
- integrować się z **DefectDojo**.

Problemy, które wskazuje AGH:
- brak gotowego narzędzia (SecureCodeBox nie spełnia wymagań),
- duża adresacja,
- hosty odpowiadające tylko o niektórych porach (jak raportować zmianę, jak określić pewność identyfikacji, po ilu nieudanych skanach uznać host za nieaktywny).

## Wymagania obowiązkowe (lista z treści zadania)

1. Wczytanie listy **IP, zakresów CIDR lub domen**.
2. Bezpieczny skan discovery: **wielowątkowo**, narzędziami typu **nmap** (integrowalnymi z DefectDojo), **pomiar czasu skanu**, **podział adresów na optymalne podgrupy**.
3. Wykrycie aktywnych hostów.
4. Identyfikacja podstawowych usług.
5. HTTP/HTTPS: **tytuł, kod odpowiedzi, nagłówki, ciasteczka, certyfikat TLS, przekierowania**.
6. Wykrywanie technologii: CMS, framework, serwer aplikacyjny, urządzenie IoT.
7. Rozpoznawanie: **środowisko testowe/staging, panel administracyjny**.
8. Porównanie wyników między przebiegami.
9. Oznaczanie **nowych, znikających i zmienionych** usług.
10. **Własne sygnatury detekcyjne**, bezpieczne: nagłówek, ciasteczko, hash favicony, fragment HTML, ścieżka `/login` `/admin` `/version` (bez prób logowania), wersja w stopce, fingerprint CMS. **Żadnej eksploatacji podatności.**
11. Formularz danych: **ręcznie oraz z pliku CSV i/lub JSON**, przetwarzany tak samo jak reszta.
12. **RBAC** z możliwością tworzenia ról.
13. Role: **Administracja; Dodawanie/usuwanie/modyfikacja; Modyfikacja i odczyt; Odczyt**.
14. **Edycja wprowadzonych wartości** niezależnie od stanu skanu, z zachowaniem zmian przy kolejnych skanach.
15. Czytelny interfejs dla każdej roli + **główny dashboard** z najważniejszymi znaleziskami.
16. Baza danych z **szyfrowaniem w spoczynku** dla wszystkich pól z danymi wrażliwymi.

Dodatkowo:
- **okna czasowe i częstotliwość** skanów; gdy skan przekroczy okno, zostaje zatrzymany i uruchomiony ponownie w kolejnym oknie,
- ograniczanie tempa zapytań,
- import wyników skanów (JSON/CSV),
- eksport (JSON/CSV).

**Mile widziane:**
- harmonogram cyklicznych skanów,
- różnice zależne od pory dnia,
- ocena „ciekawości” i priorytet analityczny,
- powtarzanie pomiarów dla hostów niestabilnych,
- grupowanie podobnych usług, tagi,
- eksport do DefectDojo (finding informacyjny / evidence),
- wizualizacja zmian w czasie,
- pasywne źródła danych.

## Wymagania formalne
- Repozytorium kodu źródłowego.
- Dokumentacja techniczna.
- Prezentacja **do 10 slajdów** + **działające demo** (lokalnie lub w środowisku testowym).
- Tylko darmowe, open source lub niewymagające licencji technologie.

## Ocena

| Kryterium | Waga |
|---|---|
| Skuteczność discovery i poprawność identyfikacji usług w dużej infrastrukturze | **30%** |
| Jakość techniczna, dokumentacja, prezentacja, łatwość uruchomienia, import/eksport, integracja (DefectDojo) | **20%** |
| Wykrywanie zmian w czasie, niestabilne hosty, raportowanie | 15% |
| Bezpieczeństwo działania, kontrola intensywności skanowania, przejrzystość dashboardu | 15% |
| Fingerprinting: technologie, CMS-y, nagłówki, ciasteczka, sygnatury | 10% |
| Role i zabezpieczenie danych | 10% |

**Test jury:** laboratorium AGH z zestawem hostów i usług, **co najmniej 2 przebiegi skanu** (wykrywanie zmian), test edycji znalezisk, importu i rozgraniczenia ról.

## Zasoby od AGH (Discord lub stoisko AGH, odebrać od razu)
1. Konfiguracja kontenerów środowiska testowego.
2. Zasady bezpiecznego skanowania i limity ruchu.
3. Lista dozwolonych portów.
4. Przykładowe wyniki referencyjne.
5. Przykładowe sygnatury.
6. Format importu/eksportu JSON/CSV.
7. Opcjonalnie: testowa instancja DefectDojo, kontener z usługami, przykładowe domeny, lista „ciekawych artefaktów”.

Linki: DefectDojo API https://demo.defectdojo.org/api/v2/oa3/swagger-ui/ · nmap https://nmap.org/docs.html · SecureCodeBox https://www.securecodebox.io/docs/getting-started/installation

## Regulamin: warunki
- Jury (≥3 osoby, ewentualnie 1 osoba od Organizatora) wskazuje zwycięzcę **i zespół rezerwowy**.
- Zwycięzca zawiera z AGH **umowę o dzieło** (25 000 zł brutto, podatek wg zasad umowy o dzieło) z przeniesieniem praw do kodu i dokumentacji. Podpisanie w 7 dni, wypłata do 1 miesiąca od przekazania dzieła.

Szczegóły i plan: [`docs/WYMAGANIA.md`](docs/WYMAGANIA.md).

## Terminy
- Draft na HackTribe: **sob. 21.11, 20:00**
- Zgłoszenie końcowe: **niedz. 22.11, 11:00**
