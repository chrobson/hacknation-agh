# Lokalny DefectDojo (integracja ASI)

Oficjalny `docker-compose.yml` DefectDojo (licencja BSD-3-Clause) przypięty do wydania **3.5.202**. Uruchamiany **osobno** od głównego `compose.yml` ASI, jako projekt compose `defectdojo`.

| | |
|---|---|
| Kontenery | nginx, uwsgi, celerybeat, celeryworker, initializer, postgres, valkey |
| Pamięć | ok. 4 GB RAM |
| Pierwszy start | kilka minut (migracje bazy w kontenerze `initializer`) |
| Adres | http://localhost:8081 (tylko 127.0.0.1, żeby nie kolidować z ASI na :8080) |

## Zmiany względem pliku upstream

- Obrazy `defectdojo-django` i `defectdojo-nginx` przypięte do tagu `3.5.202`, bez sekcji `build`.
- Domyślny rejestr to `docker.io`. Upstream używa `registry.defectdojo.com`, który loguje adresy IP; można go przywrócić zmienną `DD_IMAGE_REGISTRY`.
- Brak domyślnych sekretów: `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY` i hasło bazy są generowane losowo przez `make dojo-env` do pliku `deploy/defectdojo/.env` (poza gitem).
- Hasło administratora **nie jest nigdzie zapisane**: generuje je `initializer` przy pierwszym starcie.
- `DD_HASHCODE_FIELDS_PER_SCANNER={"Generic Findings Import": ["title", "severity", "endpoints"]}`: deduplikacja findingów ASI po tytule, severity i endpointach (zgodnie z kontraktem ASI). Domyślnie DefectDojo liczy hash tego parsera z tytułu i opisu (`compute_hash_code_legacy`), dlatego opis generowany przez ASI też jest deterministyczny: nie zawiera czasu, numeru przebiegu ani surowego banera usługi.

## Uruchomienie

```sh
make -f mk/dojo.mk dojo-up         # albo: make dojo-up (gdy główny Makefile dołącza mk/dojo.mk)
make -f mk/dojo.mk dojo-wait       # czeka, aż /login odpowie
make -f mk/dojo.mk dojo-password   # = docker compose logs initializer | grep "Admin password"
```

Logowanie: użytkownik `admin`, hasło z `dojo-password`. Linia z hasłem pojawia się tylko przy pierwszej inicjalizacji bazy. Jeśli zginie, ustaw nowe hasło:

```sh
docker compose --project-directory deploy/defectdojo -f deploy/defectdojo/compose.yml \
  --env-file deploy/defectdojo/.env exec uwsgi ./manage.py changepassword admin
```

Zatrzymanie: `make -f mk/dojo.mk dojo-down`. Wolumeny z danymi zostają.

## Test end-to-end

```sh
make -f mk/dojo.mk e2e-dojo
```

1. Plik Generic Findings jest walidowany offline (`dojo.Validate`: whitelista kluczy, wymagane pola, unikalne `unique_id_from_tool`).
2. Plik trafia do DefectDojo przez `import-scan` (`scan_type=Generic Findings Import`, `auto_create_context=true`, produkt „Attack Surface Intelligence”, engagement „e2e RRRR-MM-DD”).
3. Ten sam plik jest wysyłany ponownie przez `reimport-scan` z `close_old_findings=true`. Statystyki drugiego wywołania nie powinny pokazywać nowych findingów (lokalna instancja deduplikuje po tytule, severity i endpointach, patrz wyżej).

Źródło pliku: przy ustawionym `ASI_DATABASE_URL` generowany jest z ostatniego przebiegu w bazie, w przeciwnym razie używany jest `testdata/dojo/golden_findings.json`.

## Wysyłka z aplikacji

Wysyłka jest domyślnie **wyłączona**. Żeby ją włączyć, ustaw:

```sh
ASI_DOJO_URL=http://host.docker.internal:8081   # albo http://localhost:8081 poza dockerem
ASI_DOJO_PUSH=true
ASI_DOJO_TOKEN=...                               # token API (Profil użytkownika → API v2 Key)
# albo ASI_DOJO_USER / ASI_DOJO_PASSWORD: token zostanie pobrany z /api/v2/api-token-auth/
```

Przycisk „Wyślij do DefectDojo” na stronie `/export` wykonuje `reimport-scan` z `close_old_findings=true`. Jeśli testu jeszcze nie ma, wykonuje `import-scan`. Findingi oznaczone jako fałszywy alarm są pomijane, a ręcznie zmienione severity jest uwzględniane.

**Publiczna instancja demo (demo.defectdojo.org) jest dostępna dla wszystkich.** Wysyłaj do niej wyłącznie dane z labu lub z adresów RFC 5737.
