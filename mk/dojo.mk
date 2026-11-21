# DefectDojo integration targets (W1-6). Included by the main Makefile:
#   include mk/dojo.mk
# or used directly: make -f mk/dojo.mk <target>
#
# The local DefectDojo runs as a separate compose project ("defectdojo"),
# never together with the main ASI compose.

DOJO_DIR      ?= deploy/defectdojo
DOJO_COMPOSE  ?= docker compose --project-directory $(DOJO_DIR) -f $(DOJO_DIR)/compose.yml --env-file $(DOJO_DIR)/.env
DOJO_URL      ?= http://localhost:8081
DOJO_USER     ?= admin
DOJO_FILE     ?= testdata/dojo/golden_findings.json
DOJO_WAIT_S   ?= 900

.PHONY: dojo-env dojo-up dojo-down dojo-logs dojo-password dojo-wait dojo-validate e2e-dojo

# Random secrets for the local instance (kept out of git by deploy/defectdojo/.gitignore).
dojo-env:
	@test -f $(DOJO_DIR)/.env || { \
	  umask 077; \
	  printf 'DD_DATABASE_PASSWORD=%s\nDD_SECRET_KEY=%s\nDD_CREDENTIAL_AES_256_KEY=%s\nDD_PORT=8081\n' \
	    "$$(openssl rand -hex 16)" "$$(openssl rand -hex 32)" "$$(openssl rand -hex 16)" > $(DOJO_DIR)/.env; \
	  echo "created $(DOJO_DIR)/.env"; }

dojo-up: dojo-env
	$(DOJO_COMPOSE) up -d
	@echo "DefectDojo starting on $(DOJO_URL) (first start takes several minutes)."
	@echo "Admin password: make dojo-password"

# Stops the containers; volumes (database, media) are kept. To wipe them as
# well, run the same compose command with `down --volumes` by hand.
dojo-down:
	$(DOJO_COMPOSE) down

dojo-logs:
	$(DOJO_COMPOSE) logs -f --tail=100

# The initializer prints the generated password once, on the first start.
dojo-password:
	@$(DOJO_COMPOSE) logs initializer | grep "Admin password" || \
	  { echo "no 'Admin password' line yet: wait for the initializer to finish" >&2; exit 1; }

dojo-wait:
	@echo "waiting for $(DOJO_URL)/login ..."; \
	end=$$(( $$(date +%s) + $(DOJO_WAIT_S) )); \
	until curl -fsS -o /dev/null "$(DOJO_URL)/login"; do \
	  [ $$(date +%s) -lt $$end ] || { echo "DefectDojo not ready after $(DOJO_WAIT_S)s" >&2; exit 1; }; \
	  sleep 10; \
	done; echo "DefectDojo is up"

dojo-validate:
	go run ./internal/dojo/dojopush -validate -file $(DOJO_FILE)

# Validates a generated Generic Findings file offline, then pushes it to the
# local instance with import-scan and reimport-scan (close_old_findings=true).
# With ASI_DATABASE_URL set, the file is generated from the latest run;
# otherwise the golden file from testdata/dojo is used.
e2e-dojo: dojo-wait
	@pass=$$($(DOJO_COMPOSE) logs initializer 2>/dev/null | grep "Admin password" | tail -1 | sed 's/.*Admin password: *//' | tr -d '\r'); \
	[ -n "$$pass$$DOJO_TOKEN$$DOJO_PASSWORD" ] || { echo "admin password not found in initializer logs; set DOJO_TOKEN or DOJO_PASSWORD" >&2; exit 1; }; \
	if [ -n "$$ASI_DATABASE_URL" ]; then src="-from-db"; else src="-file $(DOJO_FILE)"; fi; \
	DOJO_URL=$(DOJO_URL) DOJO_USER=$(DOJO_USER) DOJO_PASSWORD="$${DOJO_PASSWORD:-$$pass}" \
	  go run ./internal/dojo/dojopush $$src -engagement "e2e $$(date +%Y-%m-%d)"
