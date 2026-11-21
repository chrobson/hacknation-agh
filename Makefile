.PHONY: build test vet e2e-smoke e2e e2e-agh e2e-toxi up up-lab up-host up-hostgw native-db native down env seed-demo doctor

build:
	go build -trimpath -o bin/asi ./cmd/asi

vet:
	go vet ./...

test: vet
	go test -race ./...

# Local .env with random secrets (gitignored). Never commit it.
env:
	@test -f .env || ./scripts/gen-env.sh

# Preflight: docker, compose v2, openssl, free ports (scripts/doctor.sh).
doctor:
	@./scripts/doctor.sh $(DOCTOR_ARGS)

up: env doctor
	docker compose up -d --build --wait

# App attached to the docker scan lab (start the lab first: lab/change.sh run1).
up-lab: env doctor
	docker compose -f compose.yml -f compose.lab.yml up -d --build --wait

# Scanning services published on this host (localhost), see README.
# Linux: app in the host network namespace (target localhost / 127.0.0.1).
up-host: DOCTOR_ARGS = --db-port
up-host: env doctor
	docker compose -f compose.host.yml up -d --build --wait

# Docker Desktop / OrbStack (also Linux): app reaches the host through
# host.docker.internal (target host.docker.internal).
up-hostgw: env doctor
	docker compose -f compose.yml -f compose.hostgw.yml up -d --build --wait

# Native: database in docker on 127.0.0.1:$${ASI_DB_PORT:-55432}, asi and nmap on the host.
native-db: env
	docker compose -f compose.host.yml up -d --wait db

native: build native-db
	set -a; . ./.env; set +a; \
	ASI_DATABASE_URL="postgres://$${ASI_DB_USER:-asi}:$${ASI_DB_PASSWORD}@127.0.0.1:$${ASI_DB_PORT:-55432}/asi?sslmode=disable" \
	ASI_HTTP_ADDR="127.0.0.1:$${ASI_PORT:-9080}" ./bin/asi serve

# Demo targets and the scan configuration "Demo" (auto port profile,
# 1000 packets/s). Default target: localhost, or host.docker.internal in the
# up-hostgw mode; override with SEED_TARGETS="127.0.0.1 192.168.1.10".
# Uses the running app container, or bin/asi with the native database.
seed-demo:
	@if [ -n "$$(docker compose ps -q app 2>/dev/null)" ]; then \
	  docker compose exec -T app asi seed-demo $(SEED_TARGETS); \
	else \
	  set -a; . ./.env; set +a; \
	  ASI_DATABASE_URL="postgres://$${ASI_DB_USER:-asi}:$${ASI_DB_PASSWORD}@127.0.0.1:$${ASI_DB_PORT:-55432}/asi?sslmode=disable" \
	  ./bin/asi seed-demo $(SEED_TARGETS); \
	fi

down:
	docker compose -f compose.yml -f compose.lab.yml down

# End-to-end against the docker lab: smoke = run1 only; full = run1 -> run2 -> run3
# with change detection, RBAC, DefectDojo export round trip and encryption checks.
e2e-smoke:
	./scripts/e2e.sh smoke

e2e:
	./scripts/e2e.sh full

# End-to-end against the AGH custom-network template on localhost (stop and
# restore of the service on 8787). Template files: ASI_AGH_LAB_DIR.
e2e-agh:
	./scripts/e2e.sh agh-template

# Fault injection: Toxiproxy latency and timeout toxics on a proxied service
# must not produce false gone/changed rows (scripts/e2e-toxi.sh).
e2e-toxi:
	./scripts/e2e-toxi.sh

include mk/dojo.mk
