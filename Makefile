.PHONY: build test vet e2e-smoke e2e up up-lab down env

build:
	go build -trimpath -o bin/asi ./cmd/asi

vet:
	go vet ./...

test: vet
	go test -race ./...

# Local .env with random secrets (gitignored). Never commit it.
env:
	@test -f .env || ./scripts/gen-env.sh

up: env
	docker compose up -d --build

# App attached to the docker scan lab (start the lab first: lab/change.sh run1).
up-lab: env
	docker compose -f compose.yml -f compose.lab.yml up -d --build

down:
	docker compose -f compose.yml -f compose.lab.yml down

# End-to-end against the docker lab: smoke = run1 only; full = run1 -> run2 -> run3
# with change detection, RBAC, DefectDojo export round trip and encryption checks.
e2e-smoke:
	./scripts/e2e.sh smoke

e2e:
	./scripts/e2e.sh full

include mk/dojo.mk
