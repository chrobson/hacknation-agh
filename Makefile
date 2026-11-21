.PHONY: build test e2e-smoke e2e up down

build:
	go build -trimpath -o bin/asi ./cmd/asi

test:
	go vet ./... && go test -race ./...

up:
	docker compose up -d --build

down:
	docker compose down

# End-to-end targets are implemented in scripts/ by the e2e workstream.
e2e-smoke:
	./scripts/e2e.sh smoke

e2e:
	./scripts/e2e.sh full
