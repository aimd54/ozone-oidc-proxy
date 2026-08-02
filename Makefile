# Copyright The ozone-oidc-proxy Authors
# SPDX-License-Identifier: Apache-2.0

.PHONY: help build test vet fmt-check lint tidy-check lint-docs check docker-build up init e2e loadtest portal-up portal-down ha-up ha-down monitor-up monitor-down edge-up edge-down lakehouse-up lakehouse-down lakehouse-smoke down clean logs logs-proxy

BINARY  = bin/ozone-oidc-proxy
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
IMAGE   = ozone-oidc-proxy:dev
COMPOSE        = docker compose -f deploy/compose/docker-compose.yml
COMPOSE_PORTAL = $(COMPOSE) -f deploy/compose/docker-compose.portal.yml
COMPOSE_HA      = $(COMPOSE) -f deploy/compose/docker-compose.ha.yml
COMPOSE_MONITOR = $(COMPOSE) -f deploy/compose/docker-compose.monitor.yml
COMPOSE_EDGE    = $(COMPOSE) -f deploy/compose/docker-compose.edge.yml
COMPOSE_LAKE    = $(COMPOSE) -f deploy/compose/docker-compose.lakehouse.yml
COMPOSE_ALL     = $(COMPOSE_PORTAL) -f deploy/compose/docker-compose.ha.yml -f deploy/compose/docker-compose.monitor.yml -f deploy/compose/docker-compose.edge.yml -f deploy/compose/docker-compose.lakehouse.yml

help:
	@echo "ozone-oidc-proxy, OIDC authentication for the Apache Ozone S3 Gateway"
	@echo ""
	@echo "Development:"
	@echo "  make build         - Build proxy, ozone-login and credential-portal into bin/"
	@echo "  make test          - Run unit tests with the race detector"
	@echo "  make vet           - Run go vet"
	@echo "  make fmt-check     - Fail if any file needs gofmt"
	@echo "  make lint          - Run golangci-lint (v2)"
	@echo "  make tidy-check    - Fail if go.mod/go.sum are not tidy"
	@echo "  make lint-docs     - Lint markdown (requires Node)"
	@echo "  make check         - All local gates (run before every commit)"
	@echo "  make docker-build  - Build the proxy container image ($(IMAGE))"
	@echo ""
	@echo "Compose stack (deploy/compose): Keycloak + Ozone 2.1.1 + proxy"
	@echo "  make up            - Build the image and start the stack"
	@echo "  make init          - Provision Keycloak realm/users and Ozone volume ACLs"
	@echo "  make e2e           - Run the end-to-end test suite"
	@echo "  make portal-up     - Add the credential portal + oauth2-proxy overlay"
	@echo "  make portal-down   - Remove the portal overlay services"
	@echo "  make ha-up         - Add the HA overlay: valkey store + second replica (resign)"
	@echo "  make ha-down       - Remove the HA overlay, restore the single-replica proxy"
	@echo "  make monitor-up    - Add the monitoring overlay: Prometheus + Grafana (localhost:3000)"
	@echo "  make monitor-down  - Remove the monitoring overlay"
	@echo "  make edge-up       - Add the TLS edge overlay: HAProxy (https://localhost:8443)"
	@echo "  make edge-down     - Remove the TLS edge"
	@echo "  make lakehouse-up  - Add Nessie + Postgres + Jupyter (Iceberg over OIDC creds)"
	@echo "  make lakehouse-down - Remove the lakehouse overlay"
	@echo "  make logs          - Tail all stack logs"
	@echo "  make logs-proxy    - Tail proxy logs"
	@echo "  make down          - Stop the stack (keep volumes)"
	@echo "  make clean         - Stop the stack and delete volumes"
	@echo ""
	@echo "Quickstart: make up && make init && make e2e"

GO_BUILD = CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

build:
	$(GO_BUILD) -o $(BINARY) ./cmd/proxy
	$(GO_BUILD) -o bin/ozone-login ./cmd/ozone-login
	$(GO_BUILD) -o bin/credential-portal ./cmd/credential-portal

test:
	go test -race -timeout 10m ./...

vet:
	go vet ./...

fmt-check:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

lint:
	golangci-lint run

tidy-check:
	go mod tidy -diff

lint-docs:
	npx --yes markdownlint-cli2 "**/*.md"

# All local gates; run before every commit. CI runs the same set.
check: fmt-check vet lint tidy-check test

docker-build:
	docker build -t $(IMAGE) --build-arg VERSION=$(VERSION) .

up: docker-build
	$(COMPOSE) up -d --wait keycloak stub-issuer ozone-scm ozone-om ozone-datanode ozone-s3g proxy || ($(COMPOSE) ps; exit 1)
	@echo ""
	@echo "Stack is up. Next: make init"

init:
	$(COMPOSE) run --rm --build init-service
	$(COMPOSE) exec ozone-om bash /scripts/setup-volume-acls.sh
	@echo ""
	@echo "Initialization done. Next: make e2e"

e2e:
	./deploy/compose/scripts/e2e.sh

loadtest:
	./deploy/compose/scripts/loadtest.sh

portal-up: docker-build
	$(COMPOSE_PORTAL) up -d --wait credential-portal oauth2-proxy || ($(COMPOSE_PORTAL) ps; exit 1)
	@echo ""
	@echo "Portal: http://localhost:4180, the browser must resolve 'keycloak'"
	@echo "(add '127.0.0.1 keycloak' to /etc/hosts)."

portal-down:
	$(COMPOSE_PORTAL) rm -sf oauth2-proxy credential-portal

ha-up: docker-build
	$(COMPOSE_HA) up -d --wait valkey proxy proxy-b || ($(COMPOSE_HA) ps; exit 1)
	@echo ""
	@echo "HA overlay up: replica A :9000/:9090 (valkey+rewrite),"
	@echo "replica B :9001/:9091 (valkey+resign), shared valkey store."

ha-down:
	$(COMPOSE_HA) rm -sf proxy-b valkey
	$(COMPOSE) up -d proxy

monitor-up:
	$(COMPOSE_MONITOR) up -d --wait prometheus grafana || ($(COMPOSE_MONITOR) ps; exit 1)
	@echo ""
	@echo "Grafana: http://localhost:3000 (anonymous viewer): dashboard 'Ozone OIDC Proxy'."
	@echo "Drive traffic (make e2e / make loadtest) to populate the panels."

monitor-down:
	$(COMPOSE_MONITOR) rm -sf grafana prometheus

# TLS edge (models the production HAProxy ingress). Self-signed lab cert;
# clients pin deploy/compose/edge/certs/edge.crt or disable verification.
edge-up:
	./deploy/compose/edge/gen-cert.sh
	$(COMPOSE_EDGE) up -d --wait haproxy || ($(COMPOSE_EDGE) ps; exit 1)
	@echo ""
	@echo "TLS edge: https://localhost:8443 (host) / https://haproxy:8443 (compose network)"
	@echo "CA bundle for clients: deploy/compose/edge/certs/edge.crt"

edge-down:
	$(COMPOSE_EDGE) rm -sf haproxy

# Lakehouse overlay: Nessie (Iceberg REST) + Postgres + Jupyter. Nessie
# authenticates to Ozone S3 with OIDC web-identity credentials, no static
# S3 secret anywhere. Needs the base stack + make init.
lakehouse-up:
	$(COMPOSE) exec -T ozone-om bash /scripts/setup-lakehouse-acls.sh
	$(COMPOSE_LAKE) up -d --build --wait nessie jupyter || ($(COMPOSE_LAKE) ps; exit 1)
	@echo ""
	@echo "Nessie:  http://localhost:19120 (API + UI)"
	@echo "Jupyter: http://localhost:8890 (no token; notebook: ozone-oidc-tour.ipynb)"

lakehouse-down:
	$(COMPOSE_LAKE) rm -sf jupyter nessie nessie-token-refresher postgres

lakehouse-smoke:
	./deploy/compose/scripts/lakehouse-smoke.sh

logs:
	$(COMPOSE) logs -f

logs-proxy:
	$(COMPOSE) logs -f proxy

down:
	$(COMPOSE_ALL) down

clean:
	$(COMPOSE_ALL) down -v
