GO ?= go
PYTHON ?= python3
BUILD_DIR ?= output/bin
VERSION ?= development
PACKAGE_DIR ?= ../cosmoedge-connect-$(VERSION)
CHECK_BASE ?=

.PHONY: build test test-python race vet docs-check check check-all check-plan package-macos package-windows

build:
	$(PYTHON) -c "from pathlib import Path; Path('$(BUILD_DIR)').mkdir(parents=True, exist_ok=True)"
	$(GO) build -o $(BUILD_DIR)/ ./cmd/cosmoedge-connect ./cmd/cosmoedge-mcp

test:
	$(GO) test -p 1 -count=1 ./...

race:
	$(GO) test -race -p 1 -count=1 ./internal/operations/... ./internal/operator/... ./internal/mcpbridge/... ./cmd/cosmoedge-connect ./cmd/cosmoedge-mcp

vet:
	$(GO) vet ./...

test-python:
	$(PYTHON) -m unittest discover -s integrations/workbuddy/tests -v
	$(PYTHON) -m unittest discover -s integrations/workbuddy/deploy/macos/tests -v
	$(PYTHON) -m unittest discover -s integrations/workbuddy/deploy/windows/tests -v
	$(PYTHON) -m unittest discover -s scripts/tests -v

docs-check:
	$(PYTHON) scripts/check-docs.py

check:
	$(PYTHON) scripts/check-changes.py $(if $(CHECK_BASE),--base "$(CHECK_BASE)") --run --go "$(GO)" --python "$(PYTHON)"

check-all:
	$(PYTHON) scripts/check-changes.py --all --run --go "$(GO)" --python "$(PYTHON)"

check-plan:
	$(PYTHON) scripts/check-changes.py $(if $(CHECK_BASE),--base "$(CHECK_BASE)") --json

package-macos:
	$(PYTHON) scripts/build-connect-macos.py --development-app --with-mcp --version $(VERSION) --output "$(PACKAGE_DIR)"

package-windows:
	$(PYTHON) scripts/build-connect-windows.py --with-mcp --version $(VERSION) --output "$(PACKAGE_DIR)"
