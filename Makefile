# Makefile for the Checkmk AWS SCIM Token special agent
# Run `make help` to see available targets.

.PHONY: help lint secrets format test build clean

SHELL := /bin/bash

# Proxy build arguments (pass-through for corporate environments)
BUILD_ARGS := $(if $(HTTP_PROXY),--build-arg HTTP_PROXY=$(HTTP_PROXY) --build-arg http_proxy=$(HTTP_PROXY),) \
              $(if $(HTTPS_PROXY),--build-arg HTTPS_PROXY=$(HTTPS_PROXY) --build-arg https_proxy=$(HTTPS_PROXY),) \
              $(if $(NO_PROXY),--build-arg NO_PROXY=$(NO_PROXY) --build-arg no_proxy=$(NO_PROXY),)

BUILD_IMAGE := checkmk-aws-scim-token-build

help:
	@echo "Available targets:"
	@echo "  lint      Run all pre-commit hooks: linters + secret scan (same as CI)"
	@echo "  secrets   Scan the full git history for secrets (gitleaks, Docker)"
	@echo "  format    Format and autofix Python code with ruff"
	@echo "  test      Run pytest inside the Checkmk build image"
	@echo "  build     Build the MKP package (requires podman/docker)"
	@echo "  clean     Remove build artifacts"

lint:
	@echo "==> Running pre-commit hooks (same as CI)..."
	uv run pre-commit run --all-files

secrets:
	@echo "==> Scanning the full git history for secrets..."
	docker run --rm -v "$$PWD:/repo:ro" ghcr.io/gitleaks/gitleaks:v8.30.1 git --redact --verbose /repo

format:
	@echo "==> Formatting Python code with ruff..."
	uv run ruff format .
	uv run ruff check --fix .

test:
	@echo "==> Running pytest inside the Checkmk build image..."
	docker build $(BUILD_ARGS) -t $(BUILD_IMAGE) -f build/Dockerfile .
	docker run --rm -v "$$PWD:/source:ro" --entrypoint /source/tests/run-pytest.sh $(BUILD_IMAGE)

build:
	@echo "==> Building MKP package..."
	@if command -v podman &>/dev/null; then \
		podman build --format docker $(BUILD_ARGS) -t $(BUILD_IMAGE) -f build/Dockerfile .; \
		podman run --rm -v "$$PWD:/source:Z" $(BUILD_IMAGE); \
	elif command -v docker &>/dev/null; then \
		docker build $(BUILD_ARGS) -t $(BUILD_IMAGE) -f build/Dockerfile .; \
		docker run --rm -v "$$PWD:/source" $(BUILD_IMAGE); \
	else \
		echo "ERROR: Neither podman nor docker found"; \
		exit 1; \
	fi

clean:
	@echo "==> Cleaning build artifacts..."
	rm -f *.mkp
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
