VENV := .venv
BIN := $(VENV)/bin
LAMBDA_BUILD := build/lambda
LAMBDA_MODULES := detect investigate narrate verifier authorize containment shared workflow
# Lambda runs Linux on x86_64, and CDK creates these functions with the default
# architecture. Building the asset for the host instead ships binaries that cannot load.
LAMBDA_PLATFORM := x86_64-manylinux2014
LAMBDA_PYTHON := 3.12

.PHONY: install test lint typecheck secrets check fmt lambda-package console-install console-check clean

install:
	uv venv --python 3.12 $(VENV)
	uv pip install --python $(BIN)/python -r requirements-dev.txt

test:
	$(BIN)/pytest

lint:
	$(BIN)/ruff check .
	$(BIN)/ruff format --check .

typecheck:
	$(BIN)/mypy

secrets:
	./scripts/check_secrets.sh

fmt:
	$(BIN)/ruff format .
	$(BIN)/ruff check --fix .

console-install:
	cd console && npm install

# Type-checks, unit-tests and builds the console. Skipped with a warning when the
# dependencies are not installed, so `make check` still runs on a fresh clone.
console-check:
	@if [ -d console/node_modules ]; then \
		cd console && npm run test && npm run build; \
	else \
		echo "console/node_modules missing, skipping (run: make console-install)"; \
	fi

check: secrets lint typecheck test console-check

# The Lambda asset CDK uploads: our modules plus the dependencies the Lambda
# runtime does not already carry.
#
# The platform pin is not optional. Building on macOS without it installs
# _pydantic_core.cpython-312-darwin.so into the asset, which imports fine here and
# fails on Lambda, at the worst possible moment. The check afterwards is there
# because a comment asking nicely would not have caught it the first time.
lambda-package:
	rm -rf "$(LAMBDA_BUILD)"
	mkdir -p "$(LAMBDA_BUILD)"
	cp -r $(LAMBDA_MODULES) "$(LAMBDA_BUILD)/"
	uv pip install --python $(BIN)/python --target "$(LAMBDA_BUILD)" \
		--python-platform $(LAMBDA_PLATFORM) --python-version $(LAMBDA_PYTHON) \
		--only-binary :all: -r requirements-lambda.txt --quiet
	@if find "$(LAMBDA_BUILD)" \( -name '*-darwin.so' -o -name '*.dylib' -o -name '*win_amd64*' \) \
		| grep -q .; then \
		echo "lambda-package: host-native binaries in the asset, refusing to ship it"; \
		find "$(LAMBDA_BUILD)" \( -name '*-darwin.so' -o -name '*.dylib' \); \
		exit 1; \
	fi
	@echo "lambda asset built at $(LAMBDA_BUILD) for $(LAMBDA_PLATFORM)"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache cdk.out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
