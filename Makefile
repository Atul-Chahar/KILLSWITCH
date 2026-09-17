VENV := .venv
BIN := $(VENV)/bin
LAMBDA_BUILD := build/lambda
LAMBDA_MODULES := detect investigate narrate verifier authorize containment shared workflow

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
# runtime does not already carry. boto3 is provided by the runtime; pydantic is not.
lambda-package:
	rm -rf "$(LAMBDA_BUILD)"
	mkdir -p "$(LAMBDA_BUILD)"
	cp -r $(LAMBDA_MODULES) "$(LAMBDA_BUILD)/"
	uv pip install --python $(BIN)/python --target "$(LAMBDA_BUILD)" -r requirements-lambda.txt --quiet
	@echo "lambda asset built at $(LAMBDA_BUILD)"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache cdk.out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
