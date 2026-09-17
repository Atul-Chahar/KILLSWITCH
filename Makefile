VENV := .venv
BIN := $(VENV)/bin

.PHONY: install test lint typecheck secrets check fmt clean

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

check: secrets lint typecheck test

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache cdk.out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
