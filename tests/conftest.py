"""Shared test helpers. Scripts live outside a package, so they are loaded by path."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_script(name: str) -> ModuleType:
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"killswitch_script_{name}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def attacker() -> ModuleType:
    return load_script("attacker")


@pytest.fixture(scope="session")
def lookup() -> ModuleType:
    return load_script("lookup")


@pytest.fixture(scope="session")
def capture_fixture() -> ModuleType:
    return load_script("capture_fixture")


@pytest.fixture(scope="session")
def pick_nim_model() -> ModuleType:
    return load_script("pick_nim_model")
