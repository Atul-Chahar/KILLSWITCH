"""The agreed module layout exists and imports cleanly."""

import importlib

import pytest

MODULES = [
    "shared",
    "detect",
    "investigate",
    "narrate",
    "verifier",
    "authorize",
    "containment",
    "workflow",
    "infra",
    "infra.stacks",
]


@pytest.mark.parametrize("name", MODULES)
def test_module_imports(name):
    assert importlib.import_module(name) is not None
