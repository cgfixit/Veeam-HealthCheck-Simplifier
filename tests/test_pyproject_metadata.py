"""Packaging metadata: SPDX license expression, no superseded classifier."""

from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_pyproject_uses_spdx_license_expression_not_classifier() -> None:
    assert 'license = "MIT"' in PYPROJECT
    assert "License :: OSI Approved :: MIT License" not in PYPROJECT
    floor = re.search(r'"setuptools>=(\d+)', PYPROJECT)
    assert floor and int(floor.group(1)) >= 77
