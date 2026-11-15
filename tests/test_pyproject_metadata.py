"""Packaging metadata: SPDX license, single-sourced version, constraints coverage."""

from __future__ import annotations

import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYPROJECT = (ROOT / "pyproject.toml").read_text(encoding="utf-8")


def test_pyproject_uses_spdx_license_expression_not_classifier() -> None:
    assert 'license = "MIT"' in PYPROJECT
    assert "License :: OSI Approved :: MIT License" not in PYPROJECT
    floor = re.search(r'"setuptools>=(\d+)', PYPROJECT)
    assert floor and int(floor.group(1)) >= 77


def test_version_is_single_sourced_from_module() -> None:
    project = tomllib.loads(PYPROJECT)
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "vhc_simplifier.__version__"}
    module = (ROOT / "vhc_simplifier.py").read_text(encoding="utf-8")
    assert re.search(r'^__version__ = "\d+\.\d+\.\d+"$', module, re.MULTILINE)


def test_constraints_pin_every_declared_dependency() -> None:
    project = tomllib.loads(PYPROJECT)
    declared = list(project["project"]["dependencies"])
    for extra in project["project"]["optional-dependencies"].values():
        declared += extra
    for group in project["dependency-groups"].values():
        declared += group
    names = {re.split(r"[\s\[<>=!~;]", req, maxsplit=1)[0].lower() for req in declared}
    names.discard("vhc-simplifier")
    constraints = (ROOT / "constraints.txt").read_text(encoding="utf-8")
    pinned = {m.group(1).lower() for m in re.finditer(r"^([A-Za-z0-9._-]+)==", constraints, re.MULTILINE)}
    assert names <= pinned, sorted(names - pinned)
