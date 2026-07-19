"""Guard the simulation-only boundary with a simple static import check."""

from __future__ import annotations

import ast
from pathlib import Path

BANNED_IMPORT_ROOTS = {
    "http",
    "httpx",
    "paramiko",
    "requests",
    "scapy",
    "socket",
    "subprocess",
    "urllib",
}


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".", maxsplit=1)[0])
    return roots


def test_runtime_package_has_no_real_network_or_process_primitives() -> None:
    source_root = Path(__file__).resolve().parents[1] / "src" / "conecolab_security"
    violations: dict[str, list[str]] = {}

    for path in sorted(source_root.rglob("*.py")):
        banned = sorted(imported_roots(path) & BANNED_IMPORT_ROOTS)
        if banned:
            violations[str(path.relative_to(source_root))] = banned

    assert violations == {}
