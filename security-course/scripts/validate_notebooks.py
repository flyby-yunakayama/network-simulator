"""Perform dependency-free structural checks on committed notebooks."""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NOTEBOOK_ROOT = PROJECT_ROOT / "notebooks"


def validate_notebook(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        notebook = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{path.name}: could not parse JSON: {exc}"]

    if notebook.get("nbformat") != 4:
        errors.append(f"{path.name}: nbformat must be 4")

    cells = notebook.get("cells")
    if not isinstance(cells, list) or not cells:
        return errors + [f"{path.name}: cells must be a non-empty list"]

    for index, cell in enumerate(cells):
        prefix = f"{path.name}: cell {index}"
        if cell.get("cell_type") not in {"markdown", "code", "raw"}:
            errors.append(f"{prefix}: unsupported cell_type")
        if not isinstance(cell.get("source"), list):
            errors.append(f"{prefix}: source must be a list of strings")
        if cell.get("cell_type") == "code":
            if cell.get("execution_count") is not None:
                errors.append(f"{prefix}: execution_count must be null")
            if cell.get("outputs") not in ([], None):
                errors.append(f"{prefix}: committed outputs must be empty")

    return errors


def main() -> int:
    notebooks = sorted(NOTEBOOK_ROOT.glob("*.ipynb"))
    if not notebooks:
        print("notebook validation failed: no notebooks found")
        return 1

    errors = [error for path in notebooks for error in validate_notebook(path)]
    if errors:
        print("notebook validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1

    print(f"notebook validation passed: {len(notebooks)} notebook(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
