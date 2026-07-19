"""Ensure every chapter requirement ID appears in the traceability matrix."""

from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRACEABILITY_PATH = PROJECT_ROOT / "docs" / "TRACEABILITY.md"
REQUIREMENT_PATTERN = re.compile(r"SEC\d{2}-(?:LO|FR|NFR|AC)-\d{2}")
REQUIRED_GROUPS = {"LO", "FR", "NFR", "AC"}


def chapter_specs() -> list[Path]:
    return [
        path
        for path in sorted((PROJECT_ROOT / "specs").glob("SEC-*.md"))
        if "TEMPLATE" not in path.name
    ]


def validate() -> list[str]:
    errors: list[str] = []
    if not TRACEABILITY_PATH.is_file():
        return ["docs/TRACEABILITY.md is missing"]

    traceability_text = TRACEABILITY_PATH.read_text(encoding="utf-8")
    traceability_ids = set(REQUIREMENT_PATTERN.findall(traceability_text))
    specification_ids: set[str] = set()

    specs = chapter_specs()
    if not specs:
        return ["no chapter specifications found"]

    for path in specs:
        text = path.read_text(encoding="utf-8")
        ids = set(REQUIREMENT_PATTERN.findall(text))
        if not ids:
            errors.append(f"{path.name}: no requirement IDs found")
            continue

        specification_ids.update(ids)
        # SEC04 is the compact prefix used by requirement IDs for chapter SEC-04.
        chapter_prefixes = {requirement_id.split("-", maxsplit=1)[0] for requirement_id in ids}
        if len(chapter_prefixes) != 1:
            errors.append(f"{path.name}: requirement IDs use multiple chapter prefixes")

        groups = {requirement_id.split("-")[1] for requirement_id in ids}
        missing_groups = sorted(REQUIRED_GROUPS - groups)
        if missing_groups:
            errors.append(f"{path.name}: missing requirement groups: {', '.join(missing_groups)}")

        missing_from_matrix = sorted(ids - traceability_ids)
        if missing_from_matrix:
            errors.append(
                f"{path.name}: IDs missing from TRACEABILITY.md: {', '.join(missing_from_matrix)}"
            )

    orphaned = sorted(traceability_ids - specification_ids)
    if orphaned:
        errors.append(
            "TRACEABILITY.md contains IDs absent from chapter specs: " + ", ".join(orphaned)
        )

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("traceability validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("traceability validation passed: all requirement IDs are mapped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
