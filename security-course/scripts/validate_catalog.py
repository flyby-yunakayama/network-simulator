"""Validate catalog IDs, states, and artifact traceability."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = PROJECT_ROOT / "catalog.json"
VALID_STATUSES = {"planned", "specified", "prototype", "draft", "review", "ready"}
REQUIRED_PROTOTYPE_ARTIFACTS = {"spec", "manuscript", "notebook", "scenario", "tests"}
CHAPTER_ID_PATTERN = re.compile(r"^SEC-\d{2}$")


def iter_paths(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    raise TypeError(f"artifact value must be a path or list of paths, got: {value!r}")


def validate() -> list[str]:
    errors: list[str] = []
    try:
        catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"catalog.json could not be read: {exc}"]

    if catalog.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    chapters = catalog.get("chapters")
    if not isinstance(chapters, list) or not chapters:
        return errors + ["chapters must be a non-empty list"]

    seen_ids: set[str] = set()
    for index, chapter in enumerate(chapters):
        prefix = f"chapters[{index}]"
        if not isinstance(chapter, dict):
            errors.append(f"{prefix} must be an object")
            continue

        chapter_id = chapter.get("id")
        if not isinstance(chapter_id, str) or not CHAPTER_ID_PATTERN.fullmatch(chapter_id):
            errors.append(f"{prefix}.id must match SEC-00")
            continue
        if chapter_id in seen_ids:
            errors.append(f"duplicate chapter id: {chapter_id}")
        seen_ids.add(chapter_id)

        if not isinstance(chapter.get("title"), str) or not chapter["title"].strip():
            errors.append(f"{chapter_id}: title must be non-empty")

        outcomes = chapter.get("learning_outcomes")
        if (
            not isinstance(outcomes, list)
            or not outcomes
            or not all(isinstance(outcome, str) and outcome.strip() for outcome in outcomes)
        ):
            errors.append(f"{chapter_id}: learning_outcomes must contain non-empty strings")

        status = chapter.get("status")
        if status not in VALID_STATUSES:
            errors.append(f"{chapter_id}: unsupported status {status!r}")

        artifacts = chapter.get("artifacts", {})
        if not isinstance(artifacts, dict):
            errors.append(f"{chapter_id}: artifacts must be an object")
            continue

        if status in {"prototype", "draft", "review", "ready"}:
            missing_keys = sorted(REQUIRED_PROTOTYPE_ARTIFACTS - artifacts.keys())
            if missing_keys:
                errors.append(f"{chapter_id}: missing artifact keys: {', '.join(missing_keys)}")

        for artifact_name, raw_paths in artifacts.items():
            try:
                paths = iter_paths(raw_paths)
            except TypeError as exc:
                errors.append(f"{chapter_id}.{artifact_name}: {exc}")
                continue
            for relative_path in paths:
                path = PROJECT_ROOT / relative_path
                if not path.is_file():
                    errors.append(f"{chapter_id}.{artifact_name}: missing file {relative_path}")

    expected_ids = [f"SEC-{number:02d}" for number in range(16)]
    actual_ids = [chapter.get("id") for chapter in chapters if isinstance(chapter, dict)]
    if actual_ids != expected_ids:
        errors.append("chapters must be ordered continuously from SEC-00 through SEC-15")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("catalog validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("catalog validation passed: 16 chapters, artifact paths are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
