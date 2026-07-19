"""Validate the source registry and source IDs used by chapter artifacts."""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCES_PATH = PROJECT_ROOT / "references" / "sources.json"
CATALOG_PATH = PROJECT_ROOT / "catalog.json"
SOURCE_ID_PATTERN = re.compile(r"\[([A-Z][A-Z0-9-]{2,})\]")
REQUIRED_FIELDS = {
    "id",
    "title",
    "publisher",
    "url",
    "type",
    "accessed",
    "chapters",
    "notes",
}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def artifact_markdown_files() -> list[Path]:
    paths: list[Path] = []
    for directory in (PROJECT_ROOT / "specs", PROJECT_ROOT / "manuscript"):
        paths.extend(path for path in sorted(directory.glob("*.md")) if "TEMPLATE" not in path.name)
    paths.append(PROJECT_ROOT / "docs" / "TRACEABILITY.md")
    return paths


def validate() -> list[str]:
    errors: list[str] = []
    try:
        registry = load_json(SOURCES_PATH)
        catalog = load_json(CATALOG_PATH)
    except (OSError, json.JSONDecodeError) as exc:
        return [f"could not read JSON input: {exc}"]

    if registry.get("schema_version") != 1:
        errors.append("references/sources.json: schema_version must be 1")

    sources = registry.get("sources")
    if not isinstance(sources, list) or not sources:
        return errors + ["references/sources.json: sources must be a non-empty list"]

    valid_chapters = {
        chapter.get("id") for chapter in catalog.get("chapters", []) if isinstance(chapter, dict)
    }
    source_ids: set[str] = set()
    for index, source in enumerate(sources):
        prefix = f"sources[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{prefix} must be an object")
            continue

        missing = sorted(REQUIRED_FIELDS - source.keys())
        if missing:
            errors.append(f"{prefix}: missing fields: {', '.join(missing)}")
            continue

        source_id = source["id"]
        if not isinstance(source_id, str) or not re.fullmatch(r"[A-Z][A-Z0-9-]+", source_id):
            errors.append(f"{prefix}.id has an invalid format")
        elif source_id in source_ids:
            errors.append(f"duplicate source id: {source_id}")
        else:
            source_ids.add(source_id)

        for field in ("title", "publisher", "type", "notes"):
            if not isinstance(source[field], str) or not source[field].strip():
                errors.append(f"{prefix}.{field} must be a non-empty string")

        url = source["url"]
        if not isinstance(url, str) or not url.startswith("https://"):
            errors.append(f"{prefix}.url must use https")

        try:
            date.fromisoformat(source["accessed"])
        except (TypeError, ValueError):
            errors.append(f"{prefix}.accessed must be an ISO date")

        chapters = source["chapters"]
        if not isinstance(chapters, list) or not chapters:
            errors.append(f"{prefix}.chapters must be a non-empty list")
        elif not all(chapter == "ALL" or chapter in valid_chapters for chapter in chapters):
            errors.append(f"{prefix}.chapters contains an unknown chapter ID")

    for path in artifact_markdown_files():
        if not path.is_file():
            errors.append(f"missing artifact used for source validation: {path}")
            continue
        referenced = set(SOURCE_ID_PATTERN.findall(path.read_text(encoding="utf-8")))
        unknown = sorted(referenced - source_ids)
        if unknown:
            relative = path.relative_to(PROJECT_ROOT)
            errors.append(f"{relative}: unknown source IDs: {', '.join(unknown)}")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print("reference validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("reference validation passed: source registry and chapter citations are consistent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
