"""Run the SEC-04 ARP poisoning comparison from a terminal."""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable

from conecolab_security import ScenarioResult, compare_defense, run_arp_poisoning_scenario


def print_result(result: ScenarioResult, *, show_events: bool) -> None:
    label = "防御あり" if result.defense_enabled else "防御なし"
    print(f"\n=== {label} ===")
    print(json.dumps(result.summary(), ensure_ascii=False, indent=2))
    if not show_events:
        return

    print("\n--- event timeline ---")
    for event in result.events:
        data = json.dumps(dict(event.data), ensure_ascii=False, sort_keys=True)
        print(f"{event.sequence:02d} {event.kind:<20} {event.actor:<22} {event.message} {data}")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the deterministic in-memory ARP poisoning teaching scenario."
    )
    parser.add_argument(
        "--mode",
        choices=("unprotected", "protected", "compare"),
        default="compare",
    )
    parser.add_argument(
        "--events",
        action="store_true",
        help="print the complete event timeline",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    if args.mode == "unprotected":
        results = (run_arp_poisoning_scenario(defense_enabled=False),)
    elif args.mode == "protected":
        results = (run_arp_poisoning_scenario(defense_enabled=True),)
    else:
        results = compare_defense()

    for result in results:
        print_result(result, show_events=args.events)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
