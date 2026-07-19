"""CONECOLAB network-security course prototype."""

from conecolab_security.arp_lab import (
    ScenarioResult,
    compare_defense,
    run_arp_poisoning_scenario,
)

__version__ = "0.1.0"

__all__ = [
    "ScenarioResult",
    "compare_defense",
    "run_arp_poisoning_scenario",
]
