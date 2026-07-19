from conecolab_security.arp_lab import (
    ATTACKER_MAC,
    GATEWAY_MAC,
    VICTIM_MAC,
    compare_defense,
    run_arp_poisoning_scenario,
)


def test_unprotected_host_is_poisoned_but_service_remains_available() -> None:
    result = run_arp_poisoning_scenario(defense_enabled=False)

    assert result.baseline_delivered is True
    assert result.attack_succeeded is True
    assert result.service_available_after_attack is True
    assert result.victim_gateway_mac == ATTACKER_MAC
    assert result.gateway_victim_mac == ATTACKER_MAC
    assert result.intercepted_payloads == ("after-poisoning",)
    assert result.detection_alerts >= 2
    assert result.rejected_arp_updates == 0


def test_static_binding_guard_rejects_both_forged_claims() -> None:
    result = run_arp_poisoning_scenario(defense_enabled=True)

    assert result.baseline_delivered is True
    assert result.attack_succeeded is False
    assert result.service_available_after_attack is True
    assert result.victim_gateway_mac == GATEWAY_MAC
    assert result.gateway_victim_mac == VICTIM_MAC
    assert result.intercepted_payloads == ()
    assert result.detection_alerts >= 2
    assert result.rejected_arp_updates == 2


def test_timeline_is_deterministic_and_sequence_numbers_are_contiguous() -> None:
    first = run_arp_poisoning_scenario(defense_enabled=False)
    second = run_arp_poisoning_scenario(defense_enabled=False)

    assert first.event_rows() == second.event_rows()
    assert [event.sequence for event in first.events] == list(range(1, len(first.events) + 1))
    assert {event.kind for event in first.events} >= {
        "attack.started",
        "arp.cache.updated",
        "detector.alert",
        "data.intercepted",
        "data.delivered",
    }


def test_compare_defense_returns_unprotected_then_protected() -> None:
    unprotected, protected = compare_defense()

    assert unprotected.defense_enabled is False
    assert protected.defense_enabled is True
    assert unprotected.attack_succeeded is True
    assert protected.attack_succeeded is False
