"""Deterministic, simulation-only ARP poisoning teaching model.

No socket, packet capture, OS ARP cache, or external host is used. Every frame,
cache update, alert, and defense decision is represented by Python objects.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
VICTIM_IP = "10.0.0.10"
VICTIM_MAC = "02:00:00:00:00:10"
GATEWAY_IP = "10.0.0.1"
GATEWAY_MAC = "02:00:00:00:00:01"
ATTACKER_IP = "10.0.0.66"
ATTACKER_MAC = "02:00:00:00:00:66"


def normalize_mac(value: str) -> str:
    return value.replace("-", ":").lower()


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    sequence: int
    kind: str
    actor: str
    message: str
    data: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind,
            "actor": self.actor,
            "message": self.message,
            "data": dict(self.data),
        }


class EventLog:
    def __init__(self) -> None:
        self._events: list[SecurityEvent] = []

    @property
    def events(self) -> tuple[SecurityEvent, ...]:
        return tuple(self._events)

    def record(self, kind: str, actor: str, message: str, **data: Any) -> None:
        self._events.append(SecurityEvent(len(self._events) + 1, kind, actor, message, dict(data)))


@dataclass(frozen=True, slots=True)
class ArpMessage:
    operation: Literal["request", "reply"]
    sender_ip: str
    sender_mac: str
    target_ip: str
    target_mac: str
    unsolicited: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "sender_mac", normalize_mac(self.sender_mac))
        object.__setattr__(self, "target_mac", normalize_mac(self.target_mac))


@dataclass(frozen=True, slots=True)
class DataFrame:
    source_ip: str
    destination_ip: str
    source_mac: str
    destination_mac: str
    payload: str
    hop: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_mac", normalize_mac(self.source_mac))
        object.__setattr__(self, "destination_mac", normalize_mac(self.destination_mac))


@dataclass(frozen=True, slots=True)
class ArpUpdateDecision:
    accepted: bool
    reason: str


class ArpUpdatePolicy(Protocol):
    def evaluate(self, host: Host, message: ArpMessage) -> ArpUpdateDecision: ...


class AcceptAllArpUpdates:
    def evaluate(self, host: Host, message: ArpMessage) -> ArpUpdateDecision:
        del host, message
        return ArpUpdateDecision(True, "permissive policy")


@dataclass(slots=True)
class StaticBindingGuard:
    """Reject claims that contradict configured IP-to-MAC bindings."""

    trusted_bindings: Mapping[str, str]

    def __post_init__(self) -> None:
        self.trusted_bindings = {
            ip: normalize_mac(mac) for ip, mac in self.trusted_bindings.items()
        }

    def evaluate(self, host: Host, message: ArpMessage) -> ArpUpdateDecision:
        del host
        expected = self.trusted_bindings.get(message.sender_ip)
        if expected is None:
            return ArpUpdateDecision(True, "outside protected binding set")
        if expected == message.sender_mac:
            return ArpUpdateDecision(True, "claim matches trusted binding")
        return ArpUpdateDecision(
            False,
            f"trusted binding requires {message.sender_ip} -> {expected}",
        )


@dataclass(frozen=True, slots=True)
class ArpConflictAlert:
    ip_address: str
    known_macs: tuple[str, ...]
    observed_actor: str


class ArpConflictDetector:
    """Alert once for each newly observed IP-to-multiple-MAC conflict set."""

    def __init__(self, log: EventLog) -> None:
        self.log = log
        self._claims: dict[str, set[str]] = {}
        self._fingerprints: set[tuple[str, tuple[str, ...]]] = set()
        self.alerts: list[ArpConflictAlert] = []

    def observe(self, message: ArpMessage, actor: str) -> None:
        claims = self._claims.setdefault(message.sender_ip, set())
        claims.add(message.sender_mac)
        if len(claims) < 2:
            return
        known_macs = tuple(sorted(claims))
        fingerprint = (message.sender_ip, known_macs)
        if fingerprint in self._fingerprints:
            return
        self._fingerprints.add(fingerprint)
        self.alerts.append(ArpConflictAlert(message.sender_ip, known_macs, actor))
        self.log.record(
            "detector.alert",
            "arp-conflict-detector",
            "同じIPアドレスについて複数のMACアドレスを観測した",
            ip_address=message.sender_ip,
            known_macs=list(known_macs),
            observed_actor=actor,
        )


@dataclass(slots=True)
class Host:
    name: str
    ip_address: str
    mac_address: str
    log: EventLog
    policy: ArpUpdatePolicy = field(default_factory=AcceptAllArpUpdates)
    forwarding: bool = False
    arp_table: dict[str, str] = field(default_factory=dict)
    received_payloads: list[str] = field(default_factory=list)
    intercepted_payloads: list[str] = field(default_factory=list)
    rejected_arp_updates: int = 0
    network: SimulatedLan | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        self.mac_address = normalize_mac(self.mac_address)

    def attach(self, network: SimulatedLan) -> None:
        self.network = network

    def _lan(self) -> SimulatedLan:
        if self.network is None:
            raise RuntimeError(f"host {self.name!r} is not attached")
        return self.network

    def learn_arp(self, message: ArpMessage) -> bool:
        decision = self.policy.evaluate(self, message)
        if not decision.accepted:
            self.rejected_arp_updates += 1
            self.log.record(
                "arp.cache.rejected",
                self.name,
                "ARPキャッシュの更新を拒否した",
                sender_ip=message.sender_ip,
                sender_mac=message.sender_mac,
                reason=decision.reason,
            )
            return False
        previous = self.arp_table.get(message.sender_ip)
        self.arp_table[message.sender_ip] = message.sender_mac
        self.log.record(
            "arp.cache.confirmed" if previous == message.sender_mac else "arp.cache.updated",
            self.name,
            "ARPキャッシュを更新した",
            sender_ip=message.sender_ip,
            sender_mac=message.sender_mac,
            previous_mac=previous,
            unsolicited=message.unsolicited,
            reason=decision.reason,
        )
        return True

    def receive_arp(self, message: ArpMessage) -> None:
        self.log.record(
            "arp.received",
            self.name,
            "ARPメッセージを受信した",
            operation=message.operation,
            sender_ip=message.sender_ip,
            sender_mac=message.sender_mac,
            target_ip=message.target_ip,
            unsolicited=message.unsolicited,
        )
        self.learn_arp(message)
        if message.operation == "request" and message.target_ip == self.ip_address:
            self.send_arp_reply(message.sender_ip, message.sender_mac)

    def send_arp_request(self, target_ip: str) -> None:
        self._lan().transmit_arp(
            ArpMessage(
                "request",
                self.ip_address,
                self.mac_address,
                target_ip,
                BROADCAST_MAC,
            ),
            self,
        )

    def send_arp_reply(
        self,
        target_ip: str,
        target_mac: str,
        *,
        claimed_ip: str | None = None,
        claimed_mac: str | None = None,
        unsolicited: bool = False,
    ) -> None:
        self._lan().transmit_arp(
            ArpMessage(
                "reply",
                claimed_ip or self.ip_address,
                claimed_mac or self.mac_address,
                target_ip,
                target_mac,
                unsolicited,
            ),
            self,
        )

    def resolve(self, destination_ip: str) -> str | None:
        if destination_ip not in self.arp_table:
            self.send_arp_request(destination_ip)
        return self.arp_table.get(destination_ip)

    def send_data(self, destination_ip: str, payload: str) -> bool:
        destination_mac = self.resolve(destination_ip)
        if destination_mac is None:
            self.log.record(
                "data.dropped",
                self.name,
                "宛先MACアドレスを解決できないため破棄した",
                destination_ip=destination_ip,
                payload=payload,
                reason="unresolved ARP entry",
            )
            return False
        self._lan().transmit_data(
            DataFrame(
                self.ip_address,
                destination_ip,
                self.mac_address,
                destination_mac,
                payload,
            ),
            self,
        )
        return True

    def receive_data(self, frame: DataFrame) -> None:
        if frame.destination_ip == self.ip_address:
            self.received_payloads.append(frame.payload)
            self.log.record(
                "data.delivered",
                self.name,
                "データを宛先へ配送した",
                source_ip=frame.source_ip,
                payload=frame.payload,
                hop=frame.hop,
            )
            return
        if not self.forwarding:
            self.log.record(
                "data.dropped",
                self.name,
                "自分宛てではないデータを破棄した",
                destination_ip=frame.destination_ip,
                payload=frame.payload,
                reason="forwarding disabled",
            )
            return
        self.intercepted_payloads.append(frame.payload)
        self.log.record(
            "data.intercepted",
            self.name,
            "中継位置でデータを観測した",
            destination_ip=frame.destination_ip,
            payload=frame.payload,
            hop=frame.hop,
        )
        next_mac = self.resolve(frame.destination_ip)
        if next_mac is None:
            self.log.record(
                "data.dropped",
                self.name,
                "中継先を解決できないため破棄した",
                destination_ip=frame.destination_ip,
                payload=frame.payload,
                reason="forwarding resolution failed",
            )
            return
        forwarded = DataFrame(
            frame.source_ip,
            frame.destination_ip,
            self.mac_address,
            next_mac,
            frame.payload,
            frame.hop + 1,
        )
        self.log.record(
            "data.forwarded",
            self.name,
            "観測したデータを本来の宛先へ中継した",
            destination_ip=frame.destination_ip,
            next_mac=next_mac,
            payload=frame.payload,
            hop=forwarded.hop,
        )
        self._lan().transmit_data(forwarded, self)


class SimulatedLan:
    def __init__(self, log: EventLog, detector: ArpConflictDetector) -> None:
        self.log = log
        self.detector = detector
        self._hosts_by_name: dict[str, Host] = {}
        self._hosts_by_mac: dict[str, Host] = {}

    @property
    def hosts(self) -> tuple[Host, ...]:
        return tuple(self._hosts_by_name.values())

    def add_host(self, host: Host) -> None:
        if host.name in self._hosts_by_name or host.mac_address in self._hosts_by_mac:
            raise ValueError("host name and MAC address must be unique")
        self._hosts_by_name[host.name] = host
        self._hosts_by_mac[host.mac_address] = host
        host.attach(self)
        self.log.record(
            "topology.host.added",
            host.name,
            "シミュレータへホストを追加した",
            ip_address=host.ip_address,
            mac_address=host.mac_address,
            forwarding=host.forwarding,
        )

    def transmit_arp(self, message: ArpMessage, sender: Host) -> None:
        self.log.record(
            "arp.sent",
            sender.name,
            "ARPメッセージを送信した",
            operation=message.operation,
            sender_ip=message.sender_ip,
            sender_mac=message.sender_mac,
            target_ip=message.target_ip,
            target_mac=message.target_mac,
            unsolicited=message.unsolicited,
        )
        self.detector.observe(message, sender.name)
        if message.target_mac == BROADCAST_MAC:
            recipients = [host for host in self.hosts if host is not sender]
        else:
            recipient = self._hosts_by_mac.get(message.target_mac)
            recipients = [] if recipient is None else [recipient]
        if not recipients:
            self.log.record(
                "arp.dropped",
                "simulated-lan",
                "ARPメッセージの配送先が存在しない",
                target_mac=message.target_mac,
            )
        for recipient in recipients:
            recipient.receive_arp(message)

    def transmit_data(self, frame: DataFrame, sender: Host) -> None:
        self.log.record(
            "data.sent",
            sender.name,
            "データフレームを送信した",
            source_ip=frame.source_ip,
            destination_ip=frame.destination_ip,
            source_mac=frame.source_mac,
            destination_mac=frame.destination_mac,
            payload=frame.payload,
            hop=frame.hop,
        )
        recipient = self._hosts_by_mac.get(frame.destination_mac)
        if recipient is None:
            self.log.record(
                "data.dropped",
                "simulated-lan",
                "宛先MACアドレスに対応するホストが存在しない",
                destination_mac=frame.destination_mac,
                payload=frame.payload,
                reason="unknown destination MAC",
            )
            return
        recipient.receive_data(frame)


@dataclass(slots=True)
class ArpPoisoningAttack:
    attacker: Host
    victim: Host
    gateway: Host

    def execute(self) -> None:
        if not (
            self.attacker.network is self.victim.network is self.gateway.network
            and self.attacker.network is not None
        ):
            raise ValueError("all actors must share one simulated LAN")
        self.attacker.log.record(
            "attack.started",
            self.attacker.name,
            "ARPキャッシュポイズニングのシミュレーションを開始した",
            victim=self.victim.name,
            gateway=self.gateway.name,
        )
        self.attacker.arp_table[self.victim.ip_address] = self.victim.mac_address
        self.attacker.arp_table[self.gateway.ip_address] = self.gateway.mac_address
        self.attacker.send_arp_reply(
            self.victim.ip_address,
            self.victim.mac_address,
            claimed_ip=self.gateway.ip_address,
            claimed_mac=self.attacker.mac_address,
            unsolicited=True,
        )
        self.attacker.send_arp_reply(
            self.gateway.ip_address,
            self.gateway.mac_address,
            claimed_ip=self.victim.ip_address,
            claimed_mac=self.attacker.mac_address,
            unsolicited=True,
        )
        self.attacker.log.record(
            "attack.completed",
            self.attacker.name,
            "偽装ARPリプライの送信を完了した",
            victim=self.victim.name,
            gateway=self.gateway.name,
        )


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    defense_enabled: bool
    baseline_delivered: bool
    attack_succeeded: bool
    service_available_after_attack: bool
    detection_alerts: int
    rejected_arp_updates: int
    victim_gateway_mac: str | None
    gateway_victim_mac: str | None
    intercepted_payloads: tuple[str, ...]
    gateway_payloads: tuple[str, ...]
    events: tuple[SecurityEvent, ...]

    def summary(self) -> dict[str, Any]:
        return {
            "defense_enabled": self.defense_enabled,
            "baseline_delivered": self.baseline_delivered,
            "attack_succeeded": self.attack_succeeded,
            "service_available_after_attack": self.service_available_after_attack,
            "detection_alerts": self.detection_alerts,
            "rejected_arp_updates": self.rejected_arp_updates,
            "victim_gateway_mac": self.victim_gateway_mac,
            "gateway_victim_mac": self.gateway_victim_mac,
            "intercepted_payloads": list(self.intercepted_payloads),
            "gateway_payloads": list(self.gateway_payloads),
        }

    def event_rows(self) -> list[dict[str, Any]]:
        return [event.as_dict() for event in self.events]


def run_arp_poisoning_scenario(*, defense_enabled: bool = False) -> ScenarioResult:
    log = EventLog()
    detector = ArpConflictDetector(log)
    network = SimulatedLan(log, detector)
    victim_policy: ArpUpdatePolicy = (
        StaticBindingGuard({GATEWAY_IP: GATEWAY_MAC}) if defense_enabled else AcceptAllArpUpdates()
    )
    gateway_policy: ArpUpdatePolicy = (
        StaticBindingGuard({VICTIM_IP: VICTIM_MAC}) if defense_enabled else AcceptAllArpUpdates()
    )
    victim = Host("victim", VICTIM_IP, VICTIM_MAC, log, victim_policy)
    gateway = Host("gateway", GATEWAY_IP, GATEWAY_MAC, log, gateway_policy)
    attacker = Host("attacker", ATTACKER_IP, ATTACKER_MAC, log, forwarding=True)
    for host in (victim, gateway, attacker):
        network.add_host(host)

    log.record("phase.started", "scenario", "正常系の通信を開始した", phase="baseline")
    victim.send_data(GATEWAY_IP, "baseline-message")
    ArpPoisoningAttack(attacker, victim, gateway).execute()
    log.record(
        "phase.started",
        "scenario",
        "攻撃後の通信を開始した",
        phase="post-attack",
    )
    victim.send_data(GATEWAY_IP, "after-poisoning")

    return ScenarioResult(
        defense_enabled=defense_enabled,
        baseline_delivered="baseline-message" in gateway.received_payloads,
        attack_succeeded="after-poisoning" in attacker.intercepted_payloads,
        service_available_after_attack="after-poisoning" in gateway.received_payloads,
        detection_alerts=len(detector.alerts),
        rejected_arp_updates=victim.rejected_arp_updates + gateway.rejected_arp_updates,
        victim_gateway_mac=victim.arp_table.get(GATEWAY_IP),
        gateway_victim_mac=gateway.arp_table.get(VICTIM_IP),
        intercepted_payloads=tuple(attacker.intercepted_payloads),
        gateway_payloads=tuple(gateway.received_payloads),
        events=log.events,
    )


def compare_defense() -> tuple[ScenarioResult, ScenarioResult]:
    return (
        run_arp_poisoning_scenario(defense_enabled=False),
        run_arp_poisoning_scenario(defense_enabled=True),
    )


__all__ = [
    "ATTACKER_IP",
    "ATTACKER_MAC",
    "AcceptAllArpUpdates",
    "ArpConflictAlert",
    "ArpConflictDetector",
    "ArpMessage",
    "ArpPoisoningAttack",
    "ArpUpdateDecision",
    "ArpUpdatePolicy",
    "BROADCAST_MAC",
    "DataFrame",
    "EventLog",
    "GATEWAY_IP",
    "GATEWAY_MAC",
    "Host",
    "ScenarioResult",
    "SecurityEvent",
    "SimulatedLan",
    "StaticBindingGuard",
    "VICTIM_IP",
    "VICTIM_MAC",
    "compare_defense",
    "normalize_mac",
    "run_arp_poisoning_scenario",
]
