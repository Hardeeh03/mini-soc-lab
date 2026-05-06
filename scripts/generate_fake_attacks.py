#!/usr/bin/env python3
"""Generate synthetic security events for a Mini SOC lab.

Outputs newline-delimited JSON (JSONL) that Splunk can ingest as sourcetype mini_soc:json.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


USERS = ["alice", "bob", "charlie", "dana", "svc_backup", "intern"]
HOSTS = ["dc-01", "web-01", "web-02", "db-01", "vpn-01", "helpdesk-01"]
SRC_IPS = [
    "10.0.1.10",
    "10.0.1.11",
    "10.0.1.12",
    "10.0.2.20",
    "10.0.2.21",
    "172.16.5.30",
    "198.51.100.23",
    "203.0.113.70",
    "185.244.25.10",
]
COUNTRIES = ["GB", "US", "DE", "NL", "BR", "NG", "RU", "IN"]


@dataclass
class Event:
    timestamp: str
    event_type: str
    user: str
    src_ip: str
    dest_host: str
    action: str
    status: str
    dest_port: int | None
    protocol: str | None
    country: str
    severity: str
    details: str

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "user": self.user,
            "src_ip": self.src_ip,
            "dest_host": self.dest_host,
            "action": self.action,
            "status": self.status,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "country": self.country,
            "severity": self.severity,
            "details": self.details,
        }


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def add_background(events: list[Event], start: datetime, end: datetime, rng: random.Random) -> None:
    dt = start
    while dt <= end:
        count = rng.randint(2, 6)
        for _ in range(count):
            user = rng.choice(USERS)
            src = rng.choice(SRC_IPS[:6])
            host = rng.choice(HOSTS)
            success = rng.random() > 0.15
            events.append(
                Event(
                    timestamp=iso(dt + timedelta(seconds=rng.randint(0, 50))),
                    event_type="auth",
                    user=user,
                    src_ip=src,
                    dest_host=host,
                    action="login",
                    status="success" if success else "failure",
                    dest_port=443,
                    protocol="tcp",
                    country=rng.choice(["GB", "US", "DE"]),
                    severity="low" if success else "medium",
                    details="Routine interactive authentication",
                )
            )
        dt += timedelta(minutes=8)


def add_failed_login_attack(events: list[Event], t0: datetime, rng: random.Random) -> None:
    attacker_ip = "185.244.25.10"
    target_user = "bob"
    target_host = "vpn-01"

    for i in range(18):
        events.append(
            Event(
                timestamp=iso(t0 + timedelta(seconds=i * 9)),
                event_type="auth",
                user=target_user,
                src_ip=attacker_ip,
                dest_host=target_host,
                action="login",
                status="failure",
                dest_port=443,
                protocol="tcp",
                country="RU",
                severity="high",
                details="Repeated VPN login failure pattern",
            )
        )

    events.append(
        Event(
            timestamp=iso(t0 + timedelta(seconds=18 * 9 + 12)),
            event_type="auth",
            user=target_user,
            src_ip=attacker_ip,
            dest_host=target_host,
            action="login",
            status="success",
            dest_port=443,
            protocol="tcp",
            country="RU",
            severity="critical",
            details="Potential account compromise after brute-force attempts",
        )
    )


def add_port_scan(events: list[Event], t0: datetime, rng: random.Random) -> None:
    scanner_ip = "203.0.113.70"
    target = "web-01"
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 5432, 8080]

    for i, port in enumerate(ports):
        events.append(
            Event(
                timestamp=iso(t0 + timedelta(seconds=i * 4)),
                event_type="network",
                user="-",
                src_ip=scanner_ip,
                dest_host=target,
                action="connection_attempt",
                status="failure" if port not in [80, 443] else "success",
                dest_port=port,
                protocol="tcp",
                country="NG",
                severity="high",
                details="Sequential multi-port probing behavior",
            )
        )


def add_suspicious_powershell(events: list[Event], t0: datetime) -> None:
    events.append(
        Event(
            timestamp=iso(t0),
            event_type="endpoint",
            user="charlie",
            src_ip="10.0.1.12",
            dest_host="helpdesk-01",
            action="process_start",
            status="success",
            dest_port=None,
            protocol=None,
            country="GB",
            severity="high",
            details="powershell.exe -EncodedCommand SQBmACg...",
        )
    )


def add_impossible_travel(events: list[Event], t0: datetime) -> None:
    user = "alice"
    events.extend(
        [
            Event(
                timestamp=iso(t0),
                event_type="auth",
                user=user,
                src_ip="10.0.2.20",
                dest_host="vpn-01",
                action="login",
                status="success",
                dest_port=443,
                protocol="tcp",
                country="GB",
                severity="medium",
                details="Successful login from home office",
            ),
            Event(
                timestamp=iso(t0 + timedelta(minutes=11)),
                event_type="auth",
                user=user,
                src_ip="198.51.100.23",
                dest_host="vpn-01",
                action="login",
                status="success",
                dest_port=443,
                protocol="tcp",
                country="BR",
                severity="high",
                details="Successful login from distant geography shortly after prior login",
            ),
        ]
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate fake SOC events for Splunk lab")
    parser.add_argument("--output", required=True, help="Output JSONL path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--days", type=int, default=2, help="How many days of events")
    args = parser.parse_args()

    rng = random.Random(args.seed)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)

    events: list[Event] = []
    add_background(events, start, end, rng)

    t_attack_1 = start + timedelta(hours=10)
    t_attack_2 = start + timedelta(hours=18, minutes=30)
    t_attack_3 = start + timedelta(hours=25, minutes=20)
    t_attack_4 = start + timedelta(hours=35)

    add_failed_login_attack(events, t_attack_1, rng)
    add_port_scan(events, t_attack_2, rng)
    add_suspicious_powershell(events, t_attack_3)
    add_impossible_travel(events, t_attack_4)

    events.sort(key=lambda e: e.timestamp)

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event.to_dict()))
            f.write("\n")

    print(f"Wrote {len(events)} events to {out}")


if __name__ == "__main__":
    main()