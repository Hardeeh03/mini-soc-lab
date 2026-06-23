#!/usr/bin/env python3
"""Simulate SOAR triage for Mini SOC Lab Splunk alerts.

Reads one JSON alert payload, enriches the source IP, and either escalates to a
ticket or auto-closes the alert for analyst review history.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path


KNOWN_BAD_IPS = {
    "185.244.25.10": {
        "category": "brute_force",
        "reason": "Known Mini SOC brute-force source from incident report",
    },
    "203.0.113.70": {
        "category": "port_scan",
        "reason": "Known Mini SOC port-scan source from incident report",
    },
}
HIGH_SIGNAL_DETAILS = ("EncodedCommand", "Potential account compromise")
BASE_DIR = Path(__file__).resolve().parent
TICKETS_DIR = BASE_DIR / "tickets"
AUTO_CLOSED_LOG = BASE_DIR / "auto_closed_log.csv"


def load_alert(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def enrich_ip(src_ip: str) -> dict:
    vt_api_key = os.getenv("VT_API_KEY")
    reputation = KNOWN_BAD_IPS.get(src_ip)

    if reputation:
        verdict = "malicious"
        score = 95
        reason = reputation["reason"]
        category = reputation["category"]
    else:
        verdict = "clean"
        score = 5
        reason = "No mock threat-intel hit"
        category = "none"

    return {
        "provider": "mock_virustotal",
        "lookup_ready": bool(vt_api_key),
        "src_ip": src_ip,
        "verdict": verdict,
        "score": score,
        "category": category,
        "reason": reason,
        "vt_api_key_env": "VT_API_KEY",
    }


def decide_severity(alert: dict, reputation: dict) -> dict:
    alert_name = alert.get("alert_name", "Unknown Alert")
    details = alert.get("details", "")
    severity = alert.get("severity", "low")

    reasons = []
    if reputation["verdict"] == "malicious":
        reasons.append("source IP matched mock malicious reputation")
    if severity in {"high", "critical"}:
        reasons.append(f"event severity is {severity}")
    if any(signal in details for signal in HIGH_SIGNAL_DETAILS):
        reasons.append("details contain high-signal execution or compromise text")

    if reasons:
        return {
            "decision": "escalate",
            "priority": "critical" if severity == "critical" else "high",
            "reasons": reasons,
        }

    return {
        "decision": "auto_close",
        "priority": "low",
        "reasons": ["clean IP reputation and no high-risk escalation conditions"],
    }


def ticket_id(alert: dict) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    safe_name = alert.get("alert_name", "alert").lower().replace(" ", "-")
    return f"SOAR-{stamp}-{safe_name}"


def escalate(alert: dict, reputation: dict, decision: dict) -> Path:
    TICKETS_DIR.mkdir(parents=True, exist_ok=True)
    identifier = ticket_id(alert)
    ticket = {
        "ticket_id": identifier,
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "open",
        "priority": decision["priority"],
        "alert": alert,
        "ip_reputation": reputation,
        "decision_reasons": decision["reasons"],
        "recommended_actions": recommended_actions(alert),
    }

    out = TICKETS_DIR / f"{identifier}.json"
    with out.open("w", encoding="utf-8") as f:
        json.dump(ticket, f, indent=2)
        f.write("\n")

    print(
        "[mock-slack] "
        f"{decision['priority'].upper()} alert escalated: {alert.get('alert_name')} "
        f"from {alert.get('src_ip')} on {alert.get('dest_host')} -> {identifier}"
    )
    print(f"Ticket written: {out}")
    return out


def recommended_actions(alert: dict) -> list[str]:
    alert_name = alert.get("alert_name", "")
    user = alert.get("user", "-")
    src_ip = alert.get("src_ip", "-")
    dest_host = alert.get("dest_host", "-")

    if alert_name == "Excessive Failed Logins":
        return [
            f"Reset or lock user account {user}",
            f"Block or monitor source IP {src_ip}",
            f"Review VPN logs for successful access to {dest_host}",
        ]
    if alert_name == "Port Scan Detected":
        return [
            f"Block or rate-limit source IP {src_ip}",
            f"Review exposed services on {dest_host}",
            "Check for follow-on exploit attempts",
        ]
    if alert_name == "Encoded PowerShell Detected":
        return [
            f"Isolate or investigate endpoint {dest_host}",
            f"Review process history for user {user}",
            "Collect command line, parent process, and script block logs",
        ]
    if alert_name == "Impossible Travel Login":
        return [
            f"Verify user {user} activity",
            "Force MFA challenge or password reset if unconfirmed",
            "Review recent sessions and VPN access history",
        ]
    return ["Review alert context and validate affected asset"]


def auto_close(alert: dict, reputation: dict, decision: dict) -> Path:
    AUTO_CLOSED_LOG.parent.mkdir(parents=True, exist_ok=True)
    exists = AUTO_CLOSED_LOG.exists()
    with AUTO_CLOSED_LOG.open("a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "closed_at",
                "alert_name",
                "src_ip",
                "dest_host",
                "user",
                "reputation",
                "reason",
            ],
        )
        if not exists:
            writer.writeheader()
        writer.writerow(
            {
                "closed_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
                "alert_name": alert.get("alert_name", "Unknown Alert"),
                "src_ip": alert.get("src_ip", ""),
                "dest_host": alert.get("dest_host", ""),
                "user": alert.get("user", ""),
                "reputation": reputation["verdict"],
                "reason": "; ".join(decision["reasons"]),
            }
        )

    print(
        "[auto-close] "
        f"{alert.get('alert_name')} from {alert.get('src_ip')} closed as low risk"
    )
    print(f"Auto-close log updated: {AUTO_CLOSED_LOG}")
    return AUTO_CLOSED_LOG


def process_alert(path: Path) -> None:
    alert = load_alert(path)
    reputation = enrich_ip(alert.get("src_ip", ""))
    decision = decide_severity(alert, reputation)

    print(f"Alert: {alert.get('alert_name', 'Unknown Alert')}")
    print(f"Source IP: {alert.get('src_ip', '-')}")
    print(f"Reputation: {reputation['verdict']} ({reputation['reason']})")
    print(f"Decision: {decision['decision']} priority={decision['priority']}")

    if decision["decision"] == "escalate":
        escalate(alert, reputation, decision)
    else:
        auto_close(alert, reputation, decision)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Mini SOC SOAR triage pipeline")
    parser.add_argument("--input", required=True, help="Path to JSON alert payload")
    args = parser.parse_args()

    process_alert(Path(args.input))


if __name__ == "__main__":
    main()
