# SOAR Triage Simulation

This directory adds a lightweight SOAR-style triage layer on top of the Splunk Mini SOC Lab. It simulates what happens after a Splunk alert fires: enrichment, decisioning, escalation, and auto-closure.

## Architecture

```text
+------------------+     +------------------+     +------------------+
| Splunk Alert     | --> | SOAR Webhook     | --> | IP Enrichment    |
| JSON Payload     |     | triage_pipeline  |     | mock VirusTotal  |
+------------------+     +------------------+     +------------------+
                                                        |
                                                        v
                                               +------------------+
                                               | Decision Logic   |
                                               | escalate/close   |
                                               +------------------+
                                                  |            |
                                                  v            v
                                      +------------------+  +------------------+
                                      | Ticket JSON      |  | Auto-close CSV   |
                                      | Mock Slack msg   |  | Analyst history  |
                                      +------------------+  +------------------+
```

## Real Shuffle Workflow Mapping

The same logic could be implemented in Shuffle as:

```text
Webhook -> VirusTotal node -> Condition -> Ticket/Slack
```

- Webhook: receives the Splunk alert JSON payload.
- VirusTotal node: looks up `src_ip` using an API key.
- Condition: checks malicious reputation, severity, and alert type.
- Ticket/Slack: creates an incident ticket and sends a team notification.

The Python script already checks for `VT_API_KEY` in the environment so a real VirusTotal lookup can be added later without changing the alert payload format. `enrich_ip` itself is fully mocked today — `lookup_ready` only reports whether the env var is set, it does not gate or change the reputation lookup, which always comes from the static `KNOWN_BAD_IPS` table.

## Run Commands

Run from the repository root:

```powershell
python .\soar\triage_pipeline.py --input .\soar\sample_alerts\excessive_failed_logins.json
python .\soar\triage_pipeline.py --input .\soar\sample_alerts\port_scan_detected.json
python .\soar\triage_pipeline.py --input .\soar\sample_alerts\encoded_powershell_detected.json
python .\soar\triage_pipeline.py --input .\soar\sample_alerts\impossible_travel_login.json
```

Output locations:

- Escalated tickets: `soar/tickets/`
- Auto-closed history: `soar/auto_closed_log.csv`

## Tests

```powershell
python -m pip install pytest
python -m pytest soar/test_triage_pipeline.py -q
```

## Expected Results

| Sample alert | Source IP | Mock reputation | Decision | Output |
| --- | --- | --- | --- | --- |
| Excessive Failed Logins | `185.244.25.10` | malicious | escalate | Ticket JSON + mock Slack message |
| Port Scan Detected | `203.0.113.70` | malicious | escalate | Ticket JSON + mock Slack message |
| Encoded PowerShell Detected | `10.0.1.12` | clean | escalate | Ticket JSON + mock Slack message |
| Impossible Travel Login | `198.51.100.23` | clean | auto_close | `soar/auto_closed_log.csv` entry |

## Decision Notes

- Known bad IPs from `report/incident_report.md` are escalated automatically.
- Encoded PowerShell escalates even with a clean IP because the command details are high signal.
- Impossible travel auto-closes in this sample because the source IP is clean and no high-signal keyword is present.
- Clean, medium/low-severity alerts without high-signal indicators are auto-closed to `soar/auto_closed_log.csv`.
