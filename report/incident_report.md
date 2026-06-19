# Mini SOC Lab Incident Report

## Executive Summary
During this lab run, multiple simulated adversary behaviors were detected in Splunk:
- Brute-force login activity targeting VPN access
- Reconnaissance via multi-port scanning
- Suspicious encoded PowerShell execution
- Impossible-travel authentication pattern

The detections show how correlated log patterns can identify likely account compromise, pre-exploitation reconnaissance, and potentially malicious script execution.

## What Happened

### 1) Brute-force + likely compromise
- Source IP `185.244.25.10` generated repeated failed VPN login attempts for user `bob` on host `vpn-01`.
- After a burst of failures, a successful login from the same source occurred.
- This pattern strongly indicates password guessing followed by valid credential use.

### 2) Port scanning reconnaissance
- Source IP `203.0.113.70` attempted connections to many ports on `web-01` within a short time window.
- Ports included administrative and database services (`22`, `445`, `3306`, `5432`, `3389`).
- This is consistent with attacker host/service discovery.

### 3) Suspicious PowerShell command execution
- User `charlie` on `helpdesk-01` launched PowerShell with an encoded command.
- Encoded PowerShell is a common defense-evasion and payload delivery technique.
- Requires immediate analyst validation against change windows and admin activity.

### 4) Impossible travel login anomaly
- User `alice` logged in successfully from `GB`, then from `BR` roughly 11 minutes later.
- This exceeds plausible travel time and indicates either credential sharing, VPN masking, or compromise.

## How It Was Detected

### Data Source
- Splunk ingest from `mini-soc-lab/data/security_events.jsonl`
- Sourcetype: `mini_soc:json`

### Detection Logic
- Brute force: threshold on failed auth count per user/src/host in 5-minute buckets.
- Port scan: distinct destination port count threshold per source/target in 2-minute buckets.
- Encoded PowerShell: keyword match `EncodedCommand` in process details.
- Impossible travel: sequential successful logins by user from different countries within <= 60 minutes.

### Alerting
- Scheduled alerts configured with trigger condition `results > 0`.
- Severity mapped by tactic impact:
  - Critical: encoded PowerShell
  - High: brute force + scan
  - Medium/High: impossible travel

## What It Means

### Security Impact
- The brute-force sequence represents probable initial access.
- Port scanning suggests recon prior to exploitation attempts.
- Encoded scripting indicates potential execution/persistence steps.
- Impossible travel signals compromised or misused credentials.

### SOC Actions Recommended
1. Disable/reset affected accounts (`bob`, `alice`) and force MFA re-registration.
2. Block/monitor suspicious IPs (`185.244.25.10`, `203.0.113.70`).
3. Isolate and triage `helpdesk-01` for malicious process lineage.
4. Hunt for lateral movement from `vpn-01` and `helpdesk-01`.
5. Tighten detections with allow-lists for approved admin scripts and known VPN egress IPs.

## MITRE ATT&CK Mapping (High-level)
- Brute force: T1110
- Port scan/recon: T1046
- PowerShell abuse: T1059.001
- Valid accounts / credential misuse: T1078

## Lab Limitations
- Data is synthetic and controlled.
- No endpoint telemetry enrichment (parent process hash, command line lineage, EDR verdict).
- No threat intel correlation feed in this baseline.

## Conclusion
The mini SOC pipeline successfully demonstrates end-to-end detection engineering: event simulation, log ingestion, rule creation, alerting, and analyst-focused reporting.

## Automated Triage Outcome

Brute-force activity from `185.244.25.10` is escalated by the SOAR simulation because the source IP matches the known malicious brute-force indicator from this report. The pipeline creates a high-priority ticket, recommends account reset or lockout for `bob`, and prints a mock Slack notification for analyst handoff.

Port scanning from `203.0.113.70` is escalated because the source IP matches the known malicious reconnaissance indicator. The generated ticket recommends blocking or monitoring the source IP, reviewing exposed services on `web-01`, and checking for follow-on exploit attempts.

Encoded PowerShell execution by `charlie` on `helpdesk-01` is escalated even though the source IP is clean in mock reputation. The alert details include `EncodedCommand`, so the pipeline treats it as high signal and recommends endpoint investigation, process history review, and command-line evidence collection.

Impossible travel activity for `alice` is escalated because the alert severity is high and the login pattern requires identity validation. The pipeline recommends user verification, MFA challenge or password reset if the activity is unconfirmed, and review of recent sessions and VPN access history.
