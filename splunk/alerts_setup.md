# Splunk Alert Setup Guide

Create alerts from saved searches in `detections.spl`.

## Recommended Alerts

1. `Brute Force Login Detected`
- Search: use query #1
- Schedule: every 5 minutes
- Time range: last 10 minutes
- Trigger: `Number of Results > 0`
- Severity: High
- Action: send email + add to triggered alerts

2. `Port Scan Activity Detected`
- Search: use query #2
- Schedule: every 5 minutes
- Time range: last 10 minutes
- Trigger: `Number of Results > 0`
- Severity: High

3. `Encoded PowerShell Execution`
- Search: use query #3
- Schedule: real-time or every 1 minute
- Trigger: `Number of Results > 0`
- Severity: Critical

4. `Impossible Travel Login`
- Search: use query #4
- Schedule: every 10 minutes
- Time range: last 70 minutes
- Trigger: `Number of Results > 0`
- Severity: Medium/High

## Alert Message Template
Use this in alert description/body:

"Mini SOC Lab Alert: $name$ fired at $trigger_time$.\n\nResult count: $result.count$\nTop fields: user=$result.user$, src_ip=$result.src_ip$, host=$result.dest_host$"

## Dashboard Suggestion
Build a `Mini SOC Overview` dashboard panel set:
- Events over time by severity
- Top source IPs by failures
- Top scanned destination hosts
- Last 20 high/critical events table