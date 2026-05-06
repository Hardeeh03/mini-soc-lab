# Mini SOC Lab

A hands-on blue-team project using Splunk to detect simulated attacks.

## Goals
- Generate realistic security events (failed logins, port scan, brute force, suspicious PowerShell, impossible travel).
- Ingest logs into Splunk.
- Build detections and alerts.
- Document what happened, how it was detected, and what it means.

## Project Structure
- `data/security_events.jsonl` : simulated raw events
- `scripts/generate_fake_attacks.py` : event generator
- `scripts/run_lab.ps1` : one-command local pipeline
- `splunk/inputs.conf` : file monitoring input
- `splunk/sourcetype_transforms.md` : parsing/field extraction notes
- `splunk/detections.spl` : detection searches
- `splunk/alerts_setup.md` : alert creation steps
- `report/incident_report.md` : completed SOC-style findings report

## Quick Start
1. Install Splunk Enterprise (single instance).
2. Ensure Python 3.10+ is available.
3. Generate sample attacks:
   ```powershell
   python .\scripts\generate_fake_attacks.py --output .\data\security_events.jsonl --seed 42
   ```
4. In Splunk:
   - Add Data -> Monitor Files & Directories
   - Path: absolute path to `data/security_events.jsonl`
   - Sourcetype: `mini_soc:json`
   - Index: `main` (or `soc_lab` if you created one)
5. Run detections from `splunk/detections.spl`.
6. Configure alerts with `splunk/alerts_setup.md`.
7. Review report in `report/incident_report.md`.

## Optional: Re-run with fresh timeline
```powershell
python .\scripts\generate_fake_attacks.py --output .\data\security_events.jsonl --seed 99 --days 1
```
Then in Splunk set time picker to `Last 24 hours`.