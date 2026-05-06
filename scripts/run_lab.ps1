# Generates data and reminds next Splunk step.

$OutputPath = Join-Path $PSScriptRoot "..\data\security_events.jsonl"
python (Join-Path $PSScriptRoot "generate_fake_attacks.py") --output $OutputPath --seed 42 --days 2
Write-Host "\nDone. In Splunk, ingest: $OutputPath"