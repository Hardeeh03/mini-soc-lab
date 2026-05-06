# Field Extraction Notes (`mini_soc:json`)

Because events are JSON, Splunk automatically extracts most fields.

Recommended sourcetype settings (Settings -> Source types -> mini_soc:json):
- `INDEXED_EXTRACTIONS = json`
- `TIMESTAMP_FIELDS = timestamp`
- `TIME_FORMAT = %Y-%m-%dT%H:%M:%S%z`
- `TRUNCATE = 0`

If your timestamps are not parsed correctly, verify `_time` aligns with `timestamp`.