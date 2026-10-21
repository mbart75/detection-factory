# Sentinel backend (KQL)

v1 target: Microsoft Sentinel.
- `process_creation` / `registry_set` / `image_load` rules → pySigma pipeline `microsoft_xdr`
  (DeviceProcessEvents / DeviceRegistryEvents / DeviceImageLoadEvents tables, available
  in Sentinel through the Defender XDR connector).
- Rules on native Security events (1102) → pipeline `azure_monitor` (SecurityEvent table,
  AMA agent). The pipeline cannot infer the SecurityEvent table from the logsource alone,
  so `security_event_table.yml` sets it explicitly, **before** azure_monitor (priority 5).

The pipeline for each rule is declared in `tests/manifest.yml` (`kusto_pipeline` field)
and applied by `scripts/convert_rules.py`. Output goes to `dist/kql/`
(not committed: a build artifact, published by CI).
