# Backend Sentinel (KQL)

Cible v1 : Microsoft Sentinel.
- Règles `process_creation` / `registry_set` / `image_load` → pipeline pySigma `microsoft_xdr`
  (tables DeviceProcessEvents / DeviceRegistryEvents / DeviceImageLoadEvents, disponibles
  dans Sentinel via le connecteur Defender XDR).
- Règles sur événements Security natifs (1102) → pipeline `azure_monitor` (table SecurityEvent,
  agent AMA). Le pipeline ne peut pas déduire la table SecurityEvent depuis la seule logsource,
  donc `security_event_table.yml` la fixe explicitement **avant** azure_monitor (priorité 5).

Le mapping par règle est déclaré dans `tests/manifest.yml` (champ `kusto_pipeline`)
et exécuté par `scripts/convert_rules.py`. Sorties générées dans `dist/kql/`
(non commitées : artefact de build, publié par la CI).
