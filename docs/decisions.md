# Décisions de design & trade-offs

## 1. Les EVTX ne sont pas commités
Téléchargés à l'exécution depuis un commit pinné (`tests/manifest.yml`).
Trade-off : la CI dépend de la disponibilité de GitHub raw. Accepté parce que
(a) pas de binaires GPL redistribués, (b) repo léger, (c) le pin SHA garantit
la reproductibilité. Mitigation : cache GitHub Actions clé par commit.

## 2. Validation de déclenchement backend-agnostique (Zircolite)
Le test « la règle déclenche » utilise Zircolite (moteur Sigma local sur EVTX),
pas le backend cible. Aucune dépendance cloud pour valider une détection ;
ajouter un backend (Splunk) ne change pas le harness. Zircolite plutôt que
Chainsaw : Python (cohérent avec le reste du tooling), pinnable par tag git.
Pas sur PyPI → cloné par script pinné (`scripts/setup_zircolite.sh`).
Trade-off : on ne teste pas la requête KQL générée elle-même — une conversion
qui réussit prouve la compatibilité syntaxique, pas le comportement runtime.
Assumé en v1 ; test end-to-end Sentinel possible en v2.

## 3. Validateur ATT&CK désactivé (et pourquoi c'est justifié)
`config/sigma_validation.yml` désactive le seul validateur `attacktag`.
pySigma 1.4.0 embarque un jeu de données ATT&CK « preview » (v19.1) qui renomme
la tactique *Defense Evasion* en `stealth` et ne contient pas certaines
sous-techniques comme T1070.001. Plutôt que d'encoder cette taxonomie preview
dans des règles publiques, on garde les tags conformes à l'ATT&CK publié (ceux
qu'un reviewer SigmaHQ reconnaît) et on désactive ce contrôle sémantique
défaillant. La validation de schéma/structure reste active ; le format des IDs
de technique est vérifié dans `scripts/build_layer.py`.

## 4. Matrice de pipelines KQL par règle
`microsoft_xdr` (tables Device*) pour les catégories Sysmon, `azure_monitor`
(SecurityEvent) pour les événements Security natifs. Un pipeline unique ne
couvre pas les deux mondes ; la matrice est déclarée dans le manifest, à côté
du test — une seule source de vérité par règle. Le pipeline `azure_monitor` ne
sait pas déduire la table SecurityEvent d'une logsource `service: security`, donc
`config/sentinel/security_event_table.yml` la fixe (priorité 5, exécuté avant).

## 5. Règle T1053.005 : Security 4698 → process_creation schtasks
Version initiale : détection sur Security 4698 avec le champ `TaskContent`.
Elle déclenchait dans Zircolite (EVTX brut aplati) mais ne convertissait pas :
`TaskContent` n'est pas une colonne de la table Sentinel `SecurityEvent`.
Décision : reformuler en `process_creation` de `schtasks.exe /create` avec
payload suspect. Plus portable, convertit proprement vers DeviceProcessEvents,
et déclenche sur un vrai sample Sysmon. Leçon documentée : une détection doit
vivre sur le chemin de log qui correspond à sa table backend.

## 6. Ordre des étapes CI
Lint → conversion → tests de détection → SAST/audit → layer. Du moins cher au
plus cher : une règle mal formée ne déclenche ni téléchargement d'EVTX ni scan.

## 7. Findings de sécurité traités, pas masqués
- Bandit B404 (import subprocess) : bruit d'import, couvert par B603 → skip ciblé
  dans `.bandit`. B603 (subprocess) : argv en liste, pas de shell, entrées internes
  → `# nosec B603` justifié. B310 (urlopen) : scheme forcé à https + host/commit
  constants → `# nosec B310` justifié.
- pip-audit PYSEC-2026-2447 (diskcache 5.6.3) : dépendance transitive de pySigma,
  aucune version corrigée publiée ; utilisée seulement comme cache local de données
  ATT&CK au build. Ignorée nommément (`--ignore-vuln`) ; tout autre vuln fait
  échouer la CI.

## 8. Swaps v1 dictés par les samples
Certaines règles de l'inventaire initial ont été remplacées faute d'EVTX de
référence disponible (certutil, vssadmin, fodhelper, PowerShell -enc). Principe :
une règle sans preuve de déclenchement ne rentre pas dans le repo. Les techniques
écartées reviendront en v2 avec des logs générés en lab.
