# Design decisions and trade-offs

## 1. EVTX samples are not committed
They are downloaded at test time from a pinned commit (`tests/manifest.yml`).
Trade-off: CI depends on GitHub raw being available. Accepted because
(a) no third-party binaries are redistributed, (b) the repo stays small, and
(c) a commit SHA fixes the content of every file, so results are reproducible.
Mitigation: the GitHub Actions cache is keyed on the hash of the manifest, so
changing the pinned commit or a sample invalidates it and tests never run
against stale logs.

## 2. Backend-agnostic firing tests (Zircolite)
The "the rule fires" test uses Zircolite, a local Sigma engine that runs on
EVTX files, not the target backend. Proving a detection needs no cloud
dependency, and adding a backend (Splunk, say) does not change the harness.
Zircolite rather than Chainsaw: Python, consistent with the rest of the
tooling. It is not on PyPI, so `scripts/setup_zircolite.sh` fetches it at a
pinned commit.
Trade-off: the generated KQL itself is not executed. A successful conversion
proves syntactic compatibility, not runtime behaviour in Sentinel. Accepted
for v1; an end-to-end Sentinel test is possible in v2.

## 3. ATT&CK tags are validated offline, against a pinned release
`config/sigma_validation.yml` disables pySigma's `attacktag` validator (and
`d3_fendtag`, unused here). Both download reference data from moving sources
at run time: ATT&CK from the master branch of `mitre-attack/attack-stix-data`,
D3FEND from d3fend.mitre.org. A release upstream could change the result of
the lint stage with no change in this repository, which breaks the rule that
every input of the pipeline is pinned.

**Compensating control**: `scripts/build_layer.py` checks every tag against
`config/attack/enterprise-attack.json`, a small extract of one ATT&CK release
(v20.0), produced by `scripts/update_attack_data.py` with a SHA-256 check of
the official STIX bundle. The build fails on a missing or malformed tag, an
unknown, revoked or deprecated technique, an unknown tactic, or a tactic that
none of the rule's techniques belongs to. Moving to a new ATT&CK release is a
deliberate, reviewed change: bump the version, regenerate, read the diff.

**Correction (October 2026).** The July version of this decision said pySigma
bundled a "preview" ATT&CK taxonomy. That was wrong: ATT&CK v19 had been the
published release since 28 April 2026, and pySigma downloads it rather than
bundling it. The validator was right. The rules were tagged against the
pre-v19 taxonomy, with the old underscore tag convention
(`attack.defense_evasion`). v19 split Defense Evasion into Stealth and Defense
Impairment and revoked T1070.001 in favour of T1685.005. The rules now follow
ATT&CK v20, and pySigma's own validator, run against the live data, agrees
with the offline check.

## 4. Per-rule KQL pipeline matrix
`microsoft_xdr` (Device* tables) for Sysmon categories, `azure_monitor`
(SecurityEvent) for native Security events. One pipeline does not cover both;
the matrix is declared in the manifest, next to the test, so each rule has a
single source of truth. The `azure_monitor` pipeline cannot infer the
SecurityEvent table from a `service: security` logsource, so
`config/sentinel/security_event_table.yml` sets it (priority 5, runs first).

## 5. T1053.005 rule: Security 4698 → process_creation of schtasks
First version: detection on Security event 4698 using the `TaskContent` field.
It fired in Zircolite (flattened raw EVTX) but did not convert: `TaskContent`
is not a column of the Sentinel `SecurityEvent` table. Decision: rewrite it as
`process_creation` of `schtasks.exe /create` with a suspicious payload. More
portable, converts cleanly to DeviceProcessEvents, and fires on a real Sysmon
sample. Lesson: a detection has to live on the log path that matches its
backend table.

## 6. CI stage order
Lint → conversion → detection tests → SAST and dependency audit → ATT&CK tags
and coverage layer. Cheapest first: a malformed rule triggers neither an EVTX
download nor a scan.

## 7. Security findings are handled, not hidden
- Bandit B404 (subprocess import): import-level noise, covered by B603, so it
  is skipped in `.bandit`. B603 (subprocess call): list-form argv, no shell,
  internal inputs, so `# nosec B603` with the reason. B310 (urlopen): scheme
  forced to https and host/commit constant, so `# nosec B310` with the reason.
- pip-audit PYSEC-2026-2447 (diskcache 5.6.3, unsafe pickle deserialization):
  transitive dependency of pySigma, no fixed release published. Exploiting it
  needs write access to the cache directory; here it only caches ATT&CK data
  on a single-tenant, ephemeral CI runner. Ignored by name
  (`--ignore-vuln`); any other vulnerability fails CI. Next review: January
  2027, or as soon as a fixed release exists.

## 8. v1 rule swaps forced by the samples
Some rules from the initial inventory were replaced for lack of a reference
EVTX (certutil, vssadmin, fodhelper, PowerShell `-enc`). Principle: a rule
with no proof that it fires does not enter the repository. The dropped
techniques come back in v2 with logs generated in a lab.

## 9. Every input of the pipeline is pinned
A test that passes today and fails tomorrow with no change here is worthless,
so nothing the pipeline consumes is allowed to move on its own:
- Python dependencies: `requirements.txt` is a lock file generated from
  `requirements.in`, with every transitive dependency and its hashes, and CI
  installs it with `--require-hashes`. Until October 2026 only direct
  dependencies were pinned, and pySigma drifted from 1.4.0 to 1.5.1 unnoticed.
- Zircolite: a commit SHA, not a release tag (a tag can be moved).
- GitHub Actions: full commit SHAs; Dependabot proposes updates.
- Runner image: `ubuntu-24.04`, not `ubuntu-latest`.
- Test data: the EVTX repository commit (decision 1) and the ATT&CK release
  (decision 3).

To update a Python dependency, edit `requirements.in`, then regenerate:
`uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes -o requirements.txt`.

## 10. Continuous integration, not continuous deployment
Changes reach `main` through a pull request, and a ruleset requires the CI
job to pass before the merge. Nothing is deployed automatically: the KQL is
published as a build artifact. Pushing detection rules straight into a
production SIEM on every merge would turn a bad rule into an alert storm (or
a silent gap) across the whole estate; deployment stays a reviewed, human step.
