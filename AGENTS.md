# AGENTS.md - detection-factory

Briefing for AI coding agents (and humans) working on this repository.
`CLAUDE.md` is a symlink to this file.

## What this is

A Detection-as-Code pipeline: Sigma rules, converted to Microsoft Sentinel KQL,
each one proven to fire on a real Windows attack log in CI, and mapped to
MITRE ATT&CK. The value is the pipeline, not the number of rules. Read
`README.md`, then `docs/decisions.md` before changing anything that looks odd:
most oddities are deliberate and explained there.

## Commands

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements.txt
bash scripts/setup_zircolite.sh
python3 tests/runner/fetch_samples.py
sigma check -i -c config/sigma_validation.yml rules/   # stage 1
python3 scripts/convert_rules.py                       # stage 2
python3 tests/runner/run_tests.py                      # stage 3, every rule must fire
bandit -q -r scripts/ tests/runner/ -c .bandit         # stage 4a
pip-audit -r requirements.txt --require-hashes --disable-pip --ignore-vuln PYSEC-2026-2447  # stage 4b
python3 scripts/build_layer.py && git diff --exit-code docs/coverage/layer.json            # stage 5
```

Run the whole sequence before proposing a change. CI (`.github/workflows/ci.yml`)
runs the same steps, and `main` only accepts pull requests whose CI passes.

## The contract a rule must meet

- One file per rule under `rules/<tactic>/`, Sigma format, `author`, `license: DRL-1.1`,
  `date`, and `modified` when it changes.
- ATT&CK tags follow the pinned release in `config/attack/` (currently v20), with the
  hyphenated tactic convention (`attack.privilege-escalation`) and at least one
  technique tag. Every tactic tag must belong to one of the rule's techniques.
- An entry in `tests/manifest.yml` pointing to a reference EVTX sample, with
  `min_hits` and its `kusto_pipeline`. A rule without a test fails the build:
  no rule enters the repository without proof that it fires.
- Regenerate `docs/coverage/layer.json` with `scripts/build_layer.py` and commit it.

## Pinning

Every input is pinned (decision 9). Do not loosen a pin to make something work.
- Python: edit `requirements.in`, then regenerate the lock
  (`uv pip compile requirements.in --universal --python-version 3.12 --generate-hashes -o requirements.txt`).
- Zircolite: commit SHA in `scripts/setup_zircolite.sh`.
- ATT&CK: bump the constants in `scripts/update_attack_data.py`, rerun it, review the diff.
- Actions: full commit SHAs with the version in a comment.

## Rules for changes

- Never commit real client or employer data, logs from a real environment,
  secrets or tokens. Test data is the pinned public EVTX set only, downloaded
  at test time and never committed.
- Do not disable a check without writing its replacement and documenting why
  in `docs/decisions.md`. Test every new guard negatively: break it on purpose
  and confirm the build fails.
- English everywhere: code, comments, docs, commit messages (conventional
  commits).
- Before writing code for anything non-trivial, present the plan (files,
  rules, data sources) and wait for the maintainer's approval.
