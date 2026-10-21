#!/usr/bin/env python3
"""Validate ATT&CK tags on every Sigma rule, then emit an ATT&CK Navigator layer.

This is the compensating control for the disabled `attacktag` validator (see
docs/decisions.md, decision 3). Tags are checked offline against a pinned,
committed ATT&CK extract (config/attack/enterprise-attack.json, produced by
scripts/update_attack_data.py), so the result only changes when this repo does.
The build fails if a rule has no technique tag, a malformed tag, a technique
that does not exist or was revoked or deprecated, an unknown tactic, or a
tactic that none of its techniques belongs to.
"""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "coverage" / "layer.json"
ATTACK = ROOT / "config" / "attack" / "enterprise-attack.json"
TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
# Any attack.* tag that is not a technique must be a tactic short name.
TACTIC_RE = re.compile(r"^attack\.([a-z]+(?:-[a-z]+)*)$")


def collect(rule_file: Path, attack: dict, errors: list) -> list:
    rule = yaml.safe_load(rule_file.read_text())
    rel = rule_file.relative_to(ROOT)
    techniques, tactics = [], []
    for tag in rule.get("tags", []):
        if not tag.startswith("attack."):
            continue
        tech, tactic = TECH_RE.match(tag), TACTIC_RE.match(tag)
        if tech:
            tid = tech.group(1).upper()
            ref = attack["techniques"].get(tid)
            if ref is None:
                errors.append(f"{rel}: unknown ATT&CK technique {tid}")
            elif "revoked_by" in ref:
                errors.append(f"{rel}: {tid} is revoked, use {ref['revoked_by']}")
            elif ref.get("deprecated"):
                errors.append(f"{rel}: {tid} is deprecated")
            else:
                techniques.append(tid)
        elif tactic:
            if tactic.group(1) not in attack["tactics"]:
                errors.append(f"{rel}: unknown ATT&CK tactic '{tag}'")
            else:
                tactics.append(tactic.group(1))
        else:
            errors.append(f"{rel}: malformed ATT&CK tag '{tag}'")
    if not techniques:
        errors.append(f"{rel}: no valid ATT&CK technique tag (attack.tNNNN[.NNN])")
    covered = {t for tid in techniques for t in attack["techniques"][tid]["tactics"]}
    for tactic in tactics:
        if techniques and tactic not in covered:
            errors.append(f"{rel}: tactic '{tactic}' matches none of its techniques")
    return techniques


def main() -> int:
    attack = json.loads(ATTACK.read_text())
    techniques, errors = {}, []
    rule_files = sorted((ROOT / "rules").rglob("*.yml"))
    if not rule_files:
        print("no rules found", file=sys.stderr)
        return 1
    for rule_file in rule_files:
        rule = yaml.safe_load(rule_file.read_text())
        for tid in collect(rule_file, attack, errors):
            techniques.setdefault(tid, []).append(rule["title"])
    if errors:
        for err in errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1

    version = attack["attack_version"].split(".")[0]
    max_score = max(len(rules) for rules in techniques.values())
    layer = {
        "name": "detection-factory coverage",
        "versions": {"attack": version, "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by at least one CI-validated Sigma rule "
                       f"(ATT&CK v{attack['attack_version']})",
        "techniques": [
            {"techniqueID": tid, "score": len(rules), "comment": "; ".join(rules)}
            for tid, rules in sorted(techniques.items())
        ],
        "gradient": {
            "colors": ["#ffe766", "#8ec843"],
            "minValue": 0,
            "maxValue": max_score,
        },
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(layer, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(techniques)} techniques, "
          f"ATT&CK v{attack['attack_version']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
