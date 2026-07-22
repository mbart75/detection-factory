#!/usr/bin/env python3
"""Validate ATT&CK tags on every Sigma rule, then emit an ATT&CK Navigator layer.

This is the compensating control for the disabled `attacktag` validator (see
docs/decisions.md): it fails the build on a malformed or missing technique tag,
so a rule can never reach the public coverage layer unmapped.
"""
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "coverage" / "layer.json"
TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")
# Any attack.* tag that is not a tactic must parse as a technique ID.
TACTIC_RE = re.compile(r"^attack\.[a-z_]+$")


def collect(rule_file: Path, errors: list) -> list:
    rule = yaml.safe_load(rule_file.read_text())
    rel = rule_file.relative_to(ROOT)
    techniques = []
    for tag in rule.get("tags", []):
        if not tag.startswith("attack."):
            continue
        match = TECH_RE.match(tag)
        if match:
            techniques.append(match.group(1).upper())
        elif not TACTIC_RE.match(tag):
            errors.append(f"{rel}: malformed ATT&CK tag '{tag}'")
    if not techniques:
        errors.append(f"{rel}: no valid ATT&CK technique tag (attack.tNNNN[.NNN])")
    return techniques


def main() -> int:
    techniques, errors = {}, []
    rule_files = sorted((ROOT / "rules").rglob("*.yml"))
    if not rule_files:
        print("no rules found", file=sys.stderr)
        return 1
    for rule_file in rule_files:
        rule = yaml.safe_load(rule_file.read_text())
        for tid in collect(rule_file, errors):
            techniques.setdefault(tid, []).append(rule["title"])
    if errors:
        for err in errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1

    max_score = max(len(rules) for rules in techniques.values())
    layer = {
        "name": "detection-factory coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by at least one CI-validated Sigma rule",
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
    print(f"wrote {OUT.relative_to(ROOT)} ({len(techniques)} techniques)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
