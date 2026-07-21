#!/usr/bin/env python3
"""Generate an ATT&CK Navigator layer from the attack.* tags of every Sigma rule."""
import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "coverage" / "layer.json"
TECH_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def main() -> None:
    techniques = {}
    for rule_file in sorted((ROOT / "rules").rglob("*.yml")):
        rule = yaml.safe_load(rule_file.read_text())
        for tag in rule.get("tags", []):
            match = TECH_RE.match(tag)
            if match:
                techniques.setdefault(match.group(1).upper(), []).append(rule["title"])
    layer = {
        "name": "detection-factory coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques covered by at least one CI-validated Sigma rule",
        "techniques": [
            {"techniqueID": tid, "score": len(rules), "comment": "; ".join(rules)}
            for tid, rules in sorted(techniques.items())
        ],
        "gradient": {"colors": ["#ffe766", "#8ec843"], "minValue": 0, "maxValue": 2},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(layer, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)} ({len(techniques)} techniques)")


if __name__ == "__main__":
    main()
