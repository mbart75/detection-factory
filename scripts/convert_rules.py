#!/usr/bin/env python3
"""Convert every rule to Sentinel KQL using the pipeline declared in tests/manifest.yml."""
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist" / "kql"
SIGMA = Path(sys.executable).with_name("sigma")
# Windows Security-channel rules (azure_monitor -> SecurityEvent table) need the
# table set before azure_monitor runs, so this pipeline is chained first.
SECURITYEVENT_PIPELINE = ROOT / "config" / "sentinel" / "security_event_table.yml"


def pipelines_for(entry: dict) -> list:
    pipeline = entry["kusto_pipeline"]
    if pipeline == "azure_monitor":
        return ["-p", str(SECURITYEVENT_PIPELINE), "-p", pipeline]
    return ["-p", pipeline]


def main() -> int:
    manifest = yaml.safe_load((ROOT / "tests" / "manifest.yml").read_text())
    DIST.mkdir(parents=True, exist_ok=True)
    failures = 0
    for entry in manifest["tests"]:
        rule = ROOT / entry["rule"]
        pipeline = entry["kusto_pipeline"]
        out = DIST / (rule.stem + ".kql")
        proc = subprocess.run(  # nosec B603: fixed argv, no shell, trusted inputs
            [str(SIGMA), "convert", "-t", "kusto", *pipelines_for(entry), str(rule)],
            capture_output=True, text=True,
        )
        if proc.returncode != 0:
            print(f"[FAIL] {rule.name} ({pipeline}):\n{proc.stderr}", file=sys.stderr)
            failures += 1
            continue
        if not proc.stdout.strip():
            print(f"[FAIL] {rule.name} ({pipeline}): empty query", file=sys.stderr)
            failures += 1
            continue
        out.write_text(proc.stdout)
        print(f"[ok] {rule.name} -> {out.relative_to(ROOT)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
