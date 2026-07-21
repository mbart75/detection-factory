#!/usr/bin/env python3
"""Run each Sigma rule against its pinned EVTX sample via Zircolite; fail if it does not fire."""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "manifest.yml"
ZIRCOLITE = ROOT / "tools" / "Zircolite" / "zircolite.py"
SAMPLES_DIR = ROOT / "tests" / "samples"
# sysmon: maps Sigma categories (process_creation, registry_set, image_load)
# to Sysmon EventIDs; windows-logsources: maps service logsources to channels.
PIPELINES = ["sysmon", "windows-logsources"]


def run_zircolite(rule: Path, sample: Path) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        outfile = Path(tmp) / "detected.json"
        cmd = [
            sys.executable, str(ZIRCOLITE),
            "--events", str(sample),
            "--ruleset", str(rule),
            "--pipeline", *PIPELINES,
            "--outfile", str(outfile),
        ]
        proc = subprocess.run(  # nosec B603: fixed argv, no shell, trusted inputs
            cmd, capture_output=True, text=True, cwd=ZIRCOLITE.parent
        )
        if not outfile.exists():
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            raise RuntimeError(f"Zircolite produced no output for {rule.name}")
        return json.loads(outfile.read_text())


def count_hits(detections: list, title: str) -> int:
    total = 0
    for d in detections:
        if d.get("title") == title:
            total += d.get("count") or len(d.get("matches", []))
    return total


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="run rules whose path contains this substring")
    args = parser.parse_args()
    manifest = yaml.safe_load(MANIFEST.read_text())
    results, failed = [], False
    for entry in manifest["tests"]:
        rule = ROOT / entry["rule"]
        if args.only and args.only not in str(rule):
            continue
        sample = SAMPLES_DIR / Path(entry["sample"]).name
        title = yaml.safe_load(rule.read_text())["title"]
        hits = count_hits(run_zircolite(rule, sample), title)
        ok = hits >= entry["min_hits"]
        failed |= not ok
        results.append((rule.name, hits, entry["min_hits"], "PASS" if ok else "FAIL"))
    if not results:
        print("no tests selected", file=sys.stderr)
        return 2
    for name, hits, want, status in results:
        print(f"{status:4} {name:50} hits={hits} (min={want})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
