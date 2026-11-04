#!/usr/bin/env python3
"""Run each Sigma rule against its pinned EVTX sample via Zircolite; fail if it does not fire."""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml
from evtx import PyEvtxParser

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "manifest.yml"
ZIRCOLITE = ROOT / "tools" / "Zircolite" / "zircolite.py"
SAMPLES_DIR = ROOT / "tests" / "samples"
# sysmon: maps Sigma categories (process_creation, registry_set, image_load)
# to Sysmon EventIDs; windows-logsources: maps service logsources to channels.
PIPELINES = ["sysmon", "windows-logsources"]


def run_zircolite(rule: Path, sample: Path, json_input: bool = False) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        outfile = Path(tmp) / "detected.json"
        cmd = [
            sys.executable, str(ZIRCOLITE),
            "--events", str(sample),
            "--ruleset", str(rule),
            "--pipeline", *PIPELINES,
            "--outfile", str(outfile),
        ]
        if json_input:
            cmd.append("--json-input")
        proc = subprocess.run(  # nosec B603: fixed argv, no shell, trusted inputs
            cmd, capture_output=True, text=True, cwd=ZIRCOLITE.parent
        )
        if not outfile.exists():
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            raise RuntimeError(f"Zircolite produced no output for {rule.name}")
        return json.loads(outfile.read_text())


def samples_dir(manifest: dict) -> Path:
    """Samples are stored per pinned commit (see fetch_samples.py)."""
    return SAMPLES_DIR / manifest["upstream"]["commit"]


def count_hits(detections: list, title: str) -> int:
    total = 0
    for d in detections:
        if d.get("title") == title:
            total += d.get("count") or len(d.get("matches", []))
    return total


def write_variant(sample: Path, overrides: dict, dest: Path) -> int:
    """Rewrite fields of the pinned sample's events into a JSON-lines copy.

    Returns how many events were rewritten. Nothing synthetic is committed: a
    variant is the real attack log with one value changed, built at test time.
    """
    rewritten = 0
    with dest.open("w") as out:
        for record in PyEvtxParser(str(sample)).records_json():
            event = json.loads(record["data"])
            data = event["Event"].get("EventData") or {}
            if overrides.keys() <= data.keys():
                data.update(overrides)
                rewritten += 1
            out.write(json.dumps(event) + "\n")
    return rewritten


def run_variants(rule: Path, sample: Path, title: str, variants: list) -> list:
    """Replay the sample with fields rewritten; each variant must fire or stay silent."""
    results = []
    for variant in variants:
        bounds = {k: variant[k] for k in ("min_hits", "max_hits") if k in variant}
        if len(bounds) != 1:
            raise ValueError(f"variant '{variant['name']}' needs exactly one "
                             f"of min_hits or max_hits")
        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "variant.jsonl"
            # a variant that rewrites nothing would pass while proving nothing
            if write_variant(sample, variant["set"], events) == 0:
                raise ValueError(f"variant '{variant['name']}' matches no event "
                                 f"field in {sample.name}")
            hits = count_hits(run_zircolite(rule, events, json_input=True), title)
        if "min_hits" in bounds:
            ok, want = hits >= bounds["min_hits"], f"min={bounds['min_hits']}"
        else:
            ok, want = hits <= bounds["max_hits"], f"max={bounds['max_hits']}"
        results.append((f"  variant: {variant['name']}", hits, want, ok))
    return results


def canary_self_test(manifest: dict) -> str:
    """Prove the harness can still detect at all before trusting any PASS.

    A broken harness that silently returns no detections would turn every rule
    test into a false FAIL; one that matches everything would make them
    meaningless. The canary matches all process-creation events, so it must fire
    on a Sysmon sample.
    """
    canary = Path(__file__).parent / "canary.yml"
    sample = samples_dir(manifest) / Path(manifest["tests"][0]["sample"]).name
    if not canary.exists() or not sample.exists():
        return f"canary self-test cannot run (missing {canary.name} or sample)"
    title = yaml.safe_load(canary.read_text())["title"]
    hits = count_hits(run_zircolite(canary, sample), title)
    if hits < 1:
        return f"canary did not fire on {sample.name}: harness is broken"
    return ""


def check_every_rule_is_tested(manifest: dict) -> list:
    """Every rule in rules/ must have a manifest entry, or it is never proven."""
    declared = {e["rule"] for e in manifest["tests"]}
    on_disk = {
        str(p.relative_to(ROOT)) for p in (ROOT / "rules").rglob("*.yml")
    }
    errors = [f"rule not covered by any test: {r}" for r in sorted(on_disk - declared)]
    errors += [f"manifest references missing rule: {r}" for r in sorted(declared - on_disk)]
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", help="run rules whose manifest path contains this")
    args = parser.parse_args()
    manifest = yaml.safe_load(MANIFEST.read_text())

    coverage_errors = check_every_rule_is_tested(manifest)
    if coverage_errors:
        for err in coverage_errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1

    canary_error = canary_self_test(manifest)
    if canary_error:
        print(f"[FAIL] {canary_error}", file=sys.stderr)
        return 1
    print("[canary] harness verified\n")

    results = []
    for entry in manifest["tests"]:
        rule = ROOT / entry["rule"]
        # match on the manifest-relative path, never the absolute checkout path
        if args.only and args.only not in entry["rule"]:
            continue
        sample = samples_dir(manifest) / Path(entry["sample"]).name
        if not rule.exists():
            print(f"[FAIL] missing rule file: {entry['rule']}", file=sys.stderr)
            return 1
        if not sample.exists():
            print(f"[FAIL] missing sample: {entry['sample']} "
                  f"(run tests/runner/fetch_samples.py)", file=sys.stderr)
            return 1
        title = yaml.safe_load(rule.read_text())["title"]
        hits = count_hits(run_zircolite(rule, sample), title)
        results.append((rule.name, hits, f"min={entry['min_hits']}",
                        hits >= entry["min_hits"]))
        results += run_variants(rule, sample, title, entry.get("variants", []))
    if not results:
        print("no tests selected", file=sys.stderr)
        return 2
    for name, hits, want, ok in results:
        print(f"{'PASS' if ok else 'FAIL':4} {name:68} hits={hits} ({want})")
    return 0 if all(ok for *_, ok in results) else 1


if __name__ == "__main__":
    sys.exit(main())
