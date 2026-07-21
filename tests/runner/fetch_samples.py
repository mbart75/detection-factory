#!/usr/bin/env python3
"""Download pinned EVTX reference samples listed in tests/manifest.yml."""
import sys
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "manifest.yml"
SAMPLES_DIR = ROOT / "tests" / "samples"
RAW_BASE = "https://raw.githubusercontent.com/{repo}/{commit}/{path}"


def main() -> int:
    manifest = yaml.safe_load(MANIFEST.read_text())
    upstream = manifest["upstream"]
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    failures = 0
    for entry in manifest["tests"]:
        sample = entry["sample"]
        dest = SAMPLES_DIR / Path(sample).name
        if dest.exists() and dest.stat().st_size > 0:
            print(f"[cache] {dest.name}")
            continue
        url = RAW_BASE.format(
            repo=upstream["repo"],
            commit=upstream["commit"],
            path=urllib.parse.quote(sample),
        )
        if not url.startswith("https://"):
            print(f"[error] refusing non-https URL: {url}", file=sys.stderr)
            failures += 1
            continue
        try:
            print(f"[fetch] {sample}")
            # https enforced above; host/commit constant -> file:/ scheme abuse N/A
            with urllib.request.urlopen(url, timeout=60) as resp:  # nosec B310
                dest.write_bytes(resp.read())
        except OSError as exc:
            print(f"[error] {sample}: {exc}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
