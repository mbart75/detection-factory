#!/usr/bin/env python3
"""Extract the ATT&CK reference that build_layer.py validates tags against.

The official STIX bundle is ~55 MB, too big to commit, and pySigma's own
validator reads the moving master branch at run time. This script downloads
one tagged release, checks its SHA-256, and writes a small extract to
config/attack/, which is committed. Run it only to move to a new ATT&CK
release: bump the three constants below, rerun, and review the diff.
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ATTACK_VERSION = "20.0"
STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    f"v{ATTACK_VERSION}/enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
STIX_SHA256 = "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "config" / "attack" / "enterprise-attack.json"


def external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main() -> int:
    if not STIX_URL.startswith("https://"):
        print(f"[error] refusing non-https URL: {STIX_URL}", file=sys.stderr)
        return 1
    # https enforced above; URL is a constant -> file:/ scheme abuse N/A
    with urllib.request.urlopen(STIX_URL, timeout=120) as resp:  # nosec B310
        raw = resp.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != STIX_SHA256:
        print(f"[error] sha256 mismatch: got {digest}, expected {STIX_SHA256}",
              file=sys.stderr)
        return 1
    objects = json.loads(raw)["objects"]

    tactics = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and not obj.get("revoked"):
            tactics[obj["x_mitre_shortname"]] = {
                "id": external_id(obj), "name": obj["name"]}

    stix_to_id = {o["id"]: external_id(o) for o in objects
                  if o.get("type") == "attack-pattern"}
    revoked_by = {}
    for obj in objects:
        if (obj.get("type") == "relationship"
                and obj.get("relationship_type") == "revoked-by"):
            revoked_by[stix_to_id.get(obj["source_ref"])] = stix_to_id.get(
                obj["target_ref"])

    techniques = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        tid = external_id(obj)
        if not tid:
            continue
        entry = {"name": obj["name"],
                 "tactics": sorted(p["phase_name"]
                                   for p in obj.get("kill_chain_phases", []))}
        if obj.get("revoked"):
            entry["revoked_by"] = revoked_by.get(tid)
        elif obj.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        techniques[tid] = entry

    extract = {
        "attack_version": ATTACK_VERSION,
        "source": STIX_URL,
        "source_sha256": STIX_SHA256,
        "tactics": dict(sorted(tactics.items())),
        "techniques": dict(sorted(techniques.items())),
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(extract, indent=1) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: ATT&CK v{ATTACK_VERSION}, "
          f"{len(tactics)} tactics, {len(techniques)} techniques")
    return 0


if __name__ == "__main__":
    sys.exit(main())
