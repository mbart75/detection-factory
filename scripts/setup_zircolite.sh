#!/usr/bin/env bash
# Zircolite is not on PyPI, so it is cloned. It is pinned to the commit behind
# the v3.7.6 release tag, not to the tag itself: a tag can be moved, a commit
# hash cannot. Its Python dependencies are locked in requirements.txt.
set -euo pipefail
ZIRCOLITE_COMMIT="b37b51eb00c49fc7bfd2f4968f1e5c3fc30da643"  # v3.7.6
DEST="tools/Zircolite"
if [ ! -d "$DEST/.git" ]; then
  git init -q "$DEST"
  git -C "$DEST" fetch -q --depth 1 https://github.com/wagga40/Zircolite.git "$ZIRCOLITE_COMMIT"
  git -C "$DEST" checkout -q FETCH_HEAD
fi
actual="$(git -C "$DEST" rev-parse HEAD)"
if [ "$actual" != "$ZIRCOLITE_COMMIT" ]; then
  echo "[FAIL] $DEST is at $actual, expected $ZIRCOLITE_COMMIT (delete it and rerun)" >&2
  exit 1
fi
echo "[ok] Zircolite at $ZIRCOLITE_COMMIT"
