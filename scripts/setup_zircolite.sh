#!/usr/bin/env bash
# Zircolite n'est pas sur PyPI : pin sur un tag de release pour une CI reproductible.
set -euo pipefail
ZIRCOLITE_TAG="v3.7.6"
DEST="tools/Zircolite"
if [ ! -d "$DEST" ]; then
  git clone --depth 1 --branch "$ZIRCOLITE_TAG" https://github.com/wagga40/Zircolite.git "$DEST"
fi
pip install -r "$DEST/requirements.txt"
