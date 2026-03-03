#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

BUNDLE_PATH="$($ROOT_DIR/scripts/build_release_bundle.sh smoke)"
cp "$BUNDLE_PATH" "$WORK_DIR/"
cp "$BUNDLE_PATH.sha256" "$WORK_DIR/"

cd "$WORK_DIR"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "$(basename "$BUNDLE_PATH").sha256"
else
  shasum -a 256 -c "$(basename "$BUNDLE_PATH").sha256"
fi

tar -xzf "$(basename "$BUNDLE_PATH")"
cd mrwolf

python3 cli/mrwolf.py release-gate --help
bash scripts/one_click_MRWOLF_handoff_all_v1.sh
python3 - <<'PY'
import json
from pathlib import Path
p = Path('audit_evidence/latest/mrwolf_handoff.json')
obj = json.loads(p.read_text())
assert obj['decision'] == 'PASS', obj
assert obj['blocking_issues'] == [], obj
print('smoke: PASS')
PY
