#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist"
VERSION="${1:-mvp}"
BUNDLE="mrwolf-${VERSION}.tar.gz"

mkdir -p "$OUT_DIR"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$TMP_DIR/mrwolf"
cp -R "$ROOT_DIR/cli" "$TMP_DIR/mrwolf/"
cp -R "$ROOT_DIR/scripts" "$TMP_DIR/mrwolf/"
cp -R "$ROOT_DIR/schemas" "$TMP_DIR/mrwolf/"
cp "$ROOT_DIR/README.md" "$TMP_DIR/mrwolf/"

(cd "$TMP_DIR" && tar -czf "$OUT_DIR/$BUNDLE" mrwolf)

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$OUT_DIR" && sha256sum "$BUNDLE" > "$BUNDLE.sha256")
else
  (cd "$OUT_DIR" && shasum -a 256 "$BUNDLE" > "$BUNDLE.sha256")
fi

echo "$OUT_DIR/$BUNDLE"
