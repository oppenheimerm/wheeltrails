#!/usr/bin/env bash
# Generates wwwroot/js/config.js from GOOGLE_MAPS_API_KEY env var if present
set -e
OUT_DIR="WT.Client/wwwroot/js"
mkdir -p "$OUT_DIR"
if [ -z "${GOOGLE_MAPS_API_KEY:-}" ]; then
 echo "GOOGLE_MAPS_API_KEY not set; skipping config generation"
 exit 0
fi
cat > "$OUT_DIR/config.js" <<EOF
window.__WT_CONFIG__ = { GOOGLE_MAPS_API_KEY: "${GOOGLE_MAPS_API_KEY}" };
EOF
echo "Wrote $OUT_DIR/config.js"