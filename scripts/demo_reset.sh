#!/usr/bin/env bash
# Put the demo back on standby.
#
# Clears the two trigger files, so the console drops back to the ARMED screen and the
# next ./scripts/demo_leak.sh starts a clean take. Touches nothing else.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/demo_lib.sh

rm -f "$DEMO_DIR/leak.json" "$DEMO_DIR/attack.json"
echo "demo reset — the console is back on standby"
