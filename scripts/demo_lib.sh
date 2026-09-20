# Shared by the two demo scripts.
#
# The credentials these generate are random and belong to nobody. They are shaped like
# real AWS ids so the console treats them the way it would treat the real thing, and they
# grant nothing anywhere.
#
# Randomness comes from python3 rather than `tr </dev/urandom | head`, which exits 141
# under `set -o pipefail` as soon as head closes the pipe.

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/console/public/demo"

_rand() {
  python3 -c '
import secrets, sys
alphabet, length = sys.argv[1], int(sys.argv[2])
sys.stdout.write("".join(secrets.choice(alphabet) for _ in range(length)))
' "$1" "$2"
}

rand_upper() { _rand 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' "$1"; }
rand_hex()   { _rand '0123456789abcdef' "$1"; }
rand_b64()   { _rand 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' "$1"; }

# AWS issues 17 hex characters after "i-". verifier/verify.py insists on exactly that.
instance_id() { printf 'i-0%s' "$(rand_hex 16)"; }
access_key()  { printf 'AKIA%s' "$(rand_upper 16)"; }

now_iso() { date -u +%Y-%m-%dT%H:%M:%S+00:00; }

# A run id, so the console can tell a fresh take from the one still on screen.
run_id() { printf '%s-%s' "$(date -u +%Y%m%d%H%M%S)" "$(rand_hex 6)"; }

require_demo_dir() { mkdir -p "$DEMO_DIR"; }
