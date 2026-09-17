#!/usr/bin/env bash
# Fails if anything that looks like a credential is staged or tracked.
# Run before every commit. Not a replacement for care: it is a last line of defence.
set -euo pipefail

FAIL=0
EXAMPLE_KEY="AKIAIOSFODNN7EXAMPLE"

files=$(git diff --cached --name-only --diff-filter=ACM 2>/dev/null || true)
[ -z "$files" ] && files=$(git ls-files)

for f in $files; do
  [ -f "$f" ] || continue
  # This script carries the patterns it hunts for, so it cannot scan itself.
  [ "$f" = "scripts/check_secrets.sh" ] && continue

  # Every AKIA key id except AWS's own documented example. Markdown is scanned
  # too: write-ups and evidence notes are exactly where a real key gets pasted.
  if grep -Eo 'AKIA[0-9A-Z]{16}' "$f" | grep -qv "^${EXAMPLE_KEY}$"; then
    echo "AWS access key id in $f"; FAIL=1
  fi
  if grep -Eq 'ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----' "$f"; then
    echo "secret material in $f"; FAIL=1
  fi
  # A secret access key only counts when it is assigned a 40-character value,
  # so prose that merely names the variable does not fail the build.
  if grep -Eqi 'aws_secret_access_key["'"'"']?[[:space:]]*[=:][[:space:]]*["'"'"']?[A-Za-z0-9/+=]{40}' "$f"; then
    echo "secret material in $f"; FAIL=1
  fi
  if grep -Eq 'gh[pousr]_[A-Za-z0-9]{30,}' "$f"; then
    echo "GitHub token in $f"; FAIL=1
  fi
done

if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  echo ".env is tracked by git"; FAIL=1
fi

if [ "$FAIL" -ne 0 ]; then
  echo "check_secrets: FAILED. Do not commit."; exit 1
fi
echo "check_secrets: clean"
