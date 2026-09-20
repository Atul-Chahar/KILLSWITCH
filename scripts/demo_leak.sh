#!/usr/bin/env bash
# Act one of the demo: a developer pushes an AWS key.
#
# It writes a credentials file into a clone of the watched repository, commits it, pushes
# it, and then tells the local console that a push happened. The console takes it from
# there: identify the key's owner, search CloudTrail, find nothing yet, and hold.
#
#   ./scripts/demo_leak.sh
#
# The key it generates is random and grants nothing. Nothing here calls AWS. If the push
# is refused — GitHub's push protection exists precisely to stop this — the commit still
# lands locally and the demo carries on, because the console is driven by this script and
# not by GitHub.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/demo_lib.sh

REPO_SLUG="${DEMO_REPO:-gyanranjanpanda/workbeat}"
REPO_URL="${DEMO_REPO_URL:-https://github.com/${REPO_SLUG}.git}"
CLONE_DIR="${DEMO_REPO_DIR:-$HOME/killswitch-demo/workbeat}"
# A clone under the default path is the demo's own, and is reset between takes. A clone
# you point it at with DEMO_REPO_DIR is yours, and nothing here throws away your work.
DEMO_OWNED_CLONE="${DEMO_REPO_DIR:+0}"
DEMO_OWNED_CLONE="${DEMO_OWNED_CLONE:-1}"
LEAK_PATH="${DEMO_LEAK_PATH:-config/aws.env}"
KEY_OWNER="${DEMO_KEY_OWNER:-workbeat-deploy}"
DO_PUSH="${DEMO_PUSH:-1}"

require_demo_dir

ACCESS_KEY="$(access_key)"
SECRET_KEY="$(rand_b64 40)"
RUN="$(run_id)"

echo "KILLSWITCH demo — act one: the leak"
echo

COMMIT_SHA=""
if [ -d "$CLONE_DIR/.git" ]; then
  echo "  repo      $CLONE_DIR (existing clone)"
elif git clone --quiet "$REPO_URL" "$CLONE_DIR" 2>/dev/null; then
  echo "  repo      $CLONE_DIR (cloned)"
else
  echo "  repo      could not clone $REPO_URL"
  echo "            set DEMO_REPO_DIR to a local clone, or DEMO_PUSH=0 to skip git entirely."
  DO_PUSH=0
fi

if [ -d "$CLONE_DIR/.git" ]; then
  (
    cd "$CLONE_DIR"
    if [ "$DEMO_OWNED_CLONE" = "1" ]; then
      # Each take should be one commit on top of the real branch, not a pile of them.
      git fetch --quiet origin 2>/dev/null || true
      git reset --hard --quiet "origin/$(git rev-parse --abbrev-ref HEAD)" 2>/dev/null || true
    else
      git pull --quiet --ff-only 2>/dev/null || true
    fi
    mkdir -p "$(dirname "$LEAK_PATH")"
    cat > "$LEAK_PATH" <<INNER
# Deployment credentials for the nightly sync job.
# TODO: move these into the CI secret store before the next release.
AWS_ACCESS_KEY_ID=${ACCESS_KEY}
AWS_SECRET_ACCESS_KEY=${SECRET_KEY}
AWS_DEFAULT_REGION=ap-south-1
INNER
    git add "$LEAK_PATH"
    git -c user.name="${DEMO_GIT_NAME:-demo}" \
        -c user.email="${DEMO_GIT_EMAIL:-demo@example.invalid}" \
        commit --quiet -m "chore: add deploy credentials for the nightly sync job"
  )
  COMMIT_SHA="$(git -C "$CLONE_DIR" rev-parse HEAD)"
  echo "  committed $LEAK_PATH as ${COMMIT_SHA:0:7}"

  if [ "$DO_PUSH" = "1" ]; then
    if git -C "$CLONE_DIR" push --quiet 2>/dev/null; then
      echo "  pushed    to $REPO_SLUG"
    else
      echo "  push      REFUSED by GitHub (push protection, or no write access)."
      echo "            The commit is local. The demo continues — the console is driven"
      echo "            by this script, not by GitHub."
    fi
  else
    echo "  push      skipped (DEMO_PUSH=0)"
  fi
fi

# No clone, no commit. The console still needs a plausible sha to show.
[ -n "$COMMIT_SHA" ] || COMMIT_SHA="$(rand_hex 40)"

cat > "$DEMO_DIR/leak.json" <<INNER
{
  "id": "${RUN}",
  "access_key_id": "${ACCESS_KEY}",
  "repository": "${REPO_SLUG}",
  "commit_sha": "${COMMIT_SHA}",
  "pushed_at": "$(now_iso)",
  "key_owner": "${KEY_OWNER}",
  "leaked_path": "${LEAK_PATH}"
}
INNER

# An attack left over from the previous take must not replay against this leak.
rm -f "$DEMO_DIR/attack.json"

echo
echo "  key       ${ACCESS_KEY}   (random, grants nothing)"
echo "  owner     ${KEY_OWNER}"
echo
echo "The console is picking this up now. When it says the key is live and idle, run:"
echo
echo "    ./scripts/demo_attack.sh"
echo
