#!/usr/bin/env bash
# Act two of the demo: the attacker picks the leaked key up.
#
# It calls no AWS API and creates nothing. It decides which instance ids and which second
# access key the attacker "created", prints them, and hands them to the console — which
# then streams the matching CloudTrail records in, narrates, verifies, and stops at the
# approval buttons. The ids printed here are the ids on screen, so the terminal and the
# dashboard can be filmed together.
#
#   ./scripts/demo_attack.sh
#
# Run ./scripts/demo_leak.sh first: without a leak there is no key to use.
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/demo_lib.sh

require_demo_dir

LEAK_FILE="$DEMO_DIR/leak.json"
if [ ! -f "$LEAK_FILE" ]; then
  echo "no leak yet — run ./scripts/demo_leak.sh first" >&2
  exit 1
fi

LEAK_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$LEAK_FILE")"
ACCESS_KEY="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_key_id"])' "$LEAK_FILE")"

HOME_REGION="${DEMO_HOME_REGION:-ap-south-1}"
AWAY_REGION="${DEMO_AWAY_REGION:-us-east-1}"
SOURCE_IP="${DEMO_SOURCE_IP:-203.0.113.41}"

FIRST="$(instance_id)"
SECOND="$(instance_id)"
BYSTANDER="$(instance_id)"
ROGUE_KEY="$(access_key)"
RUN="$(run_id)"

cat > "$DEMO_DIR/attack.json" <<INNER
{
  "id": "${RUN}",
  "leak_id": "${LEAK_ID}",
  "started_at": "$(now_iso)",
  "source_ip": "${SOURCE_IP}",
  "instances": [
    { "id": "${FIRST}", "region": "${HOME_REGION}" },
    { "id": "${SECOND}", "region": "${AWAY_REGION}" }
  ],
  "rogue_key": "${ROGUE_KEY}",
  "bystander_instance": "${BYSTANDER}"
}
INNER

# Paced so the terminal tells the same story as the screen, at the same speed.
step() { printf '  %s\n' "$1"; sleep "${DEMO_STEP_DELAY:-1.1}"; }

echo "Attacker session — key ${ACCESS_KEY} from ${SOURCE_IP}"
echo
step "sts GetCallerIdentity                 -> arn:aws:iam::***:user/workbeat-deploy"
step "ec2 DescribeRegions                   -> 17 regions enabled"
step "ec2 DescribeInstances  ${HOME_REGION}     -> 0 running"
step "ec2 RunInstances       ${HOME_REGION}     -> ${FIRST}"
step "ec2 RunInstances       eu-west-1       -> UnauthorizedOperation (g5.xlarge refused)"
step "ec2 RunInstances       ${AWAY_REGION}       -> ${SECOND}"
step "iam CreateAccessKey                   -> ${ROGUE_KEY}"
step "cloudtrail DeleteTrail                -> AccessDenied"
echo
echo "  2 instances running, 1 extra key minted, 2 calls refused by the account's policy."
echo "  Every call above is in CloudTrail. The console is reading it now."
echo
