#!/usr/bin/env bash
# Log in to Cognito and start the console against the deployed API.
#
# The API's approve route is the last gate in the system, so it sits behind a Cognito
# authorizer and the console must send an id token. This fetches one and hands it to
# Vite. Your password is read by the AWS CLI and never stored, echoed, or committed.
#
#   ./scripts/run_console.sh you@example.com
#
# The token lasts an hour. If the console starts reporting 401, re-run this.
set -euo pipefail
cd "$(dirname "$0")/.."

[ -f .env ] || { echo "no .env — run from the repo root"; exit 1; }
set -a; . ./.env; set +a

USERNAME="${1:-}"
[ -n "$USERNAME" ] || { echo "usage: $0 <cognito-username>"; exit 1; }

REGION="${AWS_REGION:-ap-south-1}"
POOL_ID="$(aws cloudformation describe-stacks --stack-name KillswitchConsoleApi --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)"
CLIENT_ID="$(aws cloudformation describe-stacks --stack-name KillswitchConsoleApi --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolClientId'].OutputValue" --output text)"
API_URL="$(aws cloudformation describe-stacks --stack-name KillswitchConsoleApi --region "$REGION" \
  --query "Stacks[0].Outputs[?OutputKey=='ConsoleApiUrl'].OutputValue" --output text)"

echo "pool=$POOL_ID  api=$API_URL"
printf 'password for %s: ' "$USERNAME" >&2
read -rs PASSWORD; echo >&2

AUTH="$(aws cognito-idp admin-initiate-auth --region "$REGION" \
  --user-pool-id "$POOL_ID" --client-id "$CLIENT_ID" \
  --auth-flow ADMIN_USER_PASSWORD_AUTH \
  --auth-parameters "USERNAME=$USERNAME,PASSWORD=$PASSWORD" 2>&1)" || {
    echo "$AUTH" | tail -3
    echo
    echo "If it says NEW_PASSWORD_REQUIRED, set a permanent password first:"
    echo "  aws cognito-idp admin-set-user-password --region $REGION \\"
    echo "    --user-pool-id $POOL_ID --username $USERNAME \\"
    echo "    --password '<a strong password>' --permanent"
    exit 1
  }

TOKEN="$(printf '%s' "$AUTH" | python3 -c 'import json,sys; print(json.load(sys.stdin)["AuthenticationResult"]["IdToken"])')"
unset PASSWORD

echo "logged in. starting console..."
cd console
VITE_API_BASE="${API_URL%/}" VITE_API_TOKEN="$TOKEN" npm run dev
