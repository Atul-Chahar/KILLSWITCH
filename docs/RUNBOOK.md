# Runbook

Every command a human runs, in order. Claude Code writes the code; it never runs
destructive AWS commands. Nothing here touches an account other than `DEMO_ACCOUNT_ID`.

## Once, before anything

```bash
cp .env.example .env          # fill it in, never commit it
make install                  # .venv with Python 3.12 and the dev toolchain
make check                    # secrets, lint, types, tests
```

Set in `.env` (and export before running AWS commands):

| Variable | What it is |
|---|---|
| `DEMO_ACCOUNT_ID` | The dedicated throwaway account. Every script refuses to run anywhere else |
| `AWS_REGION` | Primary demo region (`ap-south-1`) |
| `AWS_SECONDARY_REGION` | Second demo region, so the attack spans two |
| `BEDROCK_MODEL_ID` | The Bedrock model the narrator asks. Required; unset fails the step |
| `NARRATOR_MODE` | Empty or `bedrock` asks the model. `rehearsal` uses the fixed plan |

Also do these by hand, once:

- Create the dedicated demo AWS account, nothing else in it.
- Set a budget alarm at a low amount, with an email alert.

## Phase 1 — the attack

Deploy the cage the demo user lives in:

```bash
export $(grep -v '^#' .env | xargs)      # or set them however you prefer
export CDK_DEFAULT_ACCOUNT=$DEMO_ACCOUNT_ID
npx aws-cdk@2 deploy KillswitchDemoTarget       # cdk.json already points at infra/app.py
```

Mint the demo key yourself. CDK never creates it, so it cannot leak through a
CloudFormation template or a stack output:

```bash
aws iam create-access-key --user-name demo-leaky-user
```

Put that key in a **separate** shell, never in `.env`, and run the attack with it:

```bash
AWS_ACCESS_KEY_ID=<the demo key id> \
AWS_SECRET_ACCESS_KEY=<the demo secret> \
DEMO_ACCOUNT_ID=$DEMO_ACCOUNT_ID \
AWS_REGION=$AWS_REGION AWS_SECONDARY_REGION=$AWS_SECONDARY_REGION \
python scripts/attacker.py --dry-run     # resolves AMIs, launches nothing
```

Drop `--dry-run` to launch for real: one `t3.micro` per region, tagged
`demo=killswitch-attack`, with a printed timeline.

Read it back from CloudTrail with your own admin credentials:

```bash
python scripts/lookup.py <the demo key id> --wait 900
```

CloudTrail Event History is not instant. `--wait` polls instead of reporting,
wrongly, that the key did nothing.

## Phase 2 — detection

`make lambda-package` builds the asset for **x86_64 Linux**, not for your laptop. Without
that pin, building on macOS puts `_pydantic_core.cpython-312-darwin.so` in the bundle, which
imports fine locally and fails on Lambda. The target refuses to finish if it finds a
host-native binary, so you will hear about it at build time rather than at 2am.

```bash
make lambda-package                              # builds build/lambda, required before synth
GITHUB_WEBHOOK_SECRET=<your webhook secret> \
GITHUB_APP_TOKEN=<a token that can read the private repo> \
npx aws-cdk@2 deploy KillswitchDetection
```

Take `WebhookUrl` from the stack output and add it to the private demo repository as a
push webhook, with the same secret. If the secret is not set, every delivery is rejected
with a 401 — the system fails closed rather than trusting unsigned requests.

The second trigger cannot be fired by AWS for this demo: AWS only quarantines keys it
finds in public exposure, and the demo repository is private on purpose. Fire it
yourself:

```bash
python scripts/simulate_quarantine.py --region $AWS_REGION
```

Both triggers should leave exactly one row in the incident table.

## Phase 5 and 6 — the workflow and the console

```bash
make lambda-package
BEDROCK_MODEL_ID=<the model id you enabled> \
npx aws-cdk@2 deploy KillswitchResponse KillswitchConsoleApi
```

`BEDROCK_MODEL_ID` is not optional: the stack refuses to synthesize without it rather than
deploying a workflow that is certain to fail at the Narrate step. Enable that model in
Bedrock first, in `$AWS_REGION`, under Model access. The narrator Lambda is granted
`bedrock:InvokeModel` and nothing else, so an un-enabled model fails the Narrate step with
an access error rather than falling back to another model.

To rehearse without Bedrock, deploy with `NARRATOR_MODE=rehearsal` and no model id. That narrator writes
a fixed plan which always includes one instance the leaked key never created, so the
verifier strikes it out on camera every time. The console labels that prose
"Rehearsal narrator, not a model and not evidence", so it can never be shown as a model's
work.

Create yourself an operator. The pool does not allow self sign-up:

```bash
aws cognito-idp admin-create-user --user-pool-id <UserPoolId output> \
  --username you@example.com --user-attributes Name=email,Value=you@example.com
```

Run the console against the deployed API:

```bash
cd console && npm install
VITE_API_BASE=<ConsoleApiUrl output> npm run build   # then deploy console/dist to Amplify Hosting
```

With no `VITE_API_BASE` the console runs in fixture mode against a bundled example
incident, and says so on screen. That is the safe way to rehearse the screen.

## After every recording

```bash
aws iam delete-access-key --user-name demo-leaky-user --access-key-id <the demo key id>
aws ec2 terminate-instances --region $AWS_REGION --instance-ids <ids>
aws ec2 terminate-instances --region $AWS_SECONDARY_REGION --instance-ids <ids>
```

Then confirm the account is empty and the budget alarm is still armed.
