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

## After every recording

```bash
aws iam delete-access-key --user-name demo-leaky-user --access-key-id <the demo key id>
aws ec2 terminate-instances --region $AWS_REGION --instance-ids <ids>
aws ec2 terminate-instances --region $AWS_SECONDARY_REGION --instance-ids <ids>
```

Then confirm the account is empty and the budget alarm is still armed.
