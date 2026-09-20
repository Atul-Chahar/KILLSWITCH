# First run — connecting an AWS account, from zero

`docs/RUNBOOK.md` assumes you already have an AWS account and a working CLI. This file is
everything *before* that, written for someone who has never opened the AWS console.

Work through it in order. **Stop at the end of each stage and check the "you should see"
line before moving on.** Doing all of it in one go is how people end up with a half-deployed
account and no idea which step broke.

> **The one rule that protects your bank account:** this project deliberately leaks a
> working AWS key and then lets an attack script spend money with it. It must run in a
> **brand new, empty AWS account that contains nothing you care about** — never your main
> account, never a college or employer account, never one with anything else in it.
> Stage 2's budget alarm is not optional.

---

## What this will cost

Assuming you follow the teardown in stage 9, the whole demo is **well under $1**.

| What | Cost |
|---|---|
| 2 × `t3.micro` EC2, running under an hour | ~$0.02 |
| Lambda, Step Functions, DynamoDB, API Gateway at demo volume | a few cents |
| Bedrock, a handful of calls | a few cents |
| CloudTrail Event History, Verified Permissions | free |

The real risk is not the demo — it is **forgetting to tear down**. Two `t3.micro`
instances left running for a month are about $16. The budget alarm in stage 2 is what
catches that.

---

## Stage 1 — Create a dedicated AWS account

**Only you can do this.** I can't create accounts or enter card details, and you shouldn't
let any tool do that for you.

1. Open [aws.amazon.com](https://aws.amazon.com) in a private browser window — the private
   window matters, so you don't accidentally sign into an existing account.
2. **Create an AWS Account.**
3. You need three things: an email address **not already used for an AWS account** (Gmail
   accepts `you+killswitch@gmail.com` as a distinct address), a credit or debit card, and a
   phone number for verification.
4. Pick the **Basic support plan** — it is free.
5. Sign in. The email and password you just created are your **root user**, the most
   powerful identity in the account.

**You should see:** the AWS Management Console home page.

**Write down your 12-digit account ID.** Click your name in the top-right corner — it's
listed there. You need it in stage 5, and every script in this project refuses to run
against any other account.

---

## Stage 2 — Set a budget alarm before anything else

Do this now, while the account is still empty. It is the single most valuable five minutes
in this guide.

1. Search **Billing and Cost Management** in the top search bar.
2. In the left sidebar: **Budgets** → **Create budget**.
3. Choose **Zero spend budget** if you see it (alerts on the first cent), or **Customize**
   → **Cost budget** with a monthly amount of **$5**.
4. Enter your email for the alert.
5. **Create budget.**

**You should see:** one budget listed, status Active.

While you are in Billing: **Billing preferences** → turn on **Receive Free Tier alerts**.

> Budget alarms *notify*; they do not *stop* spending. Nothing in AWS automatically caps
> your bill. The alarm is a smoke detector, not a sprinkler.

---

## Stage 3 — Create a user for yourself, instead of using root

The root user can do anything, including closing the account, and its credentials can't be
scoped down. Never use it day to day, and never create access keys for it.

1. Search **IAM** → **Users** → **Create user**.
2. Name: `killswitch-operator`. Tick **Provide user access to the AWS Management Console**,
   choose **I want to create an IAM user**, and set a password.
3. **Next** → **Attach policies directly** → tick **AdministratorAccess**.

   *(Admin is broader than ideal. It is the right call here: this is a throwaway account
   with nothing in it, and fighting IAM permissions is not what you have deadline hours
   for.)*
4. **Create user.** Download or copy the sign-in URL.
5. Sign out of root, sign in as `killswitch-operator`, and **use this user from now on**.

**You should see:** the console again, with `killswitch-operator @ <account-id>` in the
top-right corner instead of your root email.

---

## Stage 4 — Give the CLI a key

Your laptop needs credentials to deploy. These belong to `killswitch-operator`, not root.

1. **IAM** → **Users** → `killswitch-operator` → **Security credentials** tab.
2. **Create access key** → **Command Line Interface (CLI)** → tick the confirmation →
   **Next** → **Create access key**.
3. You now see an **Access key ID** and a **Secret access key**. The secret is shown
   **once**. Leave the page open for the next step.

Then, in your terminal:

```bash
aws configure
```

Paste the key id and secret when prompted. Region: `ap-south-1`. Output format: `json`.

> **Type these into the `aws configure` prompt yourself.** Don't paste them into a chat, a
> file, a commit, or a message to me. `aws configure` writes them to `~/.aws/credentials`,
> which is outside the repository and outside anything I read.

Verify:

```bash
aws sts get-caller-identity
```

**You should see:** JSON with your 12-digit `Account` and an `Arn` ending in
`user/killswitch-operator`. If the account number doesn't match what you wrote down in
stage 1, stop — you are pointed at the wrong account.

---

## Stage 5 — Fill in `.env`

```bash
cd /path/to/KILLSWITCH
cp .env.example .env
```

Open `.env` and set:

```
AWS_REGION=ap-south-1
AWS_SECONDARY_REGION=us-east-1
DEMO_ACCOUNT_ID=<your 12-digit account id from stage 1>
DEMO_BUDGET_ALARM_EMAIL=<the email you used in stage 2>
```

Leave the rest blank for now — stages 6 and 7 fill them in.

`.env` is in `.gitignore` and will not be committed. Check it yourself if you want to be
sure: `git check-ignore -v .env` should print a match.

**You should see:** `make check` still passing.

---

## Stage 6 — Turn on a Bedrock model

Bedrock ships with **no models enabled**. You have to request access per region, and
availability differs between regions — so find out what your region actually has rather
than guessing:

```bash
aws bedrock list-foundation-models --region ap-south-1 \
  --by-provider anthropic --query "modelSummaries[].modelId" --output table

aws bedrock list-inference-profiles --region ap-south-1 \
  --query "inferenceProfileSummaries[].inferenceProfileId" --output table
```

Then enable one:

1. Console → search **Bedrock** → confirm the region selector (top right) says
   **Asia Pacific (Mumbai) ap-south-1**.
2. Left sidebar → **Model access** → **Modify model access** (or **Enable specific models**).
3. Tick a Claude model that appeared in the list above → **Next** → **Submit**.
4. Wait for its status to become **Access granted**. Usually seconds.

Put the exact id into `.env`:

```
BEDROCK_MODEL_ID=<paste the id from the list above>
```

Bedrock model ids carry an `anthropic.` prefix (for example `anthropic.claude-sonnet-5`).
Cross-region inference profiles add a geography prefix on top — `apac.` in Mumbai, `us.` in
the US regions. Use whatever the two commands above actually printed; do not type one from
memory.

**If no Claude model is available in ap-south-1**, you have two options:

- Set `AWS_REGION=us-east-1` in `.env` and run the whole demo there instead. Simplest.
- Or skip Bedrock for now and deploy with `NARRATOR_MODE=rehearsal`, which uses the fixed
  narrator and needs no model at all. You lose the live-model part of the demo but
  everything else works, including the verifier rejection.

> `BEDROCK_MODEL_ID` is not optional. `KillswitchResponse` refuses to synthesize without it
> rather than deploying a workflow guaranteed to fail — unless you set
> `NARRATOR_MODE=rehearsal`.

---

## Stage 7 — Create the private demo repository

**This is a hard safety boundary. Read it twice.**

Your KILLSWITCH repo is **public**. The demo repo is the one a real AWS key gets committed
to. These must be **two different repositories**, and the demo one must be **private**.

```bash
gh repo create killswitch-demo-target --private --clone
```

Then set in `.env`:

```
GITHUB_DEMO_REPO=<your-github-username>/killswitch-demo-target
GITHUB_WEBHOOK_SECRET=<any long random string you invent>
GITHUB_APP_TOKEN=<a GitHub personal access token with read access to that private repo>
```

For the webhook secret, generate one rather than inventing it by hand:

```bash
openssl rand -hex 32
```

> **Never push a real AWS key to a public repository** — not to test, not for a second, not
> "I'll delete it after". GitHub is indexed within seconds and deletion does not unpublish
> it. This is safety rule 4 in `CLAUDE.md`, and it is the rule most likely to cost you real
> money if broken.

---

## Stage 8 — Bootstrap and deploy

From here, `docs/RUNBOOK.md` takes over — it has the exact commands. The order is:

1. `make lambda-package` — builds the Lambda asset for Linux (it refuses to finish if it
   picks up macOS binaries).
2. `npx aws-cdk@2 bootstrap` — once per account and region. Creates the staging bucket CDK
   uploads through. Skipping it makes the first deploy fail with a confusing SSM-parameter
   error.
3. Deploy the stacks: `KillswitchDemoTarget`, `KillswitchDetection`, `KillswitchResponse`,
   `KillswitchConsoleApi`.

**Deploy one stack first and stop.** `KillswitchDemoTarget` is the smallest and creates only
an IAM user with a tightly scoped policy. If it succeeds, your account, credentials,
bootstrap and packaging are all correct, and the rest is mechanical.

```bash
export $(grep -v '^#' .env | xargs)
export CDK_DEFAULT_ACCOUNT=$DEMO_ACCOUNT_ID
npx aws-cdk@2 deploy KillswitchDemoTarget
```

**You should see:** `✅  KillswitchDemoTarget` and a stack ARN. Confirm in the console under
**CloudFormation** → **Stacks**.

---

## Stage 9 — Tear down when you are finished

Every recording session, without exception:

```bash
aws iam delete-access-key --user-name demo-leaky-user --access-key-id <the demo key id>
aws ec2 terminate-instances --region $AWS_REGION --instance-ids <ids>
aws ec2 terminate-instances --region $AWS_SECONDARY_REGION --instance-ids <ids>
```

And when the hackathon is over, destroy the stacks so nothing lingers:

```bash
npx aws-cdk@2 destroy --all
```

Then check **Billing** → **Bills** the next morning. A surprise there is the only way you
find out you missed something.

---

## When something breaks

| Symptom | Cause |
|---|---|
| `Unable to locate credentials` | `aws configure` not run, or run in a different shell/user |
| `sts get-caller-identity` shows the wrong account | You have another AWS profile active — check `AWS_PROFILE` |
| `SSM parameter /cdk-bootstrap/... not found` | Stage 8 step 2 (bootstrap) was skipped |
| `BEDROCK_MODEL_ID must be set` at synth | Stage 6 not finished, or `.env` not exported into this shell |
| `AccessDeniedException` calling Bedrock at the Narrate step | Model enabled in a different region than `AWS_REGION`, or the id in `.env` doesn't match what Bedrock granted |
| `lambda-package: host-native binaries` | You are on macOS and the platform pin was bypassed — do not `--no-deps` around it |
| Webhook deliveries return 401 | `GITHUB_WEBHOOK_SECRET` in the Lambda and in the GitHub webhook settings differ |

---

## What is still true, and worth remembering

Nothing in this repository has ever run against AWS. Every test uses in-memory fakes. The
first time you deploy, you are the first person to find out whether it works — expect to
debug, and budget time for that rather than assuming the first run is the recording.
