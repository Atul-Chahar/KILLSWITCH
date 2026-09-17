# Prompts for Claude Code

Copy these one at a time. Do not paste two phases at once. After each phase: review, run the proof, commit.

---

## Setup (run in your terminal first)

```bash
mkdir killswitch && cd killswitch
git init
# copy the starter files (CLAUDE.md, README.md, docs/, scripts/, .claude/, .gitignore, .env.example) into this folder
cp .env.example .env         # fill it in later, never commit it
git add -A && git commit -m "chore: project context, rules and safety scripts"
gh repo create killswitch --public --source=. --push
claude
```

Inside Claude Code, confirm ECC is loaded with `/plugin` and check that `/ecc:plan` exists.

---

## P0 — Kickoff (the first prompt of the project)

```
Read CLAUDE.md, docs/hackathon-rules.md, docs/PLAN.md and docs/DEMO.md in full before doing anything.

Then, without writing any implementation code yet:

1. Tell me back, in under 15 lines: what we are building, the one rule the system is built on, and the three hard constraints you will hold yourself to.
2. List anything in those docs that is ambiguous, contradictory or technically wrong. Be blunt. I would rather fix a bad plan now than a bad repo tomorrow.
3. Check the versions and APIs we depend on actually exist as described: AWS CDK v2 Python, Step Functions waitForTaskToken with Lambda, Strands Agents SDK on Bedrock, Amazon Verified Permissions via boto3, CloudTrail LookupEvents filtering by AccessKeyId. Flag anything that does not work the way the plan assumes.
4. Propose the repository layout as a tree, with one line per directory saying what lives there.

Stop after that and wait for me. Do not create files yet.
```

## P0.5 — Scaffold

```
Create the repository layout we agreed, with empty modules and real pyproject/requirements, a working pytest setup, and a Makefile with: make install, make test, make lint, make check (runs scripts/check_secrets.sh, lint and tests).

No business logic yet. The only requirement is that `make check` runs and passes on an empty project.

Then commit with a clear message.
```

---

## P1 — The attack, reproducible

```
Use /ecc:plan for this phase first, then implement.

Phase 1 from docs/PLAN.md: build the thing we are defending against.

1. CDK stack DemoTargetStack: an IAM user demo-leaky-user whose policy allows only ec2:RunInstances, with an IAM condition restricting instance type to t3.micro, in exactly two regions, and nothing else. Include an explicit deny for everything outside that.
2. scripts/attacker.py: takes an access key id and secret from the environment, launches one t3.micro in each demo region, tags them demo=killswitch-attack, and prints a timeline with timestamps.
3. scripts/lookup.py: given an access key id, reads CloudTrail LookupEvents in both regions and prints every RunInstances event that key made.

Constraints: I run all AWS commands, not you. You write the code and tell me the exact commands to run. Nothing in this phase may touch an account other than the demo one, so read the account id from the environment and refuse to run if it does not match DEMO_ACCOUNT_ID.

Acceptance: after I run the attacker, lookup.py prints back exactly the instances it launched.
```

## P2 — Detection

```
Phase 2 from docs/PLAN.md. Write the tests first (ECC tdd-workflow skill).

1. Lambda `detect`: verifies the GitHub webhook signature, scans the pushed diff for AWS access key patterns, and writes an incident record to DynamoDB.
2. An EventBridge rule for AWS's quarantine-policy-attached event, writing the same incident shape.
3. Idempotency: the same access key id produces exactly one incident record no matter how many times either trigger fires.

Tests that must exist and pass:
- a real-looking key in a diff is detected
- AWS's documented example key AKIAIOSFODNN7EXAMPLE is ignored as a false positive
- an invalid webhook signature is rejected
- replaying the same event twice leaves one incident record

Do not call any real AWS service in unit tests. Stub the clients.
```

## P3 — Blast radius

```
Phase 3 from docs/PLAN.md.

Build investigate/: given an access key id, query CloudTrail LookupEvents across the demo regions and return a typed object (dataclass or pydantic) listing every resource that key created, with resource id, event name, region, event time and source IP. No free-form text anywhere in the return value.

Record two real CloudTrail responses from my demo run into tests/fixtures/ (I will paste them, or you generate them from a run I trigger), scrub account ids, and unit test against them.

Handle the boring failures honestly: pagination, a region with no events, an event with no resource id. A missing piece of evidence must never be turned into a success.
```

## P4 — The verifier (most important phase)

```
Phase 4 from docs/PLAN.md. Strict test-first, use the ECC tdd-workflow skill.

verifier/ contains pure functions. No AWS calls. No model calls. Ever.

Input: a proposed containment plan, plus the blast radius facts from phase 3.
Output: approved actions, and rejected actions each with a machine-readable reason.

Rules it enforces:
- an action may only target a resource that appears in the blast radius, created by this key
- the action type must be in an explicit allow list (deactivate_key, terminate_instance, open_pr)
- an action with a resource id that does not parse is rejected
- an empty plan is valid and results in no actions, not an error

Write these failing tests first, then make them pass:
- plan targeting an instance the leaked key did not create is rejected
- plan targeting an instance the key did create is approved
- unknown action type is rejected
- the rejection reason is specific enough to show in the UI

Then tell me, honestly, what a malicious or confused model could still get past this verifier.
```

## P5 — Approval and containment

```
Phase 5 from docs/PLAN.md.

1. Step Functions state machine tying detection, investigation, narration, verification, authorization, approval, containment and verification together. Approval uses waitForTaskToken.
2. Amazon Verified Permissions policy store: reads and tagging are auto-allowed, destructive actions require a human. If the Verified Permissions setup blocks us for more than 45 minutes, say so and fall back to the policy table described in the cut list, keeping the tiering visible.
3. containment/: deactivate_key, terminate_instances, open_pr. Each one:
   - refuses to run unless the incident record holds a valid approval token for that exact action
   - is idempotent
   - writes an audit row before and after
4. Post-action verification: re-read the key status and instance states from AWS and record the confirmed end state. If verification fails, the incident goes to a failed state. It never reports success it has not confirmed.

Acceptance: I run the demo, approve one action, deny another. The denied resource is untouched and the denial is in the audit log.
```

## P6 — The console

```
Phase 6 from docs/PLAN.md. This screen is our Best UI entry, so treat it as a product.

React + Vite + TypeScript, Cognito auth, deployed to Amplify Hosting.

One incident view:
- a timeline: key committed, first attacker API call, instances launched, detection, approval, containment
- the blast radius as a table
- the proposed plan, with verifier-rejected rows visibly struck through and their reason shown
- approve / deny per action, disabled until the policy says a human is required
- live status after approval, the confirmed end state, and the audit trail
- an estimated cost avoided

Rules: it must work on a phone (the video shows approval from a phone), states must never flicker between stale and fresh data, and errors must be visible rather than swallowed. No component library bloat; keep the bundle small and the styling clean and dark.
```

## P7 — The narrator agent

```
Phase 7 from docs/PLAN.md.

A Strands agent on Amazon Bedrock that takes the blast radius object and returns strict JSON: an incident summary for a human, and a proposed plan of actions.

- Validate the JSON against a schema. Invalid output fails the step. Never repair or guess.
- The agent has no write tools. It cannot act. It can only propose.
- Its output always goes through verifier/ before a human sees it.

Then add a demo path where the model proposes an action the verifier rejects, so we can show the guardrail working on camera.
```

## P8 — Proof, docs, video

```
Phase 8 from docs/PLAN.md.

1. Rewrite README.md in this order: one-line pitch, architecture diagram (mermaid), why this matters with the Unit 42 evidence, the safety model, the AWS services table with each service's job, quickstart, how to run the tests, limitations.
2. Limitations must be honest and specific. List what is simulated, what is untested, what would break at scale. Do not soften it.
3. Fill docs/AI-TOOLS.md and docs/CREDITS.md.
4. Put screenshots and a saved Step Functions execution graph in evidence/.
5. Write the AWS Builder Center blog draft in docs/blog.md: the problem, what we built, the three things that were harder than expected, what we learned.

Then run /code-review and the security-reviewer agent, fix what they find, and tell me what you chose not to fix and why.
```

---

## Reusable prompts

**End of each phase**

```
Before we commit: run make check. Then tell me in five lines what actually runs end to end right now, and what is still stubbed or untested. Be exact. If a piece is not proven, do not describe it as working.
```

**When it starts drifting or adding scope**

```
Stop. Re-read CLAUDE.md section 3 and docs/PLAN.md. Are you building something we agreed on? If the answer involves a new service, framework or abstraction, we are not doing it. Propose the smallest change that gets the current phase to its acceptance check.
```

**Before the freeze**

```
Act as a hostile hackathon judge scoring this repo on: idea and impact, built on AWS, learning demonstrated, execution quality, demo video. For each, give a score out of 5 and the single most damaging thing you would say about our project in front of the team. Then list the three cheapest fixes, in time order.
```

**If something breaks on demo day**

```
The demo failed at <step>. Do not refactor. Find the smallest change that makes the demo path work, explain the root cause in two lines, and tell me what it means for the limitations section.
```
