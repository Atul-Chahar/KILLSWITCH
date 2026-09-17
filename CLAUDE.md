# KILLSWITCH — project context for Claude Code

Read this file fully before writing any code. Then read `docs/hackathon-rules.md`, `docs/PLAN.md` and `docs/DEMO.md`. If anything you are about to do conflicts with this file, stop and ask.

---

## 1. What we are building

**KILLSWITCH** is a leaked-AWS-credential responder.

> A student pushes AWS keys to GitHub. Bots find them in minutes and start crypto miners. KILLSWITCH catches the leak, shows exactly what the attacker did, and with one human approval kills the key, terminates the attacker's instances and opens a PR that removes the secret.

Why it matters: Unit 42 (Palo Alto Networks) documented attackers stealing AWS keys from GitHub within five minutes of exposure and launching EC2 instances across regions roughly seven minutes later. AWS does auto-quarantine some keys, but only ones it detects, and it does not terminate what the attacker launched, clean the repository, or explain what happened.

This is a hackathon project for **First Commit** (WeMakeDevs x AWS, Sep 17 to 20, Ship It track). A separate, freshly written version will be built for a different event on Sep 26 — **do not** write any code for that here.

## 2. The one rule that shapes the whole system

**The model proposes. Plain code verifies. A human approves.**

- A large language model may write summaries and *propose* a containment plan.
- `verifier/` is ordinary deterministic Python. It re-checks every proposed action against CloudTrail ownership facts and drops anything the leaked key did not create. It contains no LLM calls, ever.
- Destructive actions (deactivate key, terminate instances, open PR) only run after an explicit human approval.

If you are ever tempted to let the model decide what gets deleted, you have broken the project. This rule is what judges score under "approval thresholds and safety boundaries".

## 3. Architecture (do not redesign without asking)

```
GitHub push webhook ──► API Gateway ──► Lambda: detect (secret scan on the diff)
AWS quarantine event ──► EventBridge ──────────┐
                                               ▼
                                 Step Functions: response workflow
  1. identify      IAM ListAccessKeys / GetAccessKeyLastUsed  -> which user owns the key
  2. blast radius  CloudTrail LookupEvents by AccessKeyId, multiple regions
                   -> every resource that key created, with event time + region
  3. narrate       Strands agent on Amazon Bedrock: incident summary + proposed plan (JSON)
  4. verify        deterministic verifier: drop anything not created by this key
  5. authorize     Amazon Verified Permissions (Cedar): which actions need a human
  6. approve       waitForTaskToken, human approves in the web console
  7. contain       deactivate key, terminate attacker instances, open GitHub PR
  8. record        DynamoDB audit log, verified end state, estimated money saved
```

Two triggers, one idempotent workflow. Whichever fires first does the work; the second finds the incident already handled.

## 4. Stack (fixed)

| Layer | Choice |
|---|---|
| Infra | AWS CDK v2, Python |
| Lambdas | Python 3.12 |
| Orchestration | AWS Step Functions (standard, `waitForTaskToken` for approval) |
| Agent | Strands Agents SDK on Amazon Bedrock |
| Authorization | Amazon Verified Permissions (Cedar policies) |
| State and audit | DynamoDB (single table, incident id partition key) |
| Web console | React + Vite + TypeScript, AWS Amplify Hosting, Cognito for auth |
| Tests | pytest, with the verifier covered hardest |
| Region | ap-south-1 primary, plus one second region for the attack demo |

Do not add frameworks, queues, databases or services beyond this list without asking. Every service must earn its place in the video.

## 5. Hard safety rules (breaking any of these ends the project)

1. **Never commit a secret.** No real keys in code, tests, fixtures, logs, screenshots or the demo video. `scripts/check_secrets.sh` must pass before every commit.
2. **Demo runs in a dedicated throwaway AWS account** with a budget alarm. Never point KILLSWITCH at a personal or shared account.
3. The demo "leaked" IAM user is restricted by an IAM policy condition to `t3.micro` in two regions only.
4. **Never push a live key to a public repository**, even for testing. The demo repository is private and KILLSWITCH's own scanner watches it.
5. Destructive AWS calls (terminate, delete, deactivate) live in exactly one module, `containment/`, and each one refuses to run without an approval token in the DynamoDB record.
6. You (Claude Code) do not run destructive AWS CLI commands directly. Write the code, let the human run the demo.
7. Redact account IDs and ARNs in anything that gets published.

## 6. Hackathon rules that constrain how we work

From `docs/hackathon-rules.md`, the ones that affect every commit:

- **All code starts today, Sep 17.** No prior work, even rewritten. Libraries and templates are fine.
- Commit history must match the event window. Small, honest, well-messaged commits throughout, not one giant dump at the end.
- AWS usage must be **visible in the demo video**, not just described.
- AI tools used must be named in the write-up. Keep `docs/AI-TOOLS.md` current as we go, including ECC.
- Anything we did not write needs credit.

## 7. What "done" looks like (definition of done for every task)

A task is done when:

1. The code runs, and there is a way to prove it (a test, a script, or a screenshot in `evidence/`).
2. Deterministic logic has unit tests. The verifier has tests for both the accept and the reject path.
3. No secrets, and `scripts/check_secrets.sh` passes.
4. A commit exists with a clear message (`feat:`, `fix:`, `test:`, `docs:`, `chore:`).
5. `docs/PLAN.md` checkboxes reflect reality. Never tick a box for something that does not run.

**Never claim something works that you have not run.** If a step is untested, say so plainly in the commit body and in the README's limitations section. Two past winning projects both shipped an honest limitations section, and judges rewarded it.

## 8. Style

- Python: type hints everywhere, small pure functions in the verifier, no clever metaprogramming.
- Errors stay visible. Never swallow an exception to make a demo look clean. A missing piece of evidence must never be turned into a success.
- Comments explain why, not what.
- No dead code, no commented-out blocks, no "TODO later" left in the final submission.

## 9. Using ECC (installed plugin)

Use it in a focused way, not everywhere:

- `/ecc:plan` before each phase in `docs/PLAN.md`.
- `tdd-workflow` skill for `verifier/` and `containment/`. These two modules are where correctness matters most.
- `/code-review` after each phase is merged.
- `security-reviewer` agent before the final freeze, and after the containment module lands.
- Language reviewer for Python where useful.

Do not run broad refactor or "improve everything" commands. Scope creep loses hackathons. If ECC suggests a large restructure, note it in `docs/PLAN.md` and ask before doing it.

## 10. Working agreement

- Work phase by phase from `docs/PLAN.md`. Finish a phase and commit before starting the next.
- At the start of a phase, restate the goal and the acceptance check in one or two lines.
- If a phase is running long, say so and propose what to cut. The deadline is real and a working narrow demo beats a broken broad one.
- After every phase, update `README.md` if the architecture changed.
