# KILLSWITCH build plan

Rule: finish a phase, prove it, commit, then start the next. Never tick a box for something that has not run.

Time budget is in hours of actual work, not wall clock. The deadline is Sunday 20 Sep; aim to submit Saturday night.

---

## Phase 0 — Ground rules and repo (1 h, Thu 17)

- [x] `git init`, first commit today, repo pushed to `origin`
- [x] `CLAUDE.md`, `docs/`, `.gitignore`, `.env.example`, `scripts/check_secrets.sh` in place
- [ ] Dedicated demo AWS account created, budget alarm set at a low amount — **operator, not confirmed here**
- [x] `docs/AI-TOOLS.md` and `docs/CREDITS.md` started
- **Proof:** `scripts/check_secrets.sh` runs clean (`make check`), first commit timestamped 17 Sep
- Also done: module scaffold and `make install/test/lint/typecheck/check`, plus eight regression
  tests for the secret scanner after it was found to skip markdown entirely and to treat AWS's
  example key as a whole-file pass

## Phase 1 — The attack, reproducible (2 h, Thu 17)

Build the thing we are defending against first. Everything downstream needs real CloudTrail events to read.

- [x] CDK stack `DemoTargetStack`: an IAM user `demo-leaky-user` whose policy only allows `ec2:RunInstances` with a condition limiting instance type to `t3.micro`, in two regions
- [x] `scripts/attacker.py`: uses the demo key to launch instances in both regions and tag them, printing a timeline
- [ ] Confirm the events land in CloudTrail and can be read back by access key id — **needs a real run in the demo account**
- **Proof so far:** the stack synthesizes to CloudFormation with all seven statements and no
  access-key resource; 51 tests pass, covering the policy shape, the launch call, the
  demo-account guard, CloudTrail pagination and unreadable-evidence handling. Both scripts are
  unit tested against stubs and have **never been run against AWS**.
- **Still unproven:** everything that needs the demo account — the deploy, the launch, and the
  CloudTrail readback. Commands are in `docs/RUNBOOK.md`.
- **Commit:** `feat: reproducible demo attack and CloudTrail readback`

## Phase 2 — Detection (2 h, Thu 17 evening)

- [x] Lambda `detect`: receives a GitHub push webhook, scans the diff for AWS key patterns, verifies the signature header
- [x] EventBridge rule for the AWS quarantine policy attachment event as the second trigger
- [x] Both triggers write the same incident record to DynamoDB, idempotent on access key id
- [x] Unit tests: real key pattern found, AWS's documented example key `AKIAIOSFODNN7EXAMPLE` ignored, no duplicate incident on repeat delivery
- [x] Added beyond the plan: `investigate/identify.py`, because a quarantine event names a user
  and never a key, and `scripts/simulate_quarantine.py`, because AWS's real quarantine only reacts
  to public exposure and our demo repository is private
- **Proof so far:** 99 tests pass (36 written before the code, RED verified in `d91659f`); both
  stacks synthesize; the quarantine function's IAM grants are asserted to be read-only
- **Still unproven:** nothing has been deployed. A real push creating exactly one incident row
  needs the demo account.
- **Commit:** `feat: two triggers, one idempotent incident record`

## Phase 3 — Blast radius (2 h, Fri 18)

- [x] `investigate/` module: CloudTrail `LookupEvents` by access key id across the demo regions, collecting resource id, event name, region, time, source IP
- [x] Output is a typed object, not free text — `BlastRadius`, and even the failures are typed
      (`ProblemKind` enum plus an AWS error code, no prose anywhere in the return value)
- [x] Unit tests against CloudTrail fixtures, with a tested scrubber (`scripts/capture_fixture.py`)
- [ ] **The fixtures are synthetic, not recorded.** Nothing here has called AWS. They are written
      to the exact `LookupEvents` shape and must be replaced with real scrubbed captures after the
      first demo run — see `tests/fixtures/README.md`
- **Proof so far:** 112 tests pass. Pagination is followed, a failed region is recorded rather than
  swallowed, a read-only call creates nothing, and a creation event with no resource id is a
  recorded gap rather than an empty success.
- **Still unproven:** that the module returns exactly what the attacker launched. That needs phase 1
  to have actually run.
- **Commit:** `feat: blast radius from CloudTrail evidence`

## Phase 4 — Verifier (2 h, Fri 18) — the most important module

- [x] `verifier/`: pure functions, no AWS calls, no LLM. Input: proposed plan + blast radius facts. Output: approved actions, rejected actions with reasons
- [x] Rejects any resource not created by the leaked key
- [x] Rejects any action type not in the allow list, and fails closed for an allow-listed type
      with no provenance check written for it
- [x] Tests for both paths, including a plan that tries to touch a pre-existing instance
- [x] Purity is enforced by a test that parses the module and fails on a boto3, strands or
      HTTP import, rather than by a comment asking nicely
- [x] The honest answer to "what could still get past it" is written down in
      `docs/VERIFIER-LIMITS.md`. The short version: omission is invisible, and the model can
      still argue with the human even though it cannot argue with the verifier
- **Proof:** 24 verifier tests, written and failing before the module existed (`2fed8ce`),
  now passing as part of 135
- **Commit:** `test: verifier refuses actions the leaked key did not create`

Use the ECC `tdd-workflow` skill here. Write the failing test first.

## Phase 5 — Approval and containment (3 h, Fri 18)

- [x] Step Functions state machine wiring phases 2 to 7
- [x] Approval step uses `waitForTaskToken`; token stored on the incident record
- [x] Amazon Verified Permissions policy: reads auto, tagging auto, destructive requires human,
      with a strict fallback table when the policy store cannot answer
- [x] `containment/`: deactivate key, terminate instances, open GitHub PR removing the secret. Each function refuses to run without a valid approval token
- [x] Post-action verification: key status is `Inactive`, instances are `shutting-down` or `terminated`, PR url recorded
- [x] Audit rows written for every decision, including rejections and denials
- [ ] The GitHub PR opener itself is **not built**. `containment/open_pull_request` works and is
      tested, but the function that actually opens the PR raises `NotImplementedError` rather than
      returning a url nobody opened. This is cut-list item 2 if time runs out.
- **Proof so far:** 191 tests. The synthesized template is asserted to grant
  `ec2:TerminateInstances` and `iam:UpdateAccessKey` in exactly one statement, the containment
  function's, so the safety boundary is checkable by CI rather than by reading the code.
- **Still unproven:** the whole of it against AWS. No state machine has executed, no policy store
  exists, and the `waitForTaskToken` round trip has never run.
- **Commit:** `feat: human-gated containment with post-action verification`

## Phase 6 — The console (3 h, Sat 19, in person)

This screen is the Best UI entry. Treat it as a product, not a form.

- [x] React + Vite + TypeScript, Cognito login on every API route, built for Amplify Hosting
- [x] Incident view: timeline (leak, first attacker call, instances launched, detection), blast radius table, proposed plan with verifier decisions visible, approve or deny per action
- [x] Live status after approval, money-saved estimate, audit trail
- [x] Works on a phone: single column under 860px, 40px touch targets, safe-area padding
- [x] Two mitigations `docs/VERIFIER-LIMITS.md` called for: resources the plan ignored are
      highlighted in the blast radius table, and model prose is rendered in a marked
      "written by the model, not evidence" block
- [x] Fixture mode, so the screen can be rehearsed without an AWS account, with a banner
      saying so on screen rather than passing fixtures off as live data
- **Proof:** `make check` type-checks, tests and builds it. 56 KB gzipped, no component library.
- **Still unproven:** there is no live URL. Nothing is deployed, Cognito has no users, and the
  approve button has never released a real task token.
- **Commit:** `feat: operator console for approval and audit`

### Phase 6b — The design, implemented (Fri 18)

The Claude Design source (`KILLSWITCH.dc.html`) covers both a public page and a redesigned
console. Implemented in the existing React + Vite + TypeScript app — no new dependency, no
Next.js — because the stack is fixed and the console ships through Amplify.

- [x] Public page at `/`: the problem, the three-stage safety model, the guard table and the
      demo slot. The console opens at `/#console`, and `?incident=<id>` still opens it directly
- [x] Every factual claim on that page checked against the repository before shipping it:
      `tools=[]` and `limits={"turns": 1}` in `narrate/agent.py`, the Cedar policy file, the
      guard module and 21 verifier test functions all exist as named
- [x] Console rebuilt to the design: workflow rail, tinted panel heads, per-action cards
- [x] `console/src/stages.ts` + 7 tests. A stage is ticked because the record carries what
      that stage produces, never because the status field says so, and an **unconfirmed** end
      state leaves Confirm unfinished rather than rounding up to success
- [x] The prototype's scenario tabs were **not** implemented. They switch between invented
      incident states, and this console renders what the backend proved
- **Two real bugs found and fixed while doing it.** Fixture mode's refresh timer handed back
  the untouched fixture five seconds after an approval, wiping the contained screen off the
  demo; the fixture now persists what was submitted. And it never wrote the before/after audit
  entries that `containment/actions.py` writes, so the rail showed Contain unfinished on an
  incident that said CONTAINED.
- **Proof:** `make check`. Screenshots of both views, desktop and 390px, in `evidence/`.
- **Still unproven:** no real device has rendered the phone layout — the capture browser
  pinned its viewport width, so the mobile shot is a 390px iframe.
- **Commit:** `feat: implement the KILLSWITCH design — public page and rebuilt console`

## Phase 7 — The narrator agent (2 h, Sat 19)

- [x] Strands agent on Bedrock: takes the blast radius, writes the incident summary and a proposed plan as strict JSON
- [x] Schema validation on the output; invalid output fails the step rather than being patched up
- [x] The plan always passes through the verifier before any human sees an approve button
- [x] The agent is built with no tools at all, so it has nothing to act with
- [x] Wired into the state machine as `Narrate`, between `Investigate` and `Verify`. `Verify`
      now reads `event["plan"]` as a required key: an absent plan used to read as an empty
      one, which verifies clean and contains nothing
- [x] `narrate/rehearsal.py`, a fixed narrator that always proposes one unowned instance,
      so the verifier's rejection can be filmed without waiting for a model to misbehave.
      Which narrator ran is stored on the incident and labelled on screen
- [x] **Decision recorded, not assumed:** Strands implements structured output on Bedrock as
      a tool call and, by default, hands a pydantic validation failure back to the model as a
      tool error so it can retry. We switch that off with `limits={"turns": 1}`. The cost is
      that Strands' second-turn nudge for a model that replied in prose is disabled too, so
      such a reply fails the step. This was read from the installed strands-agents 1.56.0
      source, not from its documentation
- **Proof:** 34 narrator tests plus 6 more on the synthesized template, written and failing
  first (`c26d040`). The rehearsal plan is run end to end through `narrate_task` into
  `verify_task` in a test, and the verifier strikes out exactly one action.
- **Still unproven:** no model has ever been called. Every test uses a stub agent. Whether a
  real Bedrock model satisfies the schema on its first and only turn is unknown, and the
  one-turn decision makes that the riskiest untested thing in the project.
- **Commit:** `feat: model proposes, verifier disposes`

## Phase 8 — Proof, docs, video (4 h, Sat 19 evening to Sun 20)

- [x] README in the winner shape: one-line pitch, mermaid diagram, why it matters, safety
      model with a table of which test checks which guard, AWS services table, quickstart,
      tests, and twelve specific limitations
- [x] `evidence/`: console screenshots in fixture mode, the synthesized state machine
      definition, and the full test output. `evidence/README.md` says what each one proves
      and what is missing
- [ ] **No Step Functions execution graph**, because no execution has ever run. The
      synthesized definition is there instead, labelled as such
- [ ] **No mobile screenshot.** The browser window resize did not apply during capture;
      `evidence/README.md` has the command to take it by hand
- [x] Blog post drafted in `docs/blog.md`, for AWS Builder Center
- [x] `docs/AI-TOOLS.md`, `docs/CREDITS.md` final
- [ ] Record the 3-minute video per `docs/DEMO.md` — **operator**
- [ ] Publish the blog and the live URL — **operator**
- [x] Security review pass. No exploitable vulnerability introduced; the local filesystem
      path in `evidence/test-output.txt` was redacted, and the narrator's wildcard Bedrock
      resource is documented as README limitation 13 rather than silently left
- [x] Three real bugs found while reviewing, all fixed test-first. The worst was on the
      primary demo path: a key leaked by a GitHub push could never be deactivated, because
      `investigate_task` resolved the owning IAM user into the execution state and never
      wrote it to the incident, while `contain_task` re-reads the incident. Every existing
      test seeded `key_owner`, so nothing saw it. A second, same-seam bug: `confirm_task`
      never wrote the end state or the final status to DynamoDB, so the console sat on
      "awaiting approval" with an empty end-state panel however the incident finished. Both
      fixed. The other two:
      `ResponseStack` deployed happily without `BEDROCK_MODEL_ID` into a workflow certain to
      fail at Narrate, and `make lambda-package` had been building a **macOS** asset since
      phase 0 — `_pydantic_core.cpython-312-darwin.so` would have failed to import on Lambda
      on the first deploy. The asset is now pinned to `x86_64-manylinux2014` and the target
      refuses to finish if a host-native binary is in it
- [x] `tests/test_workflow_end_to_end.py`: the whole chain against in-memory AWS, written
      during the review pass because every other test covered one module and nothing covered
      the seams. Mutation-checked — deleting the approval guard fails three of its twelve.
      It paid for itself immediately: extending it to start at `investigate_task` rather than
      at a seeded incident is what exposed the key-owner bug
- [ ] `/code-review` pass, then freeze
- [ ] Submit — **operator**
- **Commit:** `docs: judge-facing README, evidence and limitations`

## Phase 9 — Adversarial review, and what it broke (Fri 18)

The project was reviewed as a hostile judge would: every claim attacked, every AWS
assumption questioned, no credit for passing unit tests. It found more than the friendly
reviews did, including one thing that invalidated the architecture diagram.

- [x] **Nothing started the workflow.** `DetectionStack` wrote an incident and stopped;
      `ResponseStack` built a state machine no code invoked. A repo-wide grep for
      `StartExecution` returned nothing. Every module test passed because every test called
      the tasks directly. Fixed with a DynamoDB stream into `workflow/start.py`: only the
      conditional write that wins produces an INSERT, so two triggers racing still start one
      execution, and the execution name makes a redelivered record harmless.
      `tests/test_start_workflow.py` (10 tests) and three template assertions in
      `tests/test_response_stack.py`
- [x] **CloudTrail is ~15 minutes behind and we queried it in seconds.** A real run would
      have found an empty blast radius and reported it as a clean incident. Investigate is
      now a poll with a `Wait` + `Choice` loop, and giving up empty-handed records
      `evidence_not_yet_available` per region so `evidence_incomplete` reaches the screen
      rather than an empty list that reads as "all clear"
- [x] **Deactivating a key does not lock the attacker out.** Sessions already minted from it
      stay valid for hours. Containment now also attaches a deny-all policy conditioned on
      `aws:TokenIssueTime` — what AWS's own revoke-sessions control does — and confirmation
      re-reads the policy, so `Inactive` alone can no longer be reported as containment
- [x] **`open_pr` confirmed itself.** `confirm_end_state` set `confirmed = True` for a pull
      request without checking that one was opened, and the opener raises `NotImplementedError`.
      The one module that exists to refuse unverified success was granting it. Now confirmed
      only by a recorded url
- [x] **A denied action failed the whole incident.** Confirmation re-read every verified
      target including ones the operator denied, found them alive, and reported `failed`.
      Confirmation now covers only what containment attempted, and a withheld action ends the
      incident `declined` — neither contained, because an attacker resource may still be
      running, nor failed, because nothing broke
- [x] The same key proposed with and without a region produced two signatures and two
      approval buttons. Only instances are region-scoped, so only they key on region
- [x] Destructive IAM is no longer account-wide: `ec2:TerminateInstances` is conditioned on
      the demo regions, and the IAM grants are scoped to `user/*` so the account root is out
      of reach. Asserted in `tests/test_response_stack.py`
- [x] **One criticism was wrong and is recorded as such.** "No retries are configured" —
      CDK gives every `LambdaInvoke` a default retry covering `Lambda.ServiceException` and
      siblings, and never `States.TaskFailed`. That is the policy we want. The redundant
      layer that had been added was removed, and a test now asserts the property instead of
      trusting the default
- [x] README limitations grew from 13 entries to 21, including three gaps found here and
      deliberately **not** fixed: role chaining defeats the blast radius entirely, an attacker
      who mints new credentials is invisible, and nothing re-investigates during the approval
      wait
- **Proof:** `make check` — 293 Python tests, 16 console tests. `evidence/state-machine-definition.json`
  regenerated and now shows the evidence loop and the declined branch.
- **Still unproven:** all of it, against real AWS. Session revocation, the stream trigger and
  the polling loop are unit-tested against fakes and have never met the services they name.
- **Commit:** `fix: the gaps an adversarial review found, with tests that prove each one`

## Phase 10 — Attacker persistence, adversarial proof, and the joins (Fri 18)

Scoped deliberately: the highest-impact items from a hostile audit, and nothing else.
Role chaining and post-approval re-investigation were considered and **cut** — reasons
below, because a cut with a reason is worth more than a half-built feature.

- [x] **`CreateAccessKey` is evidence now.** An attacker's first move with a working key is
      often to mint one of their own, and until this phase that key was invisible to every
      stage downstream: deactivating the leaked key left them exactly where they were. The
      blast radius carries a second resource kind, the verifier will approve deactivating a
      key it can show this incident creating, and containment resolves that key's owner
      separately because it is not the incident's user
- [x] **Deactivate, not delete.** `DeleteAccessKey` was the obvious action and is the wrong
      one: same effect, irreversible, and a new destructive IAM grant. `UpdateAccessKey ->
      Inactive` reuses the permission containment already has and can be undone if we were
      wrong about the key
- [x] `tests/test_narrate_adversarial.py` — 17 tests where the model proposes what it should
      not and plain code refuses: a hallucinated instance, the right instance in the wrong
      region, someone else's key, an unrelated repository, an action type KILLSWITCH does
      not have, six malformed targets, over-reach alongside a valid action, and the same
      action twice. The one approval in the file is the evidence-bound exception, asserted
      beside the rejections so it stays bound
- [x] `tests/test_integration_wiring.py` — 19 tests running a signed GitHub push all the way
      to a confirmed end state with nothing seeded, through the table stream and the real
      console API. Includes the deny path, the nobody-answered path, the superseded-token
      path, and a test that walks the synthesized definition to prove the runner follows the
      state order that is actually deployed
- [x] `scripts/capture_narration.py` — one real Bedrock call, the real verifier over its
      answer, scrubbed and written to `evidence/`. It labels itself as evidence the model was
      called and **not** evidence the verifier is correct, so the artefact cannot be read as
      a passing test
- [x] Containment gained `iam:GetAccessKeyLastUsed`, read-only, because an attacker-minted
      key belongs to whichever user they created it under

**Cut, with reasons:**

- **Role chaining** (`AssumeRole` -> session key -> downstream activity) is the largest
  evidence gap in the project and is documented as limitation 3. It was cut because it is
  invisible on camera unless the attack script is rewritten to use it, and because an
  unbounded key-by-key sweep across regions would not survive the 60-second Lambda timeout
  or CloudTrail's two-lookups-per-second limit. Doing it properly needs a bounded frontier
  and a claim change — "the leaked key, or a credential obtained with it" — not a patch.
- **Re-investigation after approval** was cut because the obvious implementation is unsafe
  in two directions. Acting on newly found resources would destroy things no human approved.
  Dropping approved actions whose evidence no longer verifies turns a transient CloudTrail
  failure into a denial of containment. The correct version drops only on positive
  contradiction and sends new findings to a second approval round; that is a phase, not a fix.

- **Proof:** `make check` — 333 Python tests, 16 console tests.
- **Still unproven:** every line of it against real AWS.
- **Commit:** `feat: see the credentials an attacker mints, and prove the verifier refuses the rest`

---

## Cut list (if time runs out, drop in this order)

1. Verified Permissions, replaced by a hardcoded policy table (keep the tiering visible in the UI)
2. The GitHub PR action, keep key deactivation and instance termination
3. The second region in the attack demo
4. The money-saved estimate

Never cut: the verifier, the approval gate, the denial path in the video, tests on the verifier.
