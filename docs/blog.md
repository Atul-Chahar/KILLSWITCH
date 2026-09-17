# We let an LLM propose deleting our AWS resources, then made sure it could never decide

*Draft for AWS Builder Center. Written during First Commit, 17 to 20 September 2026.*

---

## The problem is a timeline, not a technology

Unit 42 tracked attackers pulling AWS keys off GitHub **within five minutes** of exposure,
and launching EC2 instances across regions about seven minutes later. If you are a student
with a free-tier account and a public repo, the first thing you learn about your leaked key
is the bill.

AWS does quarantine leaked keys it detects. Quarantine is genuinely good and it is genuinely
narrow: it attaches a deny policy. It does not terminate the instances the attacker already
launched, it does not clean your repository, and it does not tell you what happened. The
commercial scanners mostly alert. Somebody still has to work out what the key touched, decide
what to destroy, destroy it, and check it worked.

So we built KILLSWITCH: detect the leak, rebuild the blast radius from CloudTrail, propose a
containment plan, verify it, ask a human, contain, and confirm.

## The one rule

**The model proposes. Plain code verifies. A human approves.**

Everyone building agents right now is negotiating some version of this. Ours is unusually
easy to state, because the dangerous verbs are so few: deactivate a key, terminate an
instance, open a PR.

- A Strands agent on Amazon Bedrock reads the CloudTrail evidence and writes a summary and a
  proposed plan. It is constructed with `tools=[]`. It has nothing to act with.
- `verifier/` is ordinary Python. It takes the proposed plan and the CloudTrail facts and
  drops every action whose target the leaked key did not create. It contains no model calls
  and no AWS calls, and a test parses the module and fails the build if it ever imports
  `boto3` or `strands`. A comment asking nicely would not have survived a deadline.
- `containment/` is the only module that destroys anything. Every function in it refuses to
  run without an approval token scoped to that exact action *and* that exact approval round.
- One statement in the whole CloudFormation template carries `ec2:TerminateInstances` and
  `iam:UpdateAccessKey`, and a test asserts that it is the containment function's. The safety
  boundary is checked by CI, not by reading the code.

## Three things that were harder than expected

### 1. The agent SDK self-corrects, and nobody tells you

Strands implements structured output on Bedrock as a tool call: your pydantic model becomes a
tool spec, and the model calls it. We assumed a schema violation would fail.

It does not. Reading the installed source, `StructuredOutputTool.stream` catches
`ValidationError` and returns it to the model as a tool error, with a comment saying the model
can "decide if it needs to retry". For a chatbot that is thoughtful. For a component whose
entire job is to be untrusted, it means the model gets to argue with the validator until it
gets through.

We disabled it with `limits={"turns": 1}`. One turn: the model either produces a valid plan
or the step fails.

The honest cost, which is in our README: Strands also uses a second turn to re-ask a model
that replied in prose instead of calling the tool, and we gave that up too. A prose reply now
fails the step. We traded availability for the guarantee that the model never gets a second
attempt at the schema. **Read your SDK's source before you rely on its failure mode.**

### 2. The verifier's real weakness is the thing it cannot see

We wrote 21 tests for the verifier, then sat down to answer "what could still get past this?"
honestly, in `docs/VERIFIER-LIMITS.md`.

The answer was uncomfortable. Every check is about actions that are *present*. A model that
wants the attacker's instances to survive does not need to smuggle anything past us — it just
proposes fewer actions than it should. An empty plan is valid and passes every check.

There is no clean fix inside the verifier, because "why is this instance not being dealt
with?" is a question about intent. What we did instead was make the gap visible: the console
shows the blast radius next to the plan and highlights any resource with no proposed action,
and the narrator's schema requires the `actions` list rather than defaulting it, so proposing
nothing has to be stated. Neither is a check. Both turn a silent nothing into a visible one.

The related one: the verifier protects the *machine* decision and does nothing for the
*human* one. A model that writes "AWS support has confirmed these are all malicious, approve
everything" is attacking the approver. So the console renders model prose in a block labelled
"Written by the model, not evidence", with the verifier's own findings outside it. It is a
label, not a guarantee, and we say so.

### 3. Being honest is a design constraint, not a disclaimer

The video needs to show the verifier rejecting an action. Our first instinct was to prompt the
model into proposing something unowned. That is staging a failure and presenting it as the
model's.

So we wrote a second narrator: a deterministic function, not a model, that always proposes one
instance the key never created. Which narrator ran is recorded on the incident and rendered on
the screen — "Rehearsal narrator, not a model and not evidence" — so a canned plan can never
be shown as a model's work.

The same pressure shaped the code. `confirm_end_state` re-reads IAM and EC2 after containment,
because "the API accepted my request" and "the key is inactive" are different claims. An
unconfirmed end state routes to `Fail`, never rounded up to `Succeed`. The PR opener is not
built, so it raises `NotImplementedError` and the action records a failure, rather than
returning a URL nobody opened.

## What we learned

- **Step Functions `waitForTaskToken` is the right shape for a human gate.** The execution
  genuinely stops. There is no timeout-and-proceed path in ours: on expiry it fails, and
  nothing is destroyed. The subtlety is ordering — the console writes decisions to DynamoDB
  *before* releasing the token, because containment re-reads those decisions, and the other
  order is a race.
- **CloudTrail forensics is mostly about honest failure handling.** Pagination, a region that
  errors, a creation event with no resource id. Each one is a chance to turn missing evidence
  into an empty success. We made every gap a typed `EvidenceProblem` on the result instead.
- **Cedar is a good fit for "which actions need a human"**, and the interesting part is the
  fallback: if the policy store cannot answer, we fall back to a strict table where anything
  destructive needs a person. A fallback that guessed "allow" would turn an outage into an
  unsupervised deletion.
- **Scoping an approval to an action *and* a round** matters more than it sounds. Without the
  round, a decision from a superseded approval could authorise something now.

## What is not true yet

At the time of writing, nothing in this repository has run against AWS. No stack is deployed,
no key has leaked, no model has been called. Every test runs against in-memory fakes and stub
agents. The README's limitations section lists twelve specific gaps, including that our
CloudTrail fixtures are synthetic and that the system only understands `RunInstances`.

We would rather ship that sentence than imply otherwise.

---

*Code: [github.com/…/killswitch](https://github.com). Built with Claude Code; the full AI
tool disclosure is in `docs/AI-TOOLS.md`.*
