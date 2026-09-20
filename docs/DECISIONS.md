# Architectural & Design Decisions

This document records the architectural trade-offs, deliberate design constraints, and features cut during the development of KILLSWITCH, including the rationale behind each decision.

---

## 1. Key Decisions Made

### Decision 1: Deactivate Keys Rather Than Deleting Them
- **Choice**: Call `iam:UpdateAccessKey` to set status to `Inactive` rather than `iam:DeleteAccessKey`.
- **Rationale**: Deactivation achieves the immediate security goal (invalidating the credential for all subsequent API requests) while remaining fully reversible. If a credential was mistakenly flagged or belonged to an essential pipeline, an administrator can reactivate it. Furthermore, reusing `iam:UpdateAccessKey` avoids granting the containment role permanent deletion privileges in IAM.

### Decision 2: Hard 1-Turn Limit on Strands Agent
- **Choice**: Lock the Strands Agent on Amazon Bedrock to `limits={"turns": 1}`.
- **Rationale**: By default, Strands catches pydantic `ValidationError` exceptions and passes them back to the model as tool execution errors, allowing the model to self-correct and retry. In an untrusted setting where the model's output determines proposed infrastructure actions, allowing repeated retry attempts introduces a surface for negotiation or jailbreak attacks against the schema. We deliberately traded away model self-correction to enforce that the model either satisfies the schema immediately or fails closed.

### Decision 3: Rehearsal Narrator for Deterministic Demonstrations
- **Choice**: Implement `narrate/rehearsal.py` alongside the live Bedrock agent.
- **Rationale**: For video demonstrations and automated UI testing, we needed to demonstrate the verifier striking out an unauthorized action on camera. Attempting to prompt an LLM into reliably generating a hallucinated instance ID during a live recording is fragile and dishonest. The rehearsal narrator deterministically returns a plan with one unowned instance (`i-0999999999ffffff9`). To maintain absolute transparency, the UI prominently labels this with a banner: *"Rehearsal narrator, not a model and not evidence"*.

### Decision 4: Pure Function Verifier with AST-Checked Impurity Tests
- **Choice**: Keep `verifier/verify.py` as a pure Python module with zero external network or AWS SDK imports.
- **Rationale**: If the verifier could make external network or AWS calls, it would create an unpredictable dependency in the core safety layer. To ensure this isolation persists through future code changes, `tests/test_verifier.py:test_verifier_imports_are_pure` uses Python's `ast` module to inspect the module's imports during CI, failing if `boto3`, `strands`, or HTTP libraries are detected.

### Decision 5: Step Functions `waitForTaskToken` for Human Approval
- **Choice**: Orchestrate incident response using AWS Step Functions Standard Workflows and `waitForTaskToken`.
- **Rationale**: A human approval step cannot rely on polling or ephemeral webhooks. `waitForTaskToken` pauses execution state durably in AWS infrastructure without keeping compute resources active. The execution can safely wait for up to 1 hour (or longer) until an authorized operator inspects the evidence and submits a cryptographic approval token.

---

## 2. Features Evaluated and Cut (With Reasons)

### Cut 1: Automated Role Chaining & Recursive Session Resolution
- **Concept**: Recursively query CloudTrail for `sts:AssumeRole` or `sts:GetSessionToken` initiated by the compromised key, then investigate actions performed by those assumed role session credentials.
- **Why Cut**: 
  1. AWS CloudTrail `LookupEvents` enforces a strict rate limit of 2 transactions per second (TPS) per account per region. A recursive search spanning multiple assumed roles across multiple regions easily exhausts this rate limit.
  2. The Lambda investigation timeout is bounded at 60 seconds. A deep tree search of session credentials would cause timeouts and leave incidents in indeterminate states.
  3. Documented in [LIMITATIONS.md](LIMITATIONS.md) as Limitation 3.

### Cut 2: Real-Time Re-Investigation During Approval Wait
- **Concept**: Continuously re-poll CloudTrail while the state machine is paused in `waitForTaskToken`, updating the proposed plan if the attacker launches additional instances while the operator is deciding.
- **Why Cut**:
  1. Introducing dynamic target lists while a human is reviewing creates an unsafe race condition. An operator could review and approve a plan targeting 2 instances, only for a 3rd instance to be silently included and terminated without explicit review.
  2. Conversely, automatically removing resources if CloudTrail query results fluctuate would cause transient API errors to abort valid containment.
  3. The safe architecture requires an immutable plan per approval round; newly discovered actions must trigger a distinct, subsequent approval round.

### Cut 3: Automated GitHub Pull Request Opener
- **Concept**: Automatically generate and open a GitHub pull request removing the committed secret string from the repository diff.
- **Why Cut**:
  1. `containment/actions.py:open_pull_request` is structured and typed, but the underlying git mutation engine was intentionally stubbed to raise `NotImplementedError`.
  2. Automating git commit rewrites requires broad write access to user repositories, introducing risks of branch corruption or merge conflicts in production repos.
  3. Instead of returning fake PR URLs, `containment/end_state.py` explicitly marks unperformed PR actions as unverified, preserving the core promise of verified end states.

### Cut 4: Multi-Region Broad Sweeps
- **Concept**: Query all 17+ commercial AWS regions for attacker activity on every incident.
- **Why Cut**:
  1. Serial or parallel queries across 17+ regions for every incident would trigger immediate CloudTrail throttling and exceed Lambda execution timeouts.
  2. The system is bounded to monitored regions defined in configuration (`ap-south-1` and `us-east-1`), matching the scope of the demo attack script.
