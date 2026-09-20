# Technical Limitations & Unverified Edges

A system claiming safety must be transparent about its boundaries. This document catalogs all 22 known limitations, unverified assumptions, and structural trade-offs in KILLSWITCH.

---

## 1. Execution & Environment Boundaries

1. **Zero Live AWS Executions to Date**: Every test in the repository executes against in-memory fakes, moto stubs, or synthetic payloads. The Step Functions workflow, Bedrock model invocations, CloudTrail lookups, and API Gateway endpoints have not been executed against a live AWS deployment.
2. **Synthetic CloudTrail Fixtures**: The test fixtures in `tests/fixtures/*.json` were authored by hand against AWS API documentation specifications rather than recorded from live AWS API calls.
3. **Simulated Quarantine Trigger**: AWS Compromised Key Quarantine only activates when keys leak on public, monitored endpoints. Because our demo repository is private (per safety rules), the EventBridge quarantine trigger is simulated via `scripts/simulate_quarantine.py`.
4. **Mobile Layout Verified via Emulation**: The mobile viewport screenshot in `evidence/console-and-landing-mobile-390px.png` was captured inside a 390px browser iframe. It has not been tested on physical iOS or Android hardware.

---

## 2. CloudTrail & Evidence Latency

5. **CloudTrail Ingestion Lag**: AWS management events typically appear in `LookupEvents` between 5 and 15 minutes after execution. While detection occurs seconds after a git push, the blast radius cannot be constructed until AWS indexes the events. KILLSWITCH implements a polling loop (60s sleep x 15 attempts), meaning containment speed is fundamentally bound by AWS CloudTrail delivery latency.
6. **Incomplete Evidence vs. Clean Incidents**: When the CloudTrail polling loop times out without finding events, it marks the blast radius with `evidence_not_yet_available` rather than returning an empty list. While this prevents the incident from reporting as "all clear", it does not resolve the underlying evidence gap.
7. **Fixed 3-Hour Lookback Window**: The CloudTrail lookup queries events from the preceding 3 hours across 2 regions. Attacker actions occurring prior to this window or outside the two monitored regions are invisible to the verifier.
8. **Role Chaining Blindspot**: The investigation queries CloudTrail using a single `AccessKeyId`. If an attacker immediately invokes `sts:AssumeRole` or `sts:GetSessionToken`, subsequent API calls occur under temporary session keys. Those actions are invisible to the initial query, making the incident appear clean despite active exploitation.

---

## 3. Threat Model & Attacker Persistence

9. **Incomplete Attacker Persistence Coverage**: The system reconstructs actions for `RunInstances` and `CreateAccessKey`. If an attacker executes `iam:CreateUser`, `iam:AttachUserPolicy`, `iam:CreateRole`, or creates console login profiles, KILLSWITCH does not capture or terminate those persistence mechanisms.
10. **Static Blast Radius During Operator Review**: The blast radius is captured once prior to generating the plan. If the attacker spawns additional instances while the human operator is reviewing the proposed plan, those instances are omitted from the containment actions.
11. **Auto Scaling Group Blindspot**: Terminating an EC2 instance that belongs to an Auto Scaling Group (ASG) causes the ASG to launch a replacement instance immediately. KILLSWITCH does not inspect Auto Scaling groups or suspend launch processes.
12. **Scope Restricted to Compute & Credentials**: KILLSWITCH does not track or contain actions affecting S3 buckets, Lambda functions, RDS databases, or DynamoDB tables.

---

## 4. Safety & Verification Guarantees

13. **Verifier Inability to Detect Omission**: The verifier can only validate actions that are present in the proposed plan. If a compromised or hallucinating model proposes an empty plan, the plan passes verification clean. The system relies on UI warning badges to alert the human operator to unaddressed resources.
14. **Untrusted Model Prose**: While the verifier strips unauthorized actions from the machine payload, it does not sanitize the natural language `summary` or `reason` fields written by the model. A model attempting to deceive an operator could still include misleading text inside its summary.
15. **Strict 1-Turn Failure Mode**: Because Strands retry mechanisms are disabled (`limits={"turns": 1}`), a model that outputs malformed JSON or natural language prose fails the step immediately. No second chance is given, which may increase false-negative execution failures during high LLM latency.

---

## 5. Scale & Operator Controls

16. **Per-Action Approval at Scale**: The console requires an explicit decision per proposed action. For an incident involving 200 EC2 instances across 5 regions, an operator would have to execute 200 individual approvals.
17. **Lack of Fine-Grained RBAC**: Cognito authentication secures API routes, but any authenticated operator can approve any incident. There is no four-eyes principle (multi-operator quorum) or role-based delegation.
18. **Tamper-Evident, Not Tamper-Proof Audit Trail**: DynamoDB audit log items are append-only by software convention, but the table does not enforce cryptographically immutable write-once (WORM) hardware storage.

---

## 6. Permissions & IAM Scope

19. **Wildcard Bedrock Invocation ARN**: The narrator Lambda role grants `bedrock:InvokeModel` on `Resource: "*"` because foundation model ARNs vary across inference profiles and regions.
20. **Regional EC2 Termination Permissions**: `ec2:TerminateInstances` is scoped to monitored regions, but cannot use resource tags because attacker-spawned instances carry no predefined organization tags.
21. **Unverified IAM Session Revocation Condition**: Containment attaches an inline policy with an `aws:TokenIssueTime` condition to revoke sessions. While verified against in-memory fakes, IAM propagation latency and session invalidation behavior have not been benchmarked against live AWS accounts.
22. **Stubbed GitHub PR Engine**: `containment/actions.py:open_pull_request` raises `NotImplementedError`. It records an unconfirmed outcome rather than generating a live pull request.
