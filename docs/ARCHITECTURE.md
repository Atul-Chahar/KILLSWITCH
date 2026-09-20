# Architecture Deep Dive

KILLSWITCH is an event-driven credential incident response pipeline designed to detect leaked AWS credentials, reconstruct their blast radius from audit trails, generate a verified containment plan, enforce a mandatory human approval gate, and execute confirmed containment actions.

---

## 1. End-to-End System Pipeline

```
GitHub Push Webhook ──► API Gateway ──┐
                                     ├──► Lambda (detect) ──► DynamoDB (incidents)
AWS Quarantine Event ─► EventBridge ─┘                             │
                                                                   ▼ (DynamoDB Streams: INSERT)
                                                             Lambda (workflow/start.py)
                                                                   │
                                                                   ▼
                                                     AWS Step Functions (Response Workflow)
                                                       │
                                                       ├─► 1. Investigate (IAM + CloudTrail Poll)
                                                       ├─► 2. Narrate (Bedrock Strands Agent)
                                                       ├─► 3. Verify (Pure Python Provenance Verifier)
                                                       ├─► 4. Authorize (Amazon Verified Permissions / Cedar)
                                                       ├─► 5. Approve (waitForTaskToken Gate)
                                                       │        ▲
                                                       │        │ Approval API (Cognito + API Gateway)
                                                       │        ▼
                                                       │     Operator Console (React / Vite)
                                                       │
                                                       ├─► 6. Contain (Token-gated Actions)
                                                       └─► 7. Confirm (Post-action AWS State Verification)
                                                                │
                                                                ├── [Confirmed] ─► Contained
                                                                └── [Unconfirmed] ─► Failed
```

---

## 2. Trigger Ingestion & Idempotency

### Dual Triggers
1. **GitHub Push Webhook**: An API Gateway HTTP endpoint receives push event payloads. Lambda `detect/webhook.py` validates the HMAC-SHA256 signature against the shared webhook secret, scans git diff commits for AWS credential patterns (`AKIA[0-9A-Z]{16}`), and rejects false positives (e.g. AWS documentation example key `AKIAIOSFODNN7EXAMPLE`).
2. **AWS Quarantine Event**: An Amazon EventBridge rule catches AWS's built-in `AWSCompromisedKeyQuarantine` policy attachment event, extracting the targeted IAM user.

### Idempotency Layer
Both triggers invoke `detect/handler.py`, which performs a conditional `PutItem` into DynamoDB partitioned by `incident_id = f"inc-{access_key_id}"`:
```python
attribute_not_exists(incident_id)
```
If both triggers fire simultaneously, exactly one write succeeds. The loser receives `ConditionalCheckFailedException` and terminates cleanly without duplicate downstream executions.

### Execution Decoupling
To eliminate tight coupling between detection and workflow orchestration, the DynamoDB incident table enables a DynamoDB Stream (`NEW_IMAGE`). Lambda `workflow/start.py` triggers only on `INSERT` records, starting the Step Functions execution with an execution name matching the incident ID. Replayed stream batches cannot create duplicate state machine executions.

---

## 3. Step Functions Response Workflow

The workflow (`infra/stacks/response.py`) is structured as a linear sequence with polling and branching logic:

| Stage | Lambda Function | Responsibility |
|---|---|---|
| **1. Investigate** | `workflow/tasks.py:investigate_task` | Identifies the key owner via IAM `ListAccessKeys` / `GetAccessKeyLastUsed`, then queries CloudTrail `LookupEvents` across monitored regions (`ap-south-1`, `us-east-1`). If events are missing, enters a 60-second `Wait` poll loop (up to 15 iterations) to account for CloudTrail delivery latency. |
| **2. Narrate** | `workflow/tasks.py:narrate_task` | Passes the structured `BlastRadius` object to a Strands Agent on Amazon Bedrock (`narrate/agent.py`). The agent runs with zero tools (`tools=[]`) and a strict 1-turn ceiling (`limits={"turns": 1}`), outputting a JSON incident summary and proposed action plan. |
| **3. Verify** | `workflow/tasks.py:verify_task` | Executes deterministic Python rules (`verifier/verify.py`). Validates every proposed action against CloudTrail evidence. Strikes out any resource not created by the leaked key with an explicit machine-readable rejection code. |
| **4. Authorize** | `workflow/tasks.py:authorize_task` | Evaluates proposed actions against Cedar policies in Amazon Verified Permissions (`authorize/policies/containment.cedar`). Read and tag actions are auto-authorized; destructive actions require human approval. |
| **5. Approve** | `workflow/tasks.py:approve_task` | Invokes `lambda:invoke.waitForTaskToken`, pausing state machine execution and storing the task token on the DynamoDB incident item. Pauses indefinitely until an operator acts via the console. |
| **6. Contain** | `workflow/tasks.py:contain_task` | Executes approved destructive actions (`containment/actions.py`): deactivates access keys, terminates attacker instances, and attaches an inline IAM deny policy to revoke active sessions. Each action verifies the presence of an approval token. |
| **7. Confirm** | `workflow/tasks.py:confirm_task` | Re-reads IAM and EC2 APIs to confirm the real end state. If any target fails verification, transitions the execution to `Fail`, preventing false success reporting. |

---

## 4. Operator Console & Approval API

- **Web Console**: A lightweight React 18 + Vite + TypeScript single-page application (`console/src/App.tsx`) with zero component library overhead. Features a live workflow progress rail (`WorkflowRail.tsx`), a chronological timeline (`Timeline.tsx`), a blast radius table with unaddressed resource highlights (`BlastRadiusPanel.tsx`), an action approval card list with verifier strike-outs (`PlanPanel.tsx`), and post-action verification metrics (`EndStatePanel.tsx`).
- **Auth & API**: Secured by Amazon Cognito User Pools. API Gateway routes `/incidents/{id}` (GET) and `/incidents/{id}/approve` (POST) are protected by a Cognito User Pool authorizer (`infra/stacks/console_api.py`).
- **Token Dispatch**: The approval payload records per-action decisions (`approved` or `denied`) into DynamoDB, updates the incident state, and dispatches `SendTaskSuccess` with the stored Step Functions task token.

---

## 5. Deployment Topology

The infrastructure is defined across four decoupled AWS CDK v2 stacks (`infra/app.py`):
1. `DetectionStack`: API Gateway webhook endpoint, EventBridge quarantine rule, DynamoDB incident table with Streams enabled, and detection Lambdas.
2. `ResponseStack`: Step Functions state machine, task Lambdas, Amazon Verified Permissions policy store, and the single IAM statement granting destructive privileges.
3. `ConsoleApiStack`: API Gateway REST API for operator inspection and approval, backed by Cognito authentication.
4. `DemoTargetStack`: The sandbox environment containing `demo-leaky-user`, an IAM policy conditioned to allow only `t3.micro` instances in two demo regions, and CloudTrail trail logging.
