# KILLSWITCH

> Your AWS keys leaked. KILLSWITCH pulls the plug.

A leaked-credential responder: it catches an AWS key the moment it escapes, shows exactly what the attacker did with it, and after one human approval kills the key, terminates what the attacker launched and opens a PR that removes the secret.

Built for [First Commit](https://www.wemakedevs.org/aws/first-commit) (WeMakeDevs x AWS Builder Center), 17 to 20 September 2026, Ship It track.

**Live console:** TODO
**Demo video (3 min):** TODO

---

## The problem

Unit 42 tracked attackers pulling AWS keys off GitHub **within five minutes** of exposure, then launching EC2 instances across regions about seven minutes later. AWS auto-quarantines some leaked keys, but only the ones it detects, and quarantine does not terminate what the attacker already launched, clean your repository, or tell you what happened. For a student on a free-tier account, the first sign is the bill.

## What KILLSWITCH does

```
TODO: diagram
```

1. **Detects** the leak from two independent triggers: a repository push webhook, and AWS's own quarantine event.
2. **Investigates** using CloudTrail, building the exact list of resources that key created, with times and regions.
3. **Proposes** a containment plan, written by a Strands agent on Amazon Bedrock.
4. **Verifies** that plan with ordinary deterministic code that drops anything the leaked key did not create.
5. **Asks** a human, with the risky actions separated from the safe ones by policy.
6. **Contains and confirms**: key deactivated, instances terminated, PR opened, end state re-checked, everything written to an audit log.

## The rule the system is built on

**The model proposes. Plain code verifies. A human approves.**

The verifier contains no model calls. If the model suggests touching a resource the leaked key never created, the verifier strikes it and says why. Nothing destructive runs without an approval token.

## Safety model

```
READS                            HUMAN GATE                    WRITES
CloudTrail, IAM, repo diff  ──►  per-action approval  ──►  deactivate key
                                 (policy decides which)      terminate instances
                                                             open PR
                                                                  │
                                                                  ▼
                                                        post-action verification
                                                             + audit record
```

## AWS services used

| Service | Job |
|---|---|
| API Gateway | Receives the repository push webhook |
| EventBridge | Second trigger, on AWS's quarantine event |
| Lambda | Detection, investigation, containment steps |
| Step Functions | Orchestration and the `waitForTaskToken` human approval |
| Amazon Bedrock + Strands Agents SDK | Incident summary and proposed plan |
| Amazon Verified Permissions | Cedar policy deciding which actions need a human |
| CloudTrail | The evidence the whole investigation stands on |
| DynamoDB | Incident state and audit log |
| IAM | Key identification and deactivation |
| Amplify Hosting + Cognito | The operator console and its login |

## Quickstart

TODO

## Tests

TODO: how to run, and what the verifier tests prove

## Limitations

Be honest here. TODO, and keep it real.

## Credits and AI tools

See [docs/CREDITS.md](docs/CREDITS.md) and [docs/AI-TOOLS.md](docs/AI-TOOLS.md).
