# Credits

Open-source libraries, templates and prior art we used or learned from. Add a row whenever you pull something in.

| Thing | Where it came from | How we used it |
|---|---|---|
| AWS CDK v2 | aws/aws-cdk (Apache 2.0) | Infrastructure as code |
| Strands Agents SDK | strands-agents (Apache 2.0) | The narrator agent |
| Vite + React template | vitejs (MIT) | Console starter |
| ECC | affaan-m/ecc (MIT) | Engineering workflow for Claude Code |

## Prior art we are not copying, and how we differ

| Existing thing | How KILLSWITCH differs |
|---|---|
| AWS compromised key quarantine | Applies to keys AWS detects; does not terminate attacker resources, clean the repo, or explain the incident |
| GitHub push protection and secret scanning | Prevention on one platform. We handle the case where the key is already out |
| GitGuardian and similar | Alerting. We investigate, contain under human approval, and verify the end state |

## Research referenced

- Unit 42, EleKtra-Leak: exposed IAM keys used within five minutes
- The Register's coverage of the same campaign
