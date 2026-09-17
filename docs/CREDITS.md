# Credits

Open-source libraries, templates and prior art we used or learned from. Add a row whenever you pull something in.

| Thing | Where it came from | How we used it |
|---|---|---|
| AWS CDK v2 | aws/aws-cdk (Apache 2.0) | All four stacks, and `aws_cdk.assertions` for the tests that assert the safety boundary |
| boto3 / botocore | boto/boto3 (Apache 2.0) | Every AWS call. Provided by the Lambda runtime, not bundled |
| Strands Agents SDK 1.56 | strands-agents/sdk-python (Apache 2.0) | The narrator agent and its Bedrock model provider |
| pydantic v2 | pydantic/pydantic (MIT) | Every typed record that crosses a module boundary |
| Vite + React + TypeScript | vitejs (MIT), facebook/react (MIT) | Console. No component library: the CSS is ours |
| vitest | vitest-dev/vitest (MIT) | Console tests |
| pytest, ruff, mypy, uv | pytest-dev (MIT), astral-sh (MIT), python/mypy (MIT), astral-sh/uv (MIT/Apache 2.0) | The `make check` gate |
| Cedar | cedar-policy/cedar (Apache 2.0), via Amazon Verified Permissions | The policy that says destructive actions need a human |
| ECC | affaan-m/ecc (MIT) | Engineering workflow for Claude Code |

AWS's documented example access key `AKIAIOSFODNN7EXAMPLE` is used throughout the tests and
fixtures on purpose: it is published by AWS as an example, it is not a credential, and using
it means no real key ever needed to exist for a test to run.

## Prior art we are not copying, and how we differ

| Existing thing | How KILLSWITCH differs |
|---|---|
| AWS compromised key quarantine | Applies to keys AWS detects; does not terminate attacker resources, clean the repo, or explain the incident |
| GitHub push protection and secret scanning | Prevention on one platform. We handle the case where the key is already out |
| GitGuardian and similar | Alerting. We investigate, contain under human approval, and verify the end state |

## Research referenced

- Unit 42 (Palo Alto Networks), *EleKtra-Leak*: exposed IAM keys found and used within five
  minutes, with EC2 instances launched across regions roughly seven minutes later. This is
  the timeline the whole project is built around
- The Register's coverage of the same campaign
- AWS documentation on the compromised-key quarantine policy, which is where the second
  trigger's event shape comes from
- The Strands Agents SDK source, read directly for its structured-output retry behaviour
