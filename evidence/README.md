# Evidence

What is in here, and — just as importantly — what is not.

| File | What it is | What it proves |
|---|---|---|
| `test-output.txt` | A full `pytest -v` run plus the console's vitest run | 256 Python tests and 7 console tests pass. Every AWS client in them is an in-memory fake and every Strands agent is a stub |
| `state-machine-definition.json` | The Step Functions definition CDK **synthesizes** | The order of states, that the approval step is `lambda:invoke.waitForTaskToken`, and that an unconfirmed end state goes to `Fail`, not `Succeed` |
| `console-incident-fixture-mode.jpg` | The operator console, running locally against the bundled fixture | The incident view: timeline, blast radius, cost estimate, model prose labelled as untrusted, and the instance with no proposed action highlighted |
| `console-verifier-rejection-fixture-mode.jpg` | The same screen, scrolled to the plan | The verifier striking out `i-0999999999ffffff9` with "this leaked key never created it", next to the two actions it approved |

## What is missing, and why

- **There is no Step Functions execution graph**, because no execution has ever run.
  `state-machine-definition.json` is the synthesized definition, not a run. A real graph
  needs the demo AWS account and the deploy in `docs/RUNBOOK.md`.
- **The console screenshots are fixture mode**, and say so on screen in a banner. Nothing
  is deployed, Cognito has no users, and the approve button has never released a real task
  token. They show the screen, not a working system.
- **There is no mobile screenshot.** The window resize did not apply during capture. The
  console's phone layout is exercised by CSS at widths under 860px and has not been
  photographed. Capture it by hand: `cd console && npm run dev`, then a narrow window.
- **No CloudTrail evidence, no Bedrock response, no terminated instance.** All of that
  needs a run in the demo account.

## Reproducing what is here

```bash
make install && make console-install
make check
cd console && npm run dev        # the console in fixture mode, on localhost
```
