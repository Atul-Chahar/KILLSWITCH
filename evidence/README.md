# Evidence

What is in here, and — just as importantly — what is not.

| File | What it is | What it proves |
|---|---|---|
| `test-output.txt` | A full `pytest` run plus the console's vitest run | 334 Python tests and 16 console tests pass. Every AWS client in them is an in-memory fake and every Strands agent is a stub |
| `state-machine-definition.json` | The Step Functions definition CDK **synthesizes** | The order of states, that the approval step is `lambda:invoke.waitForTaskToken`, and that an unconfirmed end state goes to `Fail`, not `Succeed` |
| `landing-page.jpg` | The public page at `/`, running locally | The pitch, the three AWS services named, and the console preview that opens the real thing |
| `console-incident-fixture-mode.jpg` | The operator console, running locally against the bundled fixture | The incident view: the workflow rail with Approve as the live stage, timeline, blast radius, cost estimate, model prose labelled as untrusted, and the instance with no proposed action highlighted |
| `console-verifier-rejection-fixture-mode.jpg` | The same screen, scrolled to the plan | The verifier striking out `i-0999999999ffffff9` with "this leaked key never created it", next to the two actions it approved |
| `narration-from-the-model.json` | One real Bedrock call and the verifier's verdict on it, written by `scripts/capture_narration.py` | **Not captured yet.** Until it is, nothing in this repository proves a model was ever called |
| `console-and-landing-mobile-390px.png` | Both views rendered at a 390px viewport | The phone layout: the rail unsticks and stacks, the nav collapses, and neither view scrolls sideways |
| `banner.png` | Project hero banner image | The public landing page showcasing the problem statement and the live console preview |

## What is missing, and why

- **There is no Step Functions execution graph**, because no execution has ever run.
  `state-machine-definition.json` is the synthesized definition, not a run. A real graph
  needs the demo AWS account and the deploy in `docs/RUNBOOK.md`.
- **The console screenshots are fixture mode**, and say so on screen in a banner. Nothing
  is deployed, Cognito has no users, and the approve button has never released a real task
  token. They show the screen, not a working system.
- **The mobile screenshot was taken in a 390px iframe**, not on a phone and not in a
  resized window — the capture browser pinned its viewport width regardless of the window
  size. The CSS media queries are the same ones a phone would match, and the layout was
  checked for sideways scroll at 360, 390, 700, 860, 1000 and 1440px, but no real device
  has rendered it.
- **No CloudTrail evidence, no Bedrock response, no terminated instance.** All of that
  needs a run in the demo account.

## Reproducing what is here

```bash
make install && make console-install
make check
cd console && npm run dev        # the public page and the console, in fixture mode
```
