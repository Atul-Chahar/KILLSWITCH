# AI tools used

Both events require this disclosure. It was kept current during the build, not written at the end.

| Tool | What it was used for |
|---|---|
| Claude Code (Anthropic), Opus | Most of the implementation, under the constraints in `CLAUDE.md`. Every phase was reviewed by a human before commit |
| ECC plugin (MIT, github.com/affaan-m/ecc) | `/ecc:plan` before each phase, the `tdd-workflow` skill for `verifier/` and `containment/`, `/code-review` after each phase, and the `security-reviewer` agent before the freeze |
| Claude (chat) | Research on the hackathon rules, idea validation, architecture decisions |
| Amazon Bedrock, via the Strands Agents SDK | **Inside the product**, not in the toolchain: the narrator that writes the incident summary and proposes a containment plan. It has no tools and its output is re-checked by deterministic code before a human sees it |

## How it was used, honestly

The work was done phase by phase against `docs/PLAN.md`, with a prompt per phase in
`prompts/PROMPTS.md`. Three habits did most of the work:

- **Test-first where it mattered.** `verifier/`, `containment/` and `narrate/` each landed as
  a RED commit of failing tests followed by a GREEN commit of the implementation. The RED
  commits are `2fed8ce`, `81984f2`, `d91659f` and `c26d040`, and the failures are quoted in
  their commit bodies.
- **Every commit body states what was verified and what was not.** "Never claim something
  works that you have not run" is rule 7 of `CLAUDE.md`, and it is why the README's
  limitations section is as long as it is.
- **The SDK was read, not assumed.** The decision to disable Strands' structured-output retry
  came from reading the installed `strands-agents` 1.56.0 source, where a pydantic
  `ValidationError` is handed back to the model as a tool error so it can try again. The
  documentation did not say that.

## Human work

Architecture decisions, the safety model, the AWS account setup, all demo runs, the video,
and review of every change before it was committed.
