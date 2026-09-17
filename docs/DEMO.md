# KILLSWITCH demo and video script

## Safety setup before anything runs

1. Dedicated AWS account, nothing else in it. Budget alarm at a low amount, email alert on.
2. `demo-leaky-user` can only run `t3.micro` instances, only in the two demo regions, enforced by an IAM condition. Nothing else.
3. The "leaked" repository is **private**. KILLSWITCH's own webhook watches it. Never push a live key to a public repo.
4. Rotate and delete the demo key and user after the recording.
5. Blur or redact the account id in the video and in screenshots.
6. Watch the final video once specifically looking for a visible secret before uploading.

## Rehearsal checklist

- [ ] Reset script empties the demo account (terminate instances, reactivate a fresh key)
- [ ] Full run twice without touching anything manually
- [ ] Console loads in a fresh browser session with no cached login
- [ ] Phone approval works on mobile data, not just campus Wi-Fi
- [ ] Have a recorded backup run in case the live one fails on camera

## The 3-minute video

| Time | Screen | Voiceover point |
|---|---|---|
| 0:00 to 0:20 | Headline about AWS keys being stolen from GitHub in minutes, a real surprise-bill post | This happens to students constantly |
| 0:20 to 0:50 | Split screen: commit pushed with a key, timer starts, attacker script launches instances in two regions | Attackers find keys in about five minutes. Here it takes seconds |
| 0:50 to 1:20 | KILLSWITCH console lights up: timeline, blast radius pulled from CloudTrail | We know exactly what the key did, from AWS's own audit log |
| 1:20 to 1:45 | Proposed plan, one row struck through by the verifier | The model proposes. Plain code checks ownership. It refuses to touch anything the leaked key did not create |
| 1:45 to 2:15 | Phone approval, key goes inactive, instances terminate, PR opens, timer stops | One human decision, then containment, then verification |
| 2:15 to 2:35 | The example key ignored; an action the human denied, left untouched and logged | It stops correctly too, which matters more than acting fast |
| 2:35 to 3:00 | Architecture diagram with AWS services highlighted, one line on what we learned | Step Functions approval tokens, CloudTrail forensics, Verified Permissions, Strands on Bedrock |

Rules for the recording: no dead air, no reading the README aloud, cursor moves with purpose, terminal font large enough to read on a phone.

## Questions judges will ask

| Question | Answer |
|---|---|
| Doesn't AWS already quarantine leaked keys? | Only keys it detects, and quarantine does not terminate what the attacker launched, clean the repository, or explain what happened. We use AWS's quarantine event as our second trigger |
| GitHub push protection blocks this | Only on GitHub, and it can be bypassed. Keys also leak through Discord, Postman collections and frontend bundles |
| Why not GitGuardian? | Those tools alert. We investigate, contain with a human in the loop, and verify the end state |
| Is an LLM deleting my resources safe? | The model never decides. It proposes, deterministic code verifies ownership, a policy decides what needs approval, a human approves |
| What if the agent is wrong? | Show the denial path in the video. Nothing destructive happens without approval, and every rejection is logged |
