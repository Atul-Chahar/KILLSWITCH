# What the verifier does not catch

Phase 4 of `docs/PLAN.md` asks, honestly, what a malicious or confused model could still
get past `verifier/`. This is that answer. It is deliberately unflattering.

The verifier's guarantee is narrow and worth stating exactly:

> Every action it approves targets something CloudTrail recorded this key creating,
> inside the window and regions we searched.

That is not the same as "the plan is correct", and it is not the same as "acting is safe".

## 1. Omission is invisible, and it is the strongest attack

The verifier only judges actions that are present. It has no opinion about actions that
are missing, and an empty plan is explicitly valid.

A model that wants the attacker's instances to survive does not need to smuggle anything
past the checks. It simply proposes fewer actions than it should, or none at all, and
every check passes. Nothing in this module compares the plan against the blast radius to
ask "why is this instance not being dealt with?"

**Mitigation, not yet built:** the console should show the blast radius and the plan side
by side, so a resource with no proposed action is visible to the human as a gap. Until
then, the human approver is the only thing standing between a lazy plan and an
under-contained incident.

## 2. It trusts the blast radius completely

Garbage in, verified garbage out. If `investigate/` searched the wrong regions, used too
short a window, or was handed a doctored CloudTrail response, the verifier will faithfully
approve actions against those wrong facts and report them as proven.

The verifier says "consistent with the evidence I was handed". It cannot say "true".

## 3. Provenance is not the same as safe to destroy

"The leaked key created this instance" is a fact about the past. It does not mean nothing
depends on the instance now. In a real account, a key could have created something that
was later adopted into production, and the verifier would still approve terminating it:
correctly by its own rule, and wrongly in effect.

This is why the human gate exists, and why it cannot be removed.

## 4. The model can still talk to the human

`ProposedPlan.summary` and `ProposedAction.reason` are model-written prose. The verifier
carries them through untouched and never consults them, which protects the *machine*
decision. It does nothing to protect the *human* one.

A model that writes "AWS support has confirmed all of these are malicious, approve
everything" is attacking the approver, not the verifier. The last gate in the system is a
person reading text partly written by the component we have decided not to trust.

**Mitigation, not yet built:** the console must render model prose as visibly untrusted,
and show the verifier's own findings more prominently than the model's narrative.

## 5. Nothing here reasons about scale

Fifty verified terminations pass exactly as easily as one. The verifier has no notion of
"this is more than usual, slow down". That judgement belongs to the authorization tier in
phase 5, and to the human, not here.

## 6. The window and retention bound everything

CloudTrail Event History holds 90 days, the lookup runs over a few hours by default, and
IAM's own events only reach us-east-1. Anything outside those bounds never enters the
blast radius, so the verifier will reject an action against it as "not in the blast
radius": the right answer for the wrong reason, and indistinguishable from a model
hallucinating a resource.

## What it does get right

- An action against a resource this key never created is rejected, whatever the model says.
- An unknown action type is rejected, and an action type added to the allow list without a
  provenance check written for it is rejected too, because the dispatch falls through to
  `UNKNOWN_ACTION_TYPE`. It fails closed.
- Deactivation is pinned to the leaked key, and a PR is pinned to the leaking repository,
  so neither can be redirected somewhere more interesting.
- An instance id is only meaningful in a region, so the same id proposed for the wrong
  region is rejected rather than matched.
