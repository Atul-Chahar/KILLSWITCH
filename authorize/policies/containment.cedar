// KILLSWITCH authorization policy, in Cedar.
//
// Reading evidence and tagging are things the workflow may do on its own: they are
// reversible and they create no cost. Everything destructive is forbidden to the
// automation unless a human has already approved that specific action, which is the
// rule CLAUDE.md states and the reason this project exists.
//
// The forbid is written with `unless`, so it holds even if a permit policy is added
// later that would otherwise allow the action: in Cedar, a forbid always wins.

permit (
    principal == Killswitch::Automation::"workflow",
    action in [Killswitch::Action::"read_evidence", Killswitch::Action::"tag_resource"],
    resource
);

forbid (
    principal,
    action in [
        Killswitch::Action::"deactivate_key",
        Killswitch::Action::"terminate_instance",
        Killswitch::Action::"open_pr"
    ],
    resource
)
unless { context.human_approved == true };
