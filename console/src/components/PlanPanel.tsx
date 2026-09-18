import { actionSignature } from "../signature";
import type { Decision, Incident, RejectionReason, TierDecision } from "../types";

// The console renders the reason, not the model's prose about it.
const REJECTION_TEXT: Record<RejectionReason, string> = {
  unknown_action_type: "not an action KILLSWITCH knows how to take",
  malformed_target: "the target is not a well-formed id",
  target_not_in_blast_radius: "this leaked key never created it",
  region_mismatch: "not created by this key in that region",
  key_mismatch: "not the key that leaked",
  repository_mismatch: "not the repository that leaked",
  duplicate_action: "already proposed once in this plan",
};

interface Settlement {
  label: string;
  tone: "good" | "bad";
}

// What actually became of an action, once the approval round is over. The audit trail is
// the authority; the local decision only fills in the gap between sending and the backend
// writing the entry back. Anything else renders nothing rather than a guess.
function settlementFor(
  incident: Incident,
  signature: string,
  decision: Decision | undefined,
): Settlement | null {
  const entries = incident.audit.filter((entry) => entry.action_signature === signature);
  if (entries.some((entry) => entry.stage === "after")) {
    return { label: "APPROVED BY THE OPERATOR, TOKEN SCOPED TO THIS ACTION.", tone: "good" };
  }
  if (entries.some((entry) => entry.stage === "refused")) {
    return { label: "REFUSED BY THE GUARD. NOTHING WAS RUN.", tone: "bad" };
  }
  if (entries.some((entry) => entry.stage === "failed")) {
    return { label: "EXECUTION FAILED. SEE THE AUDIT TRAIL.", tone: "bad" };
  }
  if (decision === "denied") {
    return { label: "DENIED BY THE OPERATOR. NOTHING WAS RUN.", tone: "bad" };
  }
  if (decision === "approved") {
    return { label: "APPROVED BY THE OPERATOR, TOKEN SCOPED TO THIS ACTION.", tone: "good" };
  }
  return null;
}

function tierNote(tier: TierDecision | undefined): string {
  if (!tier) return "no policy decision recorded — treated as human";
  if (tier.tier === "automatic") return "policy allows this without a human";
  return tier.source === "verified_permissions"
    ? "cedar: human required"
    : "fallback table: human required";
}

interface Props {
  incident: Incident;
  decisions: Record<string, Decision>;
  tierFor: (actionType: string) => TierDecision | undefined;
  onDecide: (signature: string, decision: Decision) => void;
  disabled: boolean;
  settled: boolean;
}

export function PlanPanel({ incident, decisions, tierFor, onDecide, disabled, settled }: Props) {
  const verification = incident.verification;

  return (
    <section className="panel">
      <div className="panel-head head-pink">
        <h2>What KILLSWITCH proposes</h2>
        <span className="panel-tag">VERIFIED AGAINST THE EVIDENCE</span>
      </div>

      <div className="plan-body">
        {incident.summary && (
          <blockquote className="prose">
            <span className="prose-chip">
              {incident.narrator === "rehearsal"
                ? "REHEARSAL NARRATOR, NOT A MODEL AND NOT EVIDENCE"
                : "WRITTEN BY THE MODEL, NOT EVIDENCE"}
            </span>
            <span className="prose-text">{incident.summary}</span>
          </blockquote>
        )}

        {!verification ? (
          <p className="panel-empty">No plan has been verified yet.</p>
        ) : (
          <>
            <ul className="actions">
              {verification.approved.map((item) => {
                const signature = actionSignature(item.action);
                const decision = decisions[signature];
                const tier = tierFor(item.action.action_type);
                const humanRequired = tier?.tier !== "automatic";
                const settlement = settled
                  ? settlementFor(incident, signature, decision)
                  : null;
                const shade =
                  decision === "approved"
                    ? " action-approved"
                    : decision === "denied"
                      ? " action-denied"
                      : "";

                return (
                  <li className={`action${shade}`} key={signature}>
                    <div className="action-head">
                      <span className="action-type">
                        {item.action.action_type.replace(/_/g, " ")}
                      </span>
                      <span className="action-target">{item.action.target}</span>
                      {item.action.region && (
                        <span className="action-region">{item.action.region}</span>
                      )}
                    </div>

                    <div className="action-body">
                      {item.evidence ? (
                        <p className="action-evidence">
                          {item.evidence.event_name} at {item.evidence.event_time.slice(11, 19)}{" "}
                          UTC, event {item.evidence.event_id.slice(0, 8)}
                        </p>
                      ) : (
                        <p className="action-evidence">Subject of the incident itself</p>
                      )}

                      {item.action.reason && <p className="action-reason">{item.action.reason}</p>}

                      {!settled && humanRequired && (
                        <div className="decide">
                          <button
                            className={decision === "approved" ? "approve chosen" : "approve"}
                            disabled={disabled}
                            onClick={() => onDecide(signature, "approved")}
                          >
                            Approve
                          </button>
                          <button
                            className={decision === "denied" ? "deny chosen" : "deny"}
                            disabled={disabled}
                            onClick={() => onDecide(signature, "denied")}
                          >
                            Deny
                          </button>
                          <span className="tier-note">{tierNote(tier)}</span>
                        </div>
                      )}

                      {!settled && !humanRequired && (
                        <p className="action-reason">{tierNote(tier)}.</p>
                      )}

                      {settlement && (
                        <p className={`settled settled-${settlement.tone}`}>{settlement.label}</p>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>

            {verification.rejected.length > 0 && (
              <div className="rejected-block">
                <h3>STRUCK OUT BY THE VERIFIER</h3>
                <ul className="actions">
                  {verification.rejected.map((item, index) => (
                    <li className="rejected" key={`${item.action.target}-${index}`}>
                      <div className="action-head">
                        <span className="action-type">
                          {item.action.action_type.replace(/_/g, " ")}
                        </span>
                        <span className="action-target">{item.action.target}</span>
                      </div>
                      <p className="rejected-reason">
                        {REJECTION_TEXT[item.reason] ?? item.reason}
                      </p>
                      <p className="rejected-code">{item.reason}</p>
                      <p className="rejected-note">
                        Proposed by the model. Dropped by <code>verifier/verify.py</code> before a
                        human ever saw a button for it.
                      </p>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {verification.evidence_incomplete && (
              <div className="warning">
                Some evidence could not be read, so this plan may be incomplete.
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
