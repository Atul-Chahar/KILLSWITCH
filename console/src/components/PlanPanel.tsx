import { actionSignature } from "../signature";
import type { Decision, Incident, RejectionReason } from "../types";

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

interface Props {
  incident: Incident;
  decisions: Record<string, Decision>;
  needsHuman: (actionType: string) => boolean;
  onDecide: (signature: string, decision: Decision) => void;
  disabled: boolean;
}

export function PlanPanel({ incident, decisions, needsHuman, onDecide, disabled }: Props) {
  const verification = incident.verification;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>What KILLSWITCH proposes</h2>
        <span className="pill verified">Verified against the evidence</span>
      </div>

      {incident.summary && (
        <blockquote className="model-prose">
          <span className="chip untrusted">Written by the model, not evidence</span>
          {incident.summary}
        </blockquote>
      )}

      {!verification ? (
        <p className="muted">No plan has been verified yet.</p>
      ) : (
        <>
          <ul className="actions">
            {verification.approved.map((item) => {
              const signature = actionSignature(item.action);
              const decision = decisions[signature];
              const humanRequired = needsHuman(item.action.action_type);
              return (
                <li key={signature} className={decision ? `decided ${decision}` : ""}>
                  <div className="action-head">
                    <span className="action-type">
                      {item.action.action_type.replace(/_/g, " ")}
                    </span>
                    <span className="mono target">{item.action.target}</span>
                    {item.action.region && <span className="chip">{item.action.region}</span>}
                  </div>

                  {item.evidence ? (
                    <p className="evidence-line mono">
                      {item.evidence.event_name} at {item.evidence.event_time.slice(11, 19)} UTC,
                      event {item.evidence.event_id.slice(0, 8)}
                    </p>
                  ) : (
                    <p className="evidence-line muted">Subject of the incident itself</p>
                  )}

                  {humanRequired ? (
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
                    </div>
                  ) : (
                    <p className="muted small">Policy allows this without a human.</p>
                  )}
                </li>
              );
            })}
          </ul>

          {verification.rejected.length > 0 && (
            <>
              <h3 className="rejected-head">Struck out by the verifier</h3>
              <ul className="actions rejected">
                {verification.rejected.map((item, index) => (
                  <li key={`${item.action.target}-${index}`}>
                    <div className="action-head">
                      <span className="action-type struck">
                        {item.action.action_type.replace(/_/g, " ")}
                      </span>
                      <span className="mono target struck">{item.action.target}</span>
                    </div>
                    <p className="reason">{REJECTION_TEXT[item.reason] ?? item.reason}</p>
                  </li>
                ))}
              </ul>
            </>
          )}

          {verification.evidence_incomplete && (
            <p className="warning small">
              Some evidence could not be read, so this plan may be incomplete.
            </p>
          )}
        </>
      )}
    </section>
  );
}
