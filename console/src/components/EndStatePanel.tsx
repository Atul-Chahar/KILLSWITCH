import { maskCredential } from "../mask";
import type { Incident } from "../types";

export function EndStatePanel({ incident }: { incident: Incident }) {
  const endState = incident.end_state;
  if (!endState || endState.targets.length === 0) return null;

  const allConfirmed = endState.targets.every((target) => target.confirmed);

  return (
    <section className="panel">
      <div className="panel-head head-green">
        <h2>Confirmed end state</h2>
        <span className="panel-tag">{allConfirmed ? "CONFIRMED WITH AWS" : "NOT CONFIRMED"}</span>
      </div>

      <div className="end-head">
        <span>ACTION</span>
        <span>TARGET</span>
        <span>OBSERVED</span>
      </div>
      {endState.targets.map((target) => (
        <div className="end-row" key={`${target.action_type}-${target.target}`}>
          <span className="end-action">{target.action_type.replace(/_/g, " ")}</span>
          <span className="end-target" title={maskCredential(target.target) !== target.target ? "Redacted AWS credential" : undefined}>{maskCredential(target.target)}</span>
          <span className={target.confirmed ? "end-observed" : "end-observed end-observed-bad"}>
            {target.observed_state ?? target.aws_error_code ?? "unknown"}
          </span>
        </div>
      ))}

      {allConfirmed ? (
        <p className="end-foot">
          KILLSWITCH re-read AWS after acting. An unconfirmed action fails the execution rather
          than being rounded up to success.
        </p>
      ) : (
        <div className="warning">
          KILLSWITCH re-read AWS and could not confirm every action. This incident is reported as
          failed rather than contained.
        </div>
      )}
    </section>
  );
}
