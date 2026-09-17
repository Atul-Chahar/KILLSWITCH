import type { Incident } from "../types";

export function EndStatePanel({ incident }: { incident: Incident }) {
  const endState = incident.end_state;
  if (!endState || endState.targets.length === 0) return null;

  const allConfirmed = endState.targets.every((target) => target.confirmed);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Confirmed end state</h2>
        <span className={`pill ${allConfirmed ? "verified" : "danger"}`}>
          {allConfirmed ? "Confirmed with AWS" : "Not confirmed"}
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Action</th>
            <th>Target</th>
            <th>Observed</th>
          </tr>
        </thead>
        <tbody>
          {endState.targets.map((target) => (
            <tr key={`${target.action_type}-${target.target}`}>
              <td>{target.action_type.replace(/_/g, " ")}</td>
              <td className="mono">{target.target}</td>
              <td className={target.confirmed ? "mono ok" : "mono bad"}>
                {target.observed_state ?? target.aws_error_code ?? "unknown"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!allConfirmed && (
        <p className="warning small">
          KILLSWITCH re-read AWS and could not confirm every action. This incident is reported as
          failed rather than contained.
        </p>
      )}
    </section>
  );
}
