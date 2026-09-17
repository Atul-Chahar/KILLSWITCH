import type { Incident } from "../types";

// Showing what the plan ignored is the point of this panel. The verifier can only judge
// actions that were proposed, so a resource with no action against it is invisible to it
// and has to be visible here instead.
function untouchedResourceIds(incident: Incident): Set<string> {
  const verification = incident.verification;
  const targeted = new Set<string>();
  for (const item of verification?.approved ?? []) targeted.add(item.action.target);
  for (const item of verification?.rejected ?? []) targeted.add(item.action.target);

  const untouched = new Set<string>();
  for (const resource of incident.blast_radius?.resources ?? []) {
    if (!targeted.has(resource.resource_id)) untouched.add(resource.resource_id);
  }
  return untouched;
}

export function BlastRadiusPanel({ incident }: { incident: Incident }) {
  const radius = incident.blast_radius;
  const untouched = untouchedResourceIds(incident);

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>What the key did</h2>
        <span className="pill evidence">From CloudTrail</span>
      </div>

      {!radius || radius.resources.length === 0 ? (
        <p className="muted">No created resources found in the searched window.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th>Resource</th>
              <th>Region</th>
              <th>Created</th>
              <th>Source IP</th>
            </tr>
          </thead>
          <tbody>
            {radius.resources.map((resource) => (
              <tr
                key={resource.event_id}
                className={untouched.has(resource.resource_id) ? "gap" : ""}
              >
                <td className="mono">
                  {resource.resource_id}
                  {untouched.has(resource.resource_id) && (
                    <span className="chip warn" title="The plan proposed nothing for this resource">
                      no action proposed
                    </span>
                  )}
                </td>
                <td>{resource.region}</td>
                <td className="mono">{resource.event_time.slice(11, 19)}</td>
                <td className="mono">{resource.source_ip}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {radius && radius.problems.length > 0 && (
        <div className="warning">
          <strong>Evidence is incomplete.</strong> Treat this list as a floor, not a total.
          <ul>
            {radius.problems.map((problem, index) => (
              <li key={index} className="mono">
                {problem.kind} in {problem.region}
                {problem.aws_error_code ? ` (${problem.aws_error_code})` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {radius && (
        <p className="muted small">
          Searched {radius.regions_searched.join(", ")} between {radius.window_start.slice(11, 19)}{" "}
          and {radius.window_end.slice(11, 19)} UTC.
        </p>
      )}
    </section>
  );
}
