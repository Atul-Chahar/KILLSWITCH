import type { Incident, ProblemKind } from "../types";

// Rendered instead of the raw enum, because this panel is where an operator decides
// whether an empty list means "the key created nothing" or "we could not find out".
const PROBLEM_TEXT: Record<ProblemKind, string> = {
  region_lookup_failed: "CloudTrail could not be searched in",
  unreadable_event: "an event could not be read in",
  creation_event_without_resource_id: "something was created, with no id recorded, in",
  evidence_not_yet_available: "CloudTrail had not delivered any events yet for",
};

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
      <div className="panel-head head-blue">
        <h2>What the key did</h2>
        <span className="panel-tag">FROM CLOUDTRAIL</span>
      </div>

      {!radius || radius.resources.length === 0 ? (
        <p className="panel-empty">No created resources found in the searched window.</p>
      ) : (
        <div>
          <div className="res-head">
            <span>RESOURCE</span>
            <span>REGION</span>
            <span>CREATED</span>
            <span>SOURCE IP</span>
          </div>
          {radius.resources.map((resource) => {
            const isUntouched = untouched.has(resource.resource_id);
            return (
              <div
                className={isUntouched ? "res-row res-row-gap" : "res-row"}
                key={resource.event_id}
              >
                <span className="res-id">
                  <span>{resource.resource_id}</span>
                  {isUntouched && (
                    <span className="res-flag" title="The plan proposed nothing for this resource">
                      NO ACTION PROPOSED
                    </span>
                  )}
                </span>
                <span className="res-region">{resource.region}</span>
                <span className="res-cell">{resource.event_time.slice(11, 19)}</span>
                <span className="res-cell">{resource.source_ip}</span>
              </div>
            );
          })}
        </div>
      )}

      {radius && radius.problems.length > 0 && (
        <div className="warning">
          <strong>Evidence is incomplete.</strong> Treat this list as a floor, not a total.
          <ul>
            {radius.problems.map((problem, index) => (
              <li key={index}>
                {PROBLEM_TEXT[problem.kind] ?? problem.kind} {problem.region}
                {problem.aws_error_code ? ` (${problem.aws_error_code})` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {radius && (
        <p className="panel-foot">
          Searched {radius.regions_searched.join(", ")} between {radius.window_start.slice(11, 19)}{" "}
          and {radius.window_end.slice(11, 19)} UTC.
        </p>
      )}
    </section>
  );
}
