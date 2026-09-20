import { elapsedSeconds, formatDuration } from "../cost";
import type { Incident } from "../types";

type MomentKind = "attack" | "detect" | "verify" | "contain" | "fail";

interface Moment {
  label: string;
  at: string;
  kind: MomentKind;
}

function moments(incident: Incident): Moment[] {
  const found: Moment[] = [];
  const resources = incident.blast_radius?.resources ?? [];

  const first = resources[0];
  if (first) found.push({ label: "First attacker API call", at: first.event_time, kind: "attack" });
  for (const resource of resources) {
    // An access key is not "launched". The event name is what CloudTrail actually recorded,
    // so the line says what happened rather than assuming every resource is an instance.
    const verb = resource.kind === "ec2_instance" ? "Launched" : "Created";
    found.push({
      label: `${verb} ${resource.resource_id} in ${resource.region}`,
      at: resource.event_time,
      kind: "attack",
    });
  }
  found.push({ label: "KILLSWITCH detected the leak", at: incident.detected_at, kind: "detect" });

  for (const entry of incident.audit) {
    if (entry.stage === "after") {
      found.push({
        label: `Contained ${entry.action_signature}`,
        at: entry.recorded_at,
        kind: "contain",
      });
    }
    if (entry.stage === "refused") {
      found.push({
        label: `Refused ${entry.action_signature}`,
        at: entry.recorded_at,
        kind: "verify",
      });
    }
    if (entry.stage === "failed") {
      found.push({
        label: `Failed ${entry.action_signature}`,
        at: entry.recorded_at,
        kind: "fail",
      });
    }
  }
  return found.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

export function Timeline({ incident }: { incident: Incident }) {
  const entries = moments(incident);
  const first = entries[0];
  const last = entries[entries.length - 1];

  return (
    <section className="panel">
      <div className="panel-head head-yellow">
        <h2>Timeline</h2>
        {first && last && entries.length > 1 && (
          <span className="panel-tag panel-tag-bare">
            {formatDuration(elapsedSeconds(first.at, last.at))} ELAPSED
          </span>
        )}
      </div>
      <ol className="timeline">
        {entries.map((moment, index) => (
          <li key={`${moment.label}-${index}`}>
            <time>{moment.at.slice(11, 19)}</time>
            <span className={`timeline-dot dot-${moment.kind}`} />
            <span className="timeline-label">{moment.label}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
