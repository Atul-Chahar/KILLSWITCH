import { elapsedSeconds, formatDuration } from "../cost";
import type { Incident } from "../types";

interface Moment {
  label: string;
  at: string;
}

function moments(incident: Incident): Moment[] {
  const found: Moment[] = [];
  const resources = incident.blast_radius?.resources ?? [];

  const first = resources[0];
  if (first) found.push({ label: "First attacker API call", at: first.event_time });
  for (const resource of resources) {
    found.push({
      label: `Launched ${resource.resource_id} in ${resource.region}`,
      at: resource.event_time,
    });
  }
  found.push({ label: "KILLSWITCH detected the leak", at: incident.detected_at });
  for (const entry of incident.audit) {
    if (entry.stage === "after") {
      found.push({ label: `Contained ${entry.action_signature}`, at: entry.recorded_at });
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
      <div className="panel-head">
        <h2>Timeline</h2>
        {first && last && entries.length > 1 && (
          <span className="pill">{formatDuration(elapsedSeconds(first.at, last.at))} elapsed</span>
        )}
      </div>
      <ol className="timeline">
        {entries.map((moment, index) => (
          <li key={`${moment.label}-${index}`}>
            <time className="mono">{moment.at.slice(11, 19)}</time>
            <span>{moment.label}</span>
          </li>
        ))}
      </ol>
    </section>
  );
}
