import type { Incident } from "../types";

export function AuditTrail({ incident }: { incident: Incident }) {
  if (incident.audit.length === 0) return null;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Audit trail</h2>
        <span className="pill">{incident.audit.length} entries</span>
      </div>
      <ol className="audit">
        {incident.audit.map((entry) => (
          <li key={entry.sk}>
            <span className={`chip stage-${entry.stage}`}>{entry.stage}</span>
            <span className="mono">{entry.action_signature}</span>
            <time className="mono muted">{entry.recorded_at.slice(11, 19)}</time>
            {entry.outcome && <span className="muted small">{entry.outcome}</span>}
          </li>
        ))}
      </ol>
    </section>
  );
}
