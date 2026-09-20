import { maskActionSignature } from "../mask";
import type { Incident } from "../types";

export function AuditTrail({ incident }: { incident: Incident }) {
  if (incident.audit.length === 0) return null;

  return (
    <section className="panel">
      <div className="panel-head head-ink">
        <h2>Audit trail</h2>
        <span className="panel-tag panel-tag-invert">
          {incident.audit.length} {incident.audit.length === 1 ? "ENTRY" : "ENTRIES"}
        </span>
      </div>
      <ol className="audit">
        {incident.audit.map((entry) => (
          <li key={entry.sk}>
            <span className={`audit-stage stage-${entry.stage}`}>
              {entry.stage.toUpperCase()}
            </span>
            <span className="audit-sig" title={maskActionSignature(entry.action_signature) !== entry.action_signature ? "Redacted action signature" : undefined}>{maskActionSignature(entry.action_signature)}</span>
            <time className="audit-time">{entry.recorded_at.slice(11, 19)}</time>
            {entry.outcome && <span className="audit-outcome">{entry.outcome}</span>}
          </li>
        ))}
      </ol>
    </section>
  );
}
