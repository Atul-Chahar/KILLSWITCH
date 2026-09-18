import { ASSUMED_HOURS, estimateAvoidedCost, formatUsd } from "../cost";
import type { Incident } from "../types";

export function CostAvoided({ incident }: { incident: Incident }) {
  const resources = incident.blast_radius?.resources ?? [];
  if (resources.length === 0) return null;

  const estimate = estimateAvoidedCost(resources);

  return (
    <section className="estimate">
      <p className="estimate-value">{formatUsd(estimate.totalUsd)}</p>
      <p className="estimate-note">
        Estimated cost avoided: {estimate.instanceCount} instance
        {estimate.instanceCount === 1 ? "" : "s"} × {ASSUMED_HOURS} hours ×{" "}
        {formatUsd(estimate.hourlyRate)}/hour. An estimate at list price, not a measurement.
      </p>
    </section>
  );
}
