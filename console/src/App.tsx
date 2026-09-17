import { useCallback, useEffect, useMemo, useState } from "react";

import { ApiError, fetchIncident, isFixtureMode, submitDecisions } from "./api";
import { AuditTrail } from "./components/AuditTrail";
import { BlastRadiusPanel } from "./components/BlastRadiusPanel";
import { CostAvoided } from "./components/CostAvoided";
import { EndStatePanel } from "./components/EndStatePanel";
import { PlanPanel } from "./components/PlanPanel";
import { Timeline } from "./components/Timeline";
import { actionSignature } from "./signature";
import type { Decision, Incident } from "./types";

const DEFAULT_INCIDENT_ID = "inc-AKIA" + "IOSFODNN7EXAMPLE";
const REFRESH_MS = 5000;

function incidentIdFromLocation(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("incident");
  return fromQuery ?? DEFAULT_INCIDENT_ID;
}

export function App() {
  const incidentId = useMemo(incidentIdFromLocation, []);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisions, setDecisions] = useState<Record<string, Decision>>({});
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    try {
      const next = await fetchIncident(incidentId);
      setIncident(next);
      setError(null);
    } catch (cause) {
      // The last good incident stays on screen. A failed refresh must not blank the
      // page or, worse, imply there is nothing to approve.
      setError(cause instanceof ApiError ? cause.message : String(cause));
    }
  }, [incidentId]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [load]);

  const needsHuman = useMemo(() => {
    const tiers = new Map(incident?.tiers.map((tier) => [tier.action_type, tier.tier]) ?? []);
    return (actionType: string) => tiers.get(actionType) !== "automatic";
  }, [incident]);

  const approvable = incident?.verification?.approved ?? [];
  const undecided = approvable.filter(
    (item) => needsHuman(item.action.action_type) && !decisions[actionSignature(item.action)],
  ).length;

  async function submit() {
    if (!incident) return;
    setSubmitting(true);
    try {
      const payload = Object.entries(decisions).map(([action_signature, state]) => ({
        action_signature,
        state,
      }));
      setIncident(await submitDecisions(incident.incident_id, payload));
      setError(null);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  }

  if (!incident) {
    return (
      <main className="shell">
        <h1 className="wordmark">KILLSWITCH</h1>
        {error ? <p className="error">{error}</p> : <p className="muted">Loading incident…</p>}
      </main>
    );
  }

  const decided = Object.keys(decisions).length > 0;
  const awaiting = incident.status === "awaiting_approval";

  return (
    <main className="shell">
      <header className="header">
        <div>
          <h1 className="wordmark">KILLSWITCH</h1>
          <p className="muted mono">{incident.incident_id}</p>
        </div>
        <span className={`status status-${incident.status}`}>
          {incident.status.replace(/_/g, " ")}
        </span>
      </header>

      {isFixtureMode() && (
        <p className="banner">
          Fixture mode: this screen is rendering a bundled example incident, not live AWS data.
        </p>
      )}
      {error && <p className="error">{error} — showing the last data that loaded.</p>}

      <Timeline incident={incident} />
      <CostAvoided incident={incident} />

      <div className="columns">
        <BlastRadiusPanel incident={incident} />
        <PlanPanel
          incident={incident}
          decisions={decisions}
          needsHuman={needsHuman}
          onDecide={(signature, decision) =>
            setDecisions((current) => ({ ...current, [signature]: decision }))
          }
          disabled={!awaiting || submitting}
        />
      </div>

      {awaiting && (
        <div className="submit-bar">
          <p className="muted">
            {undecided > 0
              ? `${undecided} action${undecided === 1 ? "" : "s"} still need a decision.`
              : "Every action has a decision."}
          </p>
          <button
            className="primary"
            onClick={() => void submit()}
            disabled={!decided || submitting}
          >
            {submitting ? "Sending…" : "Send decisions"}
          </button>
        </div>
      )}

      <EndStatePanel incident={incident} />
      <AuditTrail incident={incident} />
    </main>
  );
}
