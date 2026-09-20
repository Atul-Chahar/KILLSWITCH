import { useCallback, useEffect, useMemo, useState } from "react";

import { ApiError, fetchIncident, isFixtureMode, submitDecisions } from "./api";
import { AuditTrail } from "./components/AuditTrail";
import { BlastRadiusPanel } from "./components/BlastRadiusPanel";
import { EndStatePanel } from "./components/EndStatePanel";
import { PlanPanel } from "./components/PlanPanel";
import { Timeline } from "./components/Timeline";
import { WorkflowRail } from "./components/WorkflowRail";
import { RepoWatch } from "./components/RepoWatch";
import { Landing } from "./Landing";
import { maskIncidentId } from "./mask";
import { actionSignature } from "./signature";
import type { Decision, Incident } from "./types";

const DEFAULT_INCIDENT_ID = "inc-AKIA" + "IOSFODNN7EXAMPLE";
const REFRESH_MS = 5000;

type View = "landing" | "watch" | "console";

function incidentIdFromLocation(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("incident");
  return fromQuery ?? DEFAULT_INCIDENT_ID;
}

// A named incident is a request for that incident, so it opens the console directly and
// a shared link keeps working. A named repository opens the scanner the same way.
// Everything else starts on the public page.
function viewFromLocation(): View {
  if (window.location.hash === "#console") return "console";
  if (window.location.hash === "#watch") return "watch";
  if (new URLSearchParams(window.location.search).has("incident")) return "console";
  if (new URLSearchParams(window.location.search).has("repo")) return "watch";
  return "landing";
}

export function App() {
  const incidentId = useMemo(incidentIdFromLocation, []);
  const [view, setView] = useState<View>(viewFromLocation);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisions, setDecisions] = useState<Record<string, Decision>>({});
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    const sync = () => setView(viewFromLocation());
    window.addEventListener("popstate", sync);
    window.addEventListener("hashchange", sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("hashchange", sync);
    };
  }, []);

  const go = useCallback((next: View) => {
    const url =
      next === "landing"
        ? window.location.pathname + window.location.search
        : `#${next}`;
    window.history.pushState(null, "", url);
    setView(next);
    window.scrollTo(0, 0);
  }, []);

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

  // Nothing is fetched while the public page is showing; opening the console starts it.
  useEffect(() => {
    if (view !== "console") return;
    void load();
    const timer = window.setInterval(() => void load(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [view, load]);

  const tierFor = useMemo(() => {
    const tiers = new Map(incident?.tiers.map((tier) => [tier.action_type, tier]) ?? []);
    return (actionType: string) => tiers.get(actionType);
  }, [incident]);

  const approvable = incident?.verification?.approved ?? [];
  const undecided = approvable.filter(
    (item) =>
      tierFor(item.action.action_type)?.tier !== "automatic" &&
      !decisions[actionSignature(item.action)],
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

  if (view === "landing")
    return <Landing onOpenConsole={() => go("console")} onOpenWatch={() => go("watch")} />;

  if (view === "watch") {
    return (
      <div className="console">
        <header className="console-head">
          <div className="console-head-inner">
            <button className="btn btn-outline btn-xs" onClick={() => go("landing")}>
              &larr; SITE
            </button>
            <p className="wordmark">KILLSWITCH</p>
            <span className="console-id">repository scan</span>
            <div className="spacer" />
            <button className="btn btn-outline btn-xs" onClick={() => go("console")}>
              WORKED INCIDENT &rarr;
            </button>
          </div>
        </header>
        <RepoWatch onOpenIncident={() => go("console")} />
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="console">
        <header className="console-head">
          <div className="console-head-inner">
            <button className="btn btn-outline btn-xs" onClick={() => go("landing")}>
              &larr; SITE
            </button>
            <p className="wordmark">KILLSWITCH</p>
            <span className="console-id" title="Redacted incident identifier">{maskIncidentId(incidentId)}</span>
            <div className="spacer" />
            <button className="btn btn-outline btn-xs" onClick={() => go("watch")}>
              SCAN A REPO
            </button>
          </div>
        </header>
        <div className="loading">
          {error ? (
            <p className="banner banner-error">{error}</p>
          ) : (
            <p>Loading incident…</p>
          )}
        </div>
      </div>
    );
  }

  const awaiting = incident.status === "awaiting_approval";
  const decided = Object.keys(decisions).length > 0;

  return (
    <div className="console">
      <header className="console-head">
        <div className="console-head-inner">
          <button className="btn btn-outline btn-xs" onClick={() => go("landing")}>
            &larr; SITE
          </button>
          <p className="wordmark">KILLSWITCH</p>
          <span className="console-id" title="Redacted incident identifier">{maskIncidentId(incident.incident_id)}</span>
          <div className="spacer" />
          <button className="btn btn-outline btn-xs" onClick={() => go("watch")}>
            SCAN A REPO
          </button>
          {isFixtureMode() && <span className="mode-chip">FIXTURE MODE</span>}
          <span className={`status-chip status-${incident.status}`}>
            {incident.status.replace(/_/g, " ").toUpperCase()}
          </span>
        </div>
      </header>

      <div className="shell">
        <WorkflowRail incident={incident} undecided={undecided} />

        <main className="main">
          {isFixtureMode() && (
            <p className="banner">
              Fixture mode: this screen is rendering a bundled example incident, not live AWS
              data.
            </p>
          )}
          {error && (
            <p className="banner banner-error">{error} — showing the last data that loaded.</p>
          )}

          <Timeline incident={incident} />
          <BlastRadiusPanel incident={incident} />
          <PlanPanel
            incident={incident}
            decisions={decisions}
            tierFor={tierFor}
            onDecide={(signature, decision) =>
              setDecisions((current) => ({ ...current, [signature]: decision }))
            }
            disabled={!awaiting || submitting}
            settled={!awaiting}
          />
          <EndStatePanel incident={incident} />
          <AuditTrail incident={incident} />
        </main>
      </div>

      {awaiting && (
        <div className="submit-bar">
          <div className="submit-bar-inner">
            <span className={undecided > 0 ? "submit-count submit-count-pending" : "submit-count"}>
              {undecided > 0
                ? `${undecided} action${undecided === 1 ? "" : "s"} still need${
                    undecided === 1 ? "s" : ""
                  } a decision.`
                : "Every action has a decision."}
            </span>
            <span className="submit-scope">
              Every decision is scoped to this action and this approval round.
            </span>
            <div className="spacer" />
            <button
              onClick={() => void submit()}
              disabled={!decided || undecided > 0 || submitting}
            >
              {submitting ? "Sending…" : "Send Decisions"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
