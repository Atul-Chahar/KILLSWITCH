import { useCallback, useEffect, useMemo, useState } from "react";

import { ApiError, fetchIncident, isFixtureMode, submitDecisions } from "./api";
import { AuditTrail } from "./components/AuditTrail";
import { BlastRadiusPanel } from "./components/BlastRadiusPanel";
import { EndStatePanel } from "./components/EndStatePanel";
import { PlanPanel } from "./components/PlanPanel";
import { Timeline } from "./components/Timeline";
import { WorkflowRail } from "./components/WorkflowRail";
import { ActivityLog } from "./demo/ActivityLog";
import { LogPanel } from "./demo/LogPanel";
import {
  getDemoState,
  isDemoMode,
  runContainmentLog,
  startDemoWatch,
  subscribeDemo,
} from "./demo/runtime";
import { Landing } from "./Landing";
import { actionSignature } from "./signature";
import { Standby } from "./components/Standby";
import type { Decision, Incident } from "./types";

const DEFAULT_INCIDENT_ID = "inc-AKIA" + "IOSFODNN7EXAMPLE";
const REFRESH_MS = 5000;
// The repository the demo watches. Only ever shown, never contacted.
const DEMO_REPOSITORY = "gyanranjanpanda/workbeat";

type View = "landing" | "console";

function incidentIdFromLocation(): string {
  const fromQuery = new URLSearchParams(window.location.search).get("incident");
  return fromQuery ?? DEFAULT_INCIDENT_ID;
}

// A named incident is a request for that incident, so it opens the console directly and
// a shared link keeps working. Everything else starts on the public page.
function viewFromLocation(): View {
  if (window.location.hash === "#console") return "console";
  if (new URLSearchParams(window.location.search).has("incident")) return "console";
  return "landing";
}

export function App() {
  const demo = useMemo(isDemoMode, []);
  const incidentId = useMemo(incidentIdFromLocation, []);
  const [view, setView] = useState<View>(viewFromLocation);
  const [incident, setIncident] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [decisions, setDecisions] = useState<Record<string, Decision>>({});
  const [submitting, setSubmitting] = useState(false);
  const [demoState, setDemoState] = useState(getDemoState);

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
      next === "console" ? "#console" : window.location.pathname + window.location.search;
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
  // In demo mode there is no API to poll — the two demo scripts drive the screen instead.
  useEffect(() => {
    if (view !== "console" || demo) return;
    void load();
    const timer = window.setInterval(() => void load(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [view, load, demo]);

  useEffect(() => {
    if (!demo) return;
    return subscribeDemo(setDemoState);
  }, [demo]);

  useEffect(() => {
    if (!demo || view !== "console") return;
    return startDemoWatch();
  }, [demo, view]);

  useEffect(() => {
    if (demo) setIncident(demoState.incident);
  }, [demo, demoState.incident]);

  // A fresh leak is a fresh incident, so an earlier take's decisions must not carry over.
  useEffect(() => {
    if (demo) setDecisions({});
  }, [demo, demoState.leak?.id]);

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
      // In demo mode the containment log streams first, so the confirmed end state lands
      // after the work that produced it rather than a beat before it.
      if (demo) {
        await runContainmentLog(
          payload.filter((item) => item.state === "approved").map((i) => i.action_signature),
          payload.filter((item) => item.state === "denied").map((i) => i.action_signature),
        );
      }
      setIncident(await submitDecisions(incident.incident_id, payload));
      setError(null);
    } catch (cause) {
      setError(cause instanceof ApiError ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  }

  if (view === "landing") return <Landing onOpenConsole={() => go("console")} />;

  if (!incident) {
    return (
      <div className="console">
        <header className="console-head">
          <div className="console-head-inner">
            <button className="btn btn-outline btn-xs" onClick={() => go("landing")}>
              &larr; SITE
            </button>
            <p className="wordmark">KILLSWITCH</p>
            <span className="console-id">{incidentId}</span>
          </div>
        </header>
        {demo ? (
          <Standby
            repository={demoState.leak?.repository ?? DEMO_REPOSITORY}
            error={demoState.error}
          />
        ) : (
          <div className="loading">
            {error ? (
              <p className="banner banner-error">{error}</p>
            ) : (
              <p>Loading incident…</p>
            )}
          </div>
        )}
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
          <span className="console-id">{incident.incident_id}</span>
          <div className="spacer" />
          {demo ? (
            <span className="mode-chip mode-chip-demo">DEMO MODE</span>
          ) : (
            isFixtureMode() && <span className="mode-chip">FIXTURE MODE</span>
          )}
          <span className={`status-chip status-${incident.status}`}>
            {incident.status.replace(/_/g, " ").toUpperCase()}
          </span>
        </div>
      </header>

      <div className="shell">
        <WorkflowRail incident={incident} undecided={undecided} />

        <main className="main">
          {demo ? (
            <DemoStrip
              phase={demoState.phase}
              note={demoState.note}
              progress={demoState.progress}
            />
          ) : (
            isFixtureMode() && (
              <p className="banner">
                Fixture mode: this screen is rendering a bundled example incident, not live AWS
                data.
              </p>
            )
          )}
          {error && (
            <p className="banner banner-error">{error} — showing the last data that loaded.</p>
          )}

          {demo && <LogPanel lines={demoState.log} live={demoState.streaming} />}
          <Timeline incident={incident} />
          {demo && <ActivityLog events={demoState.activity} />}
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

// The live step the demo is on, and — between the two acts — what the operator runs next.
// It is the only thing on screen that is about the demo rather than about the incident,
// so it says so and stays out of the panels.
function DemoStrip({
  phase,
  note,
  progress,
}: {
  phase: string;
  note: string | null;
  progress: number;
}) {
  if (phase === "waiting") {
    return (
      <div className="demo-strip demo-strip-wait">
        <span className="demo-strip-dot demo-strip-dot-hot" />
        <span className="demo-strip-note">
          The key is active and CloudTrail has returned nothing yet. KILLSWITCH is holding
          here rather than reporting all clear.
        </span>
        <code className="demo-strip-cmd">./scripts/demo_attack.sh</code>
      </div>
    );
  }
  if (note === null) {
    return (
      <div className="demo-strip demo-strip-done">
        <span className="demo-strip-dot" />
        <span className="demo-strip-note">
          Demo mode: this run is driven by the local demo scripts, not by live AWS data.
          Every action below is scoped to this incident and waits on you.
        </span>
      </div>
    );
  }
  return (
    <div className="demo-strip">
      <span className="demo-strip-dot demo-strip-dot-live" />
      <span className="demo-strip-note">{note}</span>
      <span className="demo-strip-bar">
        <span className="demo-strip-fill" style={{ width: `${Math.round(progress * 100)}%` }} />
      </span>
    </div>
  );
}
