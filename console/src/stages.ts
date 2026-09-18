// The seven stages of the response workflow, as the rail draws them.
//
// A stage is "done" because the incident record carries the thing that stage produces,
// not because the status field says so. That way a half-finished incident shows exactly
// how far it actually got, and a stage can never be ticked off on the strength of a label.

import type { Incident } from "./types";

export type StageState = "done" | "current" | "pending";

export interface StageView {
  key: string;
  num: string;
  name: string;
  note: string;
  state: StageState;
}

interface StageSpec {
  key: string;
  name: string;
  note: string;
  done: (incident: Incident) => boolean;
}

const SPECS: StageSpec[] = [
  {
    key: "investigate",
    name: "Investigate",
    note: "IAM + CloudTrail",
    done: (incident) => incident.blast_radius !== null,
  },
  {
    key: "narrate",
    name: "Narrate",
    note: "Strands on Bedrock",
    done: (incident) => incident.summary !== null,
  },
  {
    key: "verify",
    name: "Verify",
    note: "no model, no AWS",
    done: (incident) => incident.verification !== null,
  },
  {
    key: "authorize",
    name: "Authorize",
    note: "Cedar decides",
    done: (incident) => incident.tiers.length > 0,
  },
  {
    key: "approve",
    name: "Approve",
    note: "waitForTaskToken",
    done: (incident) =>
      incident.status === "containing" ||
      incident.status === "contained" ||
      incident.end_state !== null,
  },
  {
    key: "contain",
    name: "Contain",
    note: "the only writes",
    done: (incident) => incident.audit.some((entry) => entry.stage === "after"),
  },
  {
    key: "confirm",
    name: "Confirm",
    note: "re-read AWS",
    // Only a confirmed end state finishes this stage. An unconfirmed one is a failure,
    // and rounding it up to success is the exact thing this project refuses to do.
    done: (incident) =>
      incident.end_state !== null &&
      incident.end_state.targets.length > 0 &&
      incident.end_state.targets.every((target) => target.confirmed),
  },
];

function noteFor(spec: StageSpec, incident: Incident, undecided: number): string {
  if (spec.key === "verify") {
    const struck = incident.verification?.rejected.length ?? 0;
    if (struck > 0) return `${struck} action${struck === 1 ? "" : "s"} struck out`;
  }
  if (spec.key === "approve" && incident.status === "awaiting_approval") {
    return undecided > 0 ? `${undecided} awaiting you` : "ready to send";
  }
  if (spec.key === "confirm") {
    const endState = incident.end_state;
    if (endState && endState.targets.some((target) => !target.confirmed)) return "not confirmed";
  }
  return spec.note;
}

export function workflowStages(incident: Incident, undecided: number): StageView[] {
  const done = SPECS.map((spec) => spec.done(incident));
  // The first unfinished stage is the one in progress. Later stages stay pending even if
  // their own evidence happens to exist, so the rail always reads top to bottom.
  const currentIndex = done.indexOf(false);
  const finished = currentIndex === -1 ? SPECS.length : currentIndex;

  return SPECS.map((spec, index) => {
    const state: StageState =
      index < finished ? "done" : index === currentIndex ? "current" : "pending";
    return {
      key: spec.key,
      num: state === "done" ? "✓" : String(index + 1).padStart(2, "0"),
      name: spec.name,
      note: noteFor(spec, incident, undecided),
      state,
    };
  });
}
