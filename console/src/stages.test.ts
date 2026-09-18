import { describe, expect, it } from "vitest";

import { FIXTURE_INCIDENT } from "./fixture";
import { workflowStages } from "./stages";
import type { Incident } from "./types";

function awaiting(): Incident {
  return structuredClone(FIXTURE_INCIDENT);
}

function contained(): Incident {
  const incident = awaiting();
  incident.status = "contained";
  incident.end_state = {
    incident_id: incident.incident_id,
    targets: [
      {
        action_type: "deactivate_key",
        target: incident.access_key_id,
        region: null,
        observed_state: "Inactive",
        confirmed: true,
        aws_error_code: null,
      },
    ],
  };
  incident.audit.push({
    incident_id: incident.incident_id,
    sk: "audit#2026-09-18T10:15:40+00:00#1#after",
    stage: "after",
    action_signature: `deactivate_key:${incident.access_key_id}:-`,
    recorded_at: "2026-09-18T10:15:40+00:00",
    outcome: "key deactivated",
    details: {},
  });
  return incident;
}

function stateOf(incident: Incident, key: string, undecided = 0) {
  const stage = workflowStages(incident, undecided).find((item) => item.key === key);
  if (!stage) throw new Error(`no stage ${key}`);
  return stage;
}

describe("workflowStages", () => {
  it("ticks off the stages whose output the record actually carries", () => {
    const incident = awaiting();
    expect(stateOf(incident, "investigate").state).toBe("done");
    expect(stateOf(incident, "narrate").state).toBe("done");
    expect(stateOf(incident, "verify").state).toBe("done");
    expect(stateOf(incident, "authorize").state).toBe("done");
  });

  it("marks the first unfinished stage as the current one", () => {
    const incident = awaiting();
    expect(stateOf(incident, "approve").state).toBe("current");
    expect(stateOf(incident, "contain").state).toBe("pending");
    expect(stateOf(incident, "confirm").state).toBe("pending");
  });

  it("numbers done stages with a tick and pending ones with their position", () => {
    const incident = awaiting();
    expect(stateOf(incident, "investigate").num).toBe("✓");
    expect(stateOf(incident, "contain").num).toBe("06");
  });

  it("reports how many actions the verifier struck out", () => {
    expect(stateOf(awaiting(), "verify").note).toBe("1 action struck out");
  });

  it("counts the decisions still owed while approval is open", () => {
    expect(stateOf(awaiting(), "approve", 2).note).toBe("2 awaiting you");
    expect(stateOf(awaiting(), "approve", 0).note).toBe("ready to send");
  });

  it("finishes every stage once AWS has confirmed the end state", () => {
    for (const stage of workflowStages(contained(), 0)) {
      expect(stage.state).toBe("done");
    }
  });

  // The project refuses to round an unconfirmed action up to success, and the rail has to
  // refuse it too rather than showing a finished workflow.
  it("does not finish the confirm stage when a target is unconfirmed", () => {
    const incident = contained();
    incident.end_state!.targets[0]!.confirmed = false;
    incident.end_state!.targets[0]!.observed_state = null;
    incident.end_state!.targets[0]!.aws_error_code = "UnauthorizedOperation";

    const confirm = stateOf(incident, "confirm");
    expect(confirm.state).toBe("current");
    expect(confirm.note).toBe("not confirmed");
  });

  // The workflow reports a denial as declined rather than failed. The rail has to agree:
  // an operator who used the gate should not be shown a workflow stuck at Approve.
  it("treats a declined incident as having passed the approval stage", () => {
    const incident = awaiting();
    incident.status = "declined";

    expect(stateOf(incident, "approve").state).toBe("done");
    expect(stateOf(incident, "contain").note).toBe("declined by the operator");
  });

  it("does not claim a declined incident was contained", () => {
    const incident = contained();
    incident.status = "declined";

    expect(stateOf(incident, "confirm").state).not.toBe("pending");
    expect(incident.status).not.toBe("contained");
  });
});
