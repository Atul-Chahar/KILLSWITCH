// Talking to the approval API.
//
// Two rules the phase sets, both enforced here rather than in the components:
//   - errors are surfaced, never swallowed into an empty state
//   - state never flickers between stale and fresh, so a failed refresh keeps the last
//     good incident on screen and shows the error beside it

import { FIXTURE_INCIDENT } from "./fixture";
import type { DecisionSubmission, Incident } from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "";
const USE_FIXTURE = import.meta.env.VITE_USE_FIXTURE === "1" || API_BASE === "";

// Every API route sits behind a Cognito authorizer — the approve button is the last
// gate in the system and is not open to the internet. The console has no login screen,
// so the operator supplies an id token from the pool and we send it as a bearer.
// It expires in an hour; a 401 means fetch a new one, not that the incident is gone.
const API_TOKEN = import.meta.env.VITE_API_TOKEN ?? "";

function authHeaders(): Record<string, string> {
  return API_TOKEN ? { Authorization: API_TOKEN } : {};
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...authHeaders(),
        ...(init?.headers ?? {}),
      },
    });
  } catch (cause) {
    throw new ApiError(`cannot reach the API: ${(cause as Error).message}`);
  }
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      throw new ApiError(
        API_TOKEN
          ? "the API rejected the token — it has probably expired, fetch a new one"
          : "the API needs a Cognito id token; start the console with VITE_API_TOKEN set",
        response.status,
      );
    }
    throw new ApiError(`the API returned ${response.status}`, response.status);
  }
  return (await response.json()) as T;
}

export function isFixtureMode(): boolean {
  return USE_FIXTURE;
}

// Fixture mode has to stand in for a backend that remembers. Without this the refresh
// timer would hand back the untouched fixture a few seconds after an approval and wipe
// the contained screen off the demo.
let fixtureState: Incident | null = null;

export async function fetchIncident(incidentId: string): Promise<Incident> {
  if (USE_FIXTURE) return structuredClone(fixtureState ?? FIXTURE_INCIDENT);
  return request<Incident>(`/incidents/${encodeURIComponent(incidentId)}`);
}

export async function submitDecisions(
  incidentId: string,
  decisions: DecisionSubmission[],
): Promise<Incident> {
  if (USE_FIXTURE) {
    // Mirrors what the backend does, so a rehearsal exercises the same screens: an end
    // state re-read from AWS, and the before/after pair that containment/actions.py
    // writes for every action it runs. A denied action never reaches containment, so it
    // leaves no audit entry at all.
    const incident = structuredClone(FIXTURE_INCIDENT);
    const approved = decisions.filter((item) => item.state === "approved");
    // Withholding any action leaves the incident declined, not contained. Rounding a
    // partial response up to "contained" is the exact claim this project refuses to make.
    incident.status =
      approved.length === 0
        ? "declined"
        : approved.length === decisions.length
          ? "contained"
          : "declined";

    const observedFor = (actionType: string) => {
      if (actionType === "deactivate_key") return "Inactive";
      if (actionType === "open_pr") return "pull request opened";
      return "shutting-down";
    };
    const startedAt = Date.parse(incident.detected_at) + 150_000;

    incident.end_state = {
      incident_id: incident.incident_id,
      targets: approved.map((item) => {
        const [action_type = "", target = ""] = item.action_signature.split(":");
        return {
          action_type,
          target,
          region: null,
          observed_state: observedFor(action_type),
          confirmed: true,
          aws_error_code: null,
        };
      }),
    };

    approved.forEach((item, index) => {
      const [action_type = ""] = item.action_signature.split(":");
      const before = new Date(startedAt + index * 4000).toISOString();
      const after = new Date(startedAt + index * 4000 + 2000).toISOString();
      incident.audit.push(
        {
          incident_id: incident.incident_id,
          sk: `audit#${before}#${index * 2 + 1}#fixture-before`,
          stage: "before",
          action_signature: item.action_signature,
          recorded_at: before,
          outcome: null,
          details: {},
        },
        {
          incident_id: incident.incident_id,
          sk: `audit#${after}#${index * 2 + 2}#fixture-after`,
          stage: "after",
          action_signature: item.action_signature,
          recorded_at: after,
          outcome: observedFor(action_type),
          details: {},
        },
      );
    });

    fixtureState = incident;
    return structuredClone(incident);
  }
  return request<Incident>(`/incidents/${encodeURIComponent(incidentId)}/decisions`, {
    method: "POST",
    body: JSON.stringify({ decisions }),
  });
}
