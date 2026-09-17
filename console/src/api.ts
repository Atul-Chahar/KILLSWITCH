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
      headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    });
  } catch (cause) {
    throw new ApiError(`cannot reach the API: ${(cause as Error).message}`);
  }
  if (!response.ok) {
    throw new ApiError(`the API returned ${response.status}`, response.status);
  }
  return (await response.json()) as T;
}

export function isFixtureMode(): boolean {
  return USE_FIXTURE;
}

export async function fetchIncident(incidentId: string): Promise<Incident> {
  if (USE_FIXTURE) return structuredClone(FIXTURE_INCIDENT);
  return request<Incident>(`/incidents/${encodeURIComponent(incidentId)}`);
}

export async function submitDecisions(
  incidentId: string,
  decisions: DecisionSubmission[],
): Promise<Incident> {
  if (USE_FIXTURE) {
    // Mirrors what the backend does, so a rehearsal exercises the same screens.
    const incident = structuredClone(FIXTURE_INCIDENT);
    const approved = decisions.filter((item) => item.state === "approved");
    incident.status = approved.length > 0 ? "contained" : "detected";
    incident.end_state = {
      incident_id: incident.incident_id,
      targets: approved.map((item) => {
        const [action_type = "", target = ""] = item.action_signature.split(":");
        return {
          action_type,
          target,
          region: null,
          observed_state: action_type === "deactivate_key" ? "Inactive" : "shutting-down",
          confirmed: true,
          aws_error_code: null,
        };
      }),
    };
    return incident;
  }
  return request<Incident>(`/incidents/${encodeURIComponent(incidentId)}/decisions`, {
    method: "POST",
    body: JSON.stringify({ decisions }),
  });
}
