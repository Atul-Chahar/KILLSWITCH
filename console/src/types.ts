// Mirrors the pydantic models the workflow emits. Kept deliberately narrow: the console
// renders what the backend proved, and invents nothing of its own.

export type IncidentStatus =
  | "detected"
  | "investigating"
  | "awaiting_approval"
  | "containing"
  | "contained"
  | "failed";

export type RejectionReason =
  | "unknown_action_type"
  | "malformed_target"
  | "target_not_in_blast_radius"
  | "region_mismatch"
  | "key_mismatch"
  | "repository_mismatch"
  | "duplicate_action";

export type ProblemKind =
  | "region_lookup_failed"
  | "unreadable_event"
  | "creation_event_without_resource_id";

export interface CreatedResource {
  resource_id: string;
  kind: "ec2_instance";
  event_name: string;
  region: string;
  event_time: string;
  source_ip: string;
  event_id: string;
}

export interface EvidenceProblem {
  kind: ProblemKind;
  region: string;
  event_id: string | null;
  aws_error_code: string | null;
}

export interface BlastRadius {
  access_key_id: string;
  regions_searched: string[];
  window_start: string;
  window_end: string;
  resources: CreatedResource[];
  problems: EvidenceProblem[];
}

export interface ProposedAction {
  action_type: string;
  target: string;
  region: string | null;
  reason: string | null;
}

export interface VerifiedAction {
  action: ProposedAction;
  evidence: CreatedResource | null;
}

export interface RejectedAction {
  action: ProposedAction;
  reason: RejectionReason;
}

export interface VerificationResult {
  access_key_id: string;
  approved: VerifiedAction[];
  rejected: RejectedAction[];
  evidence_incomplete: boolean;
}

export interface TierDecision {
  action_type: string;
  tier: "automatic" | "human";
  source: "verified_permissions" | "fallback_table";
  determining_policy_ids: string[];
  aws_error_code: string | null;
}

export interface ConfirmedTarget {
  action_type: string;
  target: string;
  region: string | null;
  observed_state: string | null;
  confirmed: boolean;
  aws_error_code: string | null;
}

export interface EndState {
  incident_id: string;
  targets: ConfirmedTarget[];
}

export interface AuditEntry {
  incident_id: string;
  sk: string;
  stage: "before" | "after" | "refused" | "failed";
  action_signature: string;
  recorded_at: string;
  outcome: string | null;
  details: Record<string, string>;
}

export interface Incident {
  incident_id: string;
  access_key_id: string;
  source: "github_push" | "aws_quarantine";
  status: IncidentStatus;
  detected_at: string;
  repository: string | null;
  commit_sha: string | null;
  key_owner: string | null;
  blast_radius: BlastRadius | null;
  // Written by the model. Rendered as untrusted, never as evidence.
  summary: string | null;
  verification: VerificationResult | null;
  tiers: TierDecision[];
  end_state: EndState | null;
  audit: AuditEntry[];
}

export type Decision = "approved" | "denied";

export interface DecisionSubmission {
  action_signature: string;
  state: Decision;
}
