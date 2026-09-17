// A worked incident, for rehearsing the screen without an AWS account.
//
// It is the same shape the workflow emits, including one action the verifier struck out
// and one instance the plan ignored, because those are the two cases the console exists
// to make visible.

import type { Incident } from "./types";

const KEY = "AKIA" + "IOSFODNN7EXAMPLE";

export const FIXTURE_INCIDENT: Incident = {
  incident_id: `inc-${KEY}`,
  access_key_id: KEY,
  source: "github_push",
  status: "awaiting_approval",
  detected_at: "2026-09-18T10:13:10+00:00",
  repository: "octo/private-demo-repo",
  commit_sha: "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
  key_owner: "demo-leaky-user",
  summary:
    "A long-term access key belonging to demo-leaky-user was committed to " +
    "octo/private-demo-repo and used within seconds to launch t3.micro instances in two " +
    "regions. I recommend deactivating the key and terminating both instances.",
  blast_radius: {
    access_key_id: KEY,
    regions_searched: ["ap-south-1", "us-east-1"],
    window_start: "2026-09-18T07:13:10+00:00",
    window_end: "2026-09-18T10:13:10+00:00",
    resources: [
      {
        resource_id: "i-0a1b2c3d4e5f60001",
        kind: "ec2_instance",
        event_name: "RunInstances",
        region: "ap-south-1",
        event_time: "2026-09-18T10:12:41+00:00",
        source_ip: "203.0.113.10",
        event_id: "3f1d9c02-1111-4a2b-9c3d-000000000001",
      },
      {
        resource_id: "i-0f9e8d7c6b5a40002",
        kind: "ec2_instance",
        event_name: "RunInstances",
        region: "us-east-1",
        event_time: "2026-09-18T10:14:55+00:00",
        source_ip: "203.0.113.10",
        event_id: "7c4e8b11-aaaa-4bbb-8ccc-000000000003",
      },
    ],
    problems: [],
  },
  verification: {
    access_key_id: KEY,
    approved: [
      {
        action: {
          action_type: "deactivate_key",
          target: KEY,
          region: null,
          reason: "The key is exposed in a commit and is being used right now.",
        },
        evidence: null,
      },
      {
        action: {
          action_type: "terminate_instance",
          target: "i-0a1b2c3d4e5f60001",
          region: "ap-south-1",
          reason: "Launched by the leaked key 12 seconds after the push.",
        },
        evidence: {
          resource_id: "i-0a1b2c3d4e5f60001",
          kind: "ec2_instance",
          event_name: "RunInstances",
          region: "ap-south-1",
          event_time: "2026-09-18T10:12:41+00:00",
          source_ip: "203.0.113.10",
          event_id: "3f1d9c02-1111-4a2b-9c3d-000000000001",
        },
      },
    ],
    rejected: [
      {
        action: {
          action_type: "terminate_instance",
          target: "i-0999999999ffffff9",
          region: "ap-south-1",
          reason: "This instance also looks suspicious and should be removed.",
        },
        reason: "target_not_in_blast_radius",
      },
    ],
    evidence_incomplete: false,
  },
  tiers: [
    {
      action_type: "deactivate_key",
      tier: "human",
      source: "verified_permissions",
      determining_policy_ids: ["policy-forbid-destructive"],
      aws_error_code: null,
    },
    {
      action_type: "terminate_instance",
      tier: "human",
      source: "verified_permissions",
      determining_policy_ids: ["policy-forbid-destructive"],
      aws_error_code: null,
    },
  ],
  end_state: null,
  audit: [
    {
      incident_id: `inc-${KEY}`,
      sk: "audit#2026-09-18T10:13:10+00:00#0#fixture-1",
      stage: "before",
      action_signature: "detect:github_push:-",
      recorded_at: "2026-09-18T10:13:10+00:00",
      outcome: "incident opened",
      details: {},
    },
  ],
};
