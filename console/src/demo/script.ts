// The scripted incident the demo plays back.
//
// This is a rehearsal, not a recording. Nothing here talks to AWS, no model writes the
// summary, and the verifier is not run — the frames below are written by hand so the
// console can be filmed end to end without an account. The console badges every screen it
// drives this way as DEMO MODE, because a rehearsal shown as live data would be the one
// lie this project cannot afford.
//
// It runs in two acts, driven by two files the demo scripts drop:
//
//   scripts/demo_leak.sh    the key is pushed. KILLSWITCH finds it, names the owner, and
//                           searches CloudTrail — which has nothing yet. It waits.
//   scripts/demo_attack.sh  the attacker picks the key up. Their calls stream in live,
//                           the model proposes, the verifier cuts, and the buttons appear.
//
// The record shape is exactly what the workflow emits, so every panel is exercised for
// real: a resource the plan ignores, an action the verifier strikes out, and a Cedar tier
// that puts a human in front of every destructive call.

import type { LogCast } from "./log";
import type {
  BlastRadius,
  CreatedResource,
  Incident,
  RejectedAction,
  TierDecision,
  VerifiedAction,
} from "../types";

// Written by scripts/demo_leak.sh.
export interface LeakTrigger {
  id: string;
  access_key_id: string;
  repository: string;
  commit_sha: string;
  pushed_at: string;
  key_owner?: string;
  leaked_path?: string;
}

// Written by scripts/demo_attack.sh. The ids it prints in the terminal are the ids the
// dashboard shows, so the two screens can be filmed side by side.
export interface AttackTrigger {
  id: string;
  // Which leak this attack belongs to. A file left over from an earlier take is ignored.
  leak_id?: string;
  started_at: string;
  source_ip?: string;
  instances?: { id: string; region: string }[];
  rogue_key?: string;
  bystander_instance?: string;
}

// One CloudTrail record, as the investigate stage reads them. The workflow keeps only the
// creating calls; this log is everything it looked at, which is what makes the attacker's
// half of the story legible.
export interface ActivityEvent {
  event_name: string;
  service: string;
  region: string;
  event_time: string;
  source_ip: string;
  detail: string;
  outcome: "created" | "read" | "denied";
  error_code: string | null;
}

export type DemoPhase = "standby" | "running" | "waiting" | "settled";

export interface DemoFrame {
  // Milliseconds after the act began.
  at: number;
  // What the workflow is doing at this frame, shown in the live strip.
  note: string | null;
  phase: DemoPhase;
  incident: Incident;
  activity: ActivityEvent[];
}

const FALLBACK_KEY = "AKIA" + "IOSFODNN7EXAMPLE";
const DEFAULT_IP = "203.0.113.41";
const HOME_REGION = "ap-south-1";
const AWAY_REGION = "us-east-1";
const BLOCKED_REGION = "eu-west-1";

function at(base: number, seconds: number): string {
  return new Date(base + seconds * 1000).toISOString().replace("Z", "+00:00");
}

function cast(leak: LeakTrigger, attack: AttackTrigger | null) {
  const first = attack?.instances?.[0] ?? { id: "i-0a1b2c3d4e5f60001", region: HOME_REGION };
  const second = attack?.instances?.[1] ?? { id: "i-0f9e8d7c6b5a40002", region: AWAY_REGION };
  return {
    key: leak.access_key_id || FALLBACK_KEY,
    owner: leak.key_owner ?? "workbeat-deploy",
    path: leak.leaked_path ?? "config/aws.env",
    ip: attack?.source_ip ?? DEFAULT_IP,
    first,
    second,
    rogue: attack?.rogue_key ?? FALLBACK_KEY,
    bystander: attack?.bystander_instance ?? "i-0999999999ffffff9",
  };
}

// The one place the two acts agree on who and what is involved, so the log, the panels
// and the terminal all name the same instances.
export function logCast(leak: LeakTrigger, attack: AttackTrigger | null): LogCast {
  const parts = cast(leak, attack);
  return {
    key: parts.key,
    owner: parts.owner,
    repository: leak.repository,
    path: parts.path,
    commit: leak.commit_sha,
    ip: parts.ip,
    first: parts.first,
    second: parts.second,
    rogue: parts.rogue,
    bystander: parts.bystander,
  };
}

function openedIncident(leak: LeakTrigger): Incident {
  const key = leak.access_key_id || FALLBACK_KEY;
  const detected = at(Date.parse(leak.pushed_at), 4);
  return {
    incident_id: `inc-${key}`,
    access_key_id: key,
    source: "github_push",
    status: "detected",
    detected_at: detected,
    repository: leak.repository,
    commit_sha: leak.commit_sha,
    key_owner: null,
    summary: null,
    narrator: null,
    blast_radius: null,
    verification: null,
    tiers: [],
    end_state: null,
    audit: [
      {
        incident_id: `inc-${key}`,
        sk: `audit#${detected}#0#demo-open`,
        stage: "before",
        action_signature: "detect:github_push:-",
        recorded_at: detected,
        outcome: "incident opened",
        details: {},
      },
    ],
  };
}

// ---------- act one: the key is pushed ----------

export const LEAK_RUN_MS = 5600;

export function buildLeakFrames(leak: LeakTrigger): DemoFrame[] {
  const { key, owner } = cast(leak, null);
  const base = openedIncident(leak);
  const detected = base.detected_at;

  // CloudTrail was searched and came back empty. That is not the same claim as "the key
  // created nothing", so the search records why, and the panel says so on screen.
  const emptyRadius: BlastRadius = {
    access_key_id: key,
    regions_searched: [HOME_REGION, AWAY_REGION],
    window_start: at(Date.parse(leak.pushed_at), -10800),
    window_end: detected,
    resources: [],
    problems: [HOME_REGION, AWAY_REGION].map((region) => ({
      kind: "evidence_not_yet_available" as const,
      region,
      event_id: null,
      aws_error_code: null,
    })),
  };

  const steps: { at: number; note: string | null; phase: DemoPhase; patch: Partial<Incident> }[] = [
    {
      at: 0,
      note: `Secret scan matched an AWS long-term key in ${leak.commit_sha.slice(0, 7)}`,
      phase: "running",
      patch: {},
    },
    {
      at: 1800,
      note: `IAM ListAccessKeys — the key belongs to ${owner}, and it is active`,
      phase: "running",
      patch: { status: "investigating", key_owner: owner },
    },
    {
      at: 3600,
      note: `CloudTrail LookupEvents across ${HOME_REGION} and ${AWAY_REGION}`,
      phase: "running",
      patch: { status: "investigating", key_owner: owner },
    },
    {
      at: 5600,
      note: null,
      phase: "waiting",
      patch: { status: "investigating", key_owner: owner, blast_radius: emptyRadius },
    },
  ];

  return steps.map((step) => ({
    at: step.at,
    note: step.note,
    phase: step.phase,
    incident: structuredClone({ ...base, ...step.patch }),
    activity: [],
  }));
}

// ---------- act two: the attacker uses it ----------

export const ATTACK_RUN_MS = 17600;

export function buildAttackFrames(leak: LeakTrigger, attack: AttackTrigger): DemoFrame[] {
  const { key, owner, path, ip, first, second, rogue, bystander } = cast(leak, attack);
  const base = openedIncident(leak);
  const started = Date.parse(attack.started_at);
  const windowStart = at(Date.parse(leak.pushed_at), -10800);

  // Wall-clock offsets tell the real story — a bot moving in under two minutes. Playback
  // is faster than that, so the log times are the incident's, not the demo's.
  const log: ActivityEvent[] = [
    {
      event_name: "GetCallerIdentity",
      service: "sts",
      region: HOME_REGION,
      event_time: at(started, 0),
      source_ip: ip,
      detail: `resolved the key to ${owner}`,
      outcome: "read",
      error_code: null,
    },
    {
      event_name: "DescribeRegions",
      service: "ec2",
      region: HOME_REGION,
      event_time: at(started, 3),
      source_ip: ip,
      detail: "enumerated every region the account can reach",
      outcome: "read",
      error_code: null,
    },
    {
      event_name: "DescribeInstances",
      service: "ec2",
      region: HOME_REGION,
      event_time: at(started, 6),
      source_ip: ip,
      detail: "listed what is already running",
      outcome: "read",
      error_code: null,
    },
    {
      event_name: "RunInstances",
      service: "ec2",
      region: first.region,
      event_time: at(started, 14),
      source_ip: ip,
      detail: `launched ${first.id} (t3.micro)`,
      outcome: "created",
      error_code: null,
    },
    {
      event_name: "RunInstances",
      service: "ec2",
      region: BLOCKED_REGION,
      event_time: at(started, 22),
      source_ip: ip,
      detail: "tried g5.xlarge — the demo user is capped at t3.micro in two regions",
      outcome: "denied",
      error_code: "UnauthorizedOperation",
    },
    {
      event_name: "RunInstances",
      service: "ec2",
      region: second.region,
      event_time: at(started, 31),
      source_ip: ip,
      detail: `launched ${second.id} (t3.micro)`,
      outcome: "created",
      error_code: null,
    },
    {
      event_name: "CreateAccessKey",
      service: "iam",
      region: first.region,
      event_time: at(started, 52),
      source_ip: ip,
      detail: `minted ${rogue} for ${owner} so revoking the leaked key is not enough`,
      outcome: "created",
      error_code: null,
    },
    {
      event_name: "DeleteTrail",
      service: "cloudtrail",
      region: first.region,
      event_time: at(started, 66),
      source_ip: ip,
      detail: "tried to delete the trail that is recording all of this",
      outcome: "denied",
      error_code: "AccessDenied",
    },
  ];

  // CloudTrail event ids are uuids, and the console shows the first eight characters of
  // one next to each action. Shaping them properly keeps that line readable.
  const eventId = (n: number) => `${(0xd0e0a000 + n).toString(16)}-4c1f-4b7a-9e22-b1c2d3e4f50${n}`;

  const instance = (id: string, region: string, offset: number, n: number): CreatedResource => ({
    resource_id: id,
    kind: "ec2_instance",
    event_name: "RunInstances",
    region,
    event_time: at(started, offset),
    source_ip: ip,
    event_id: eventId(n),
  });

  const launched = instance(first.id, first.region, 14, 1);
  const launchedAbroad = instance(second.id, second.region, 31, 2);
  const minted: CreatedResource = {
    resource_id: rogue,
    kind: "iam_access_key",
    event_name: "CreateAccessKey",
    region: first.region,
    event_time: at(started, 52),
    source_ip: ip,
    event_id: eventId(3),
  };

  const radius = (resources: CreatedResource[]): BlastRadius => ({
    access_key_id: key,
    regions_searched: [HOME_REGION, AWAY_REGION],
    window_start: windowStart,
    window_end: at(started, 80),
    resources,
    problems: [],
  });

  const summary =
    `A long-term access key belonging to ${owner} was committed to ${leak.repository} in ` +
    `${path} and picked up from ${ip}. Within a minute it launched ${first.id} in ` +
    `${first.region} and ${second.id} in ${second.region}, a region this account has never ` +
    `used, and created a second access key so that revoking the leaked one would not end ` +
    `the access. Two further calls were refused by the account's own policy. I recommend ` +
    `deactivating the key, terminating both instances, and opening a pull request that ` +
    `removes ${path} from the tracked tree.`;

  const approved: VerifiedAction[] = [
    {
      action: {
        action_type: "deactivate_key",
        target: key,
        region: null,
        reason: "The key is in a pushed commit and CloudTrail shows it in use right now.",
      },
      evidence: null,
    },
    {
      action: {
        action_type: "terminate_instance",
        target: first.id,
        region: first.region,
        reason: "Launched by the leaked key fourteen seconds after the attacker picked it up.",
      },
      evidence: launched,
    },
    {
      action: {
        action_type: "terminate_instance",
        target: second.id,
        region: second.region,
        reason: "Launched by the leaked key in a region this account has never used.",
      },
      evidence: launchedAbroad,
    },
    {
      action: {
        action_type: "open_pr",
        target: leak.repository,
        region: null,
        reason: `Removes ${path} from the tracked tree and adds it to .gitignore.`,
      },
      evidence: null,
    },
  ];

  // The model reached for one more instance because it looked related. This leaked key
  // never created it, so verifier/verify.py drops it before a human sees a button for it.
  const rejected: RejectedAction[] = [
    {
      action: {
        action_type: "terminate_instance",
        target: bystander,
        region: first.region,
        reason: "This instance is in the same account and looks related to the intrusion.",
      },
      reason: "target_not_in_blast_radius",
    },
  ];

  const verification = { access_key_id: key, approved, rejected, evidence_incomplete: false };

  const tiers: TierDecision[] = ["deactivate_key", "terminate_instance", "open_pr"].map(
    (action_type) => ({
      action_type,
      tier: "human",
      source: "verified_permissions",
      determining_policy_ids: ["policy-human-for-destructive"],
      aws_error_code: null,
    }),
  );

  const investigating: Partial<Incident> = { status: "investigating", key_owner: owner };

  const steps: {
    at: number;
    note: string | null;
    phase: DemoPhase;
    events: number;
    patch: Partial<Incident>;
  }[] = [
    {
      at: 0,
      note: `The key was used from ${ip}`,
      phase: "running",
      events: 1,
      patch: { ...investigating, blast_radius: radius([]) },
    },
    {
      at: 1100,
      note: "Reconnaissance — enumerating regions",
      phase: "running",
      events: 2,
      patch: { ...investigating, blast_radius: radius([]) },
    },
    {
      at: 2200,
      note: "Reconnaissance — listing instances",
      phase: "running",
      events: 3,
      patch: { ...investigating, blast_radius: radius([]) },
    },
    {
      at: 3400,
      note: `RunInstances in ${first.region} — ${first.id}`,
      phase: "running",
      events: 4,
      patch: { ...investigating, blast_radius: radius([launched]) },
    },
    {
      at: 4600,
      note: `Refused by the account's own policy in ${BLOCKED_REGION}`,
      phase: "running",
      events: 5,
      patch: { ...investigating, blast_radius: radius([launched]) },
    },
    {
      at: 5800,
      note: `RunInstances in ${second.region} — ${second.id}`,
      phase: "running",
      events: 6,
      patch: { ...investigating, blast_radius: radius([launched, launchedAbroad]) },
    },
    {
      at: 7000,
      note: "CreateAccessKey — the attacker is building persistence",
      phase: "running",
      events: 7,
      patch: { ...investigating, blast_radius: radius([launched, launchedAbroad, minted]) },
    },
    {
      at: 8200,
      note: "DeleteTrail refused — the evidence survives",
      phase: "running",
      events: 8,
      patch: { ...investigating, blast_radius: radius([launched, launchedAbroad, minted]) },
    },
    {
      at: 10400,
      note: "Strands agent on Bedrock is writing the incident summary and a plan",
      phase: "running",
      events: 8,
      patch: {
        ...investigating,
        blast_radius: radius([launched, launchedAbroad, minted]),
        summary,
        narrator: "bedrock",
      },
    },
    {
      at: 13000,
      note: "Verifier re-checking every proposed action against CloudTrail — no model, no AWS",
      phase: "running",
      events: 8,
      patch: {
        ...investigating,
        blast_radius: radius([launched, launchedAbroad, minted]),
        summary,
        narrator: "bedrock",
        verification,
      },
    },
    {
      at: 15200,
      note: "Cedar policy: every destructive action needs a human",
      phase: "running",
      events: 8,
      patch: {
        ...investigating,
        blast_radius: radius([launched, launchedAbroad, minted]),
        summary,
        narrator: "bedrock",
        verification,
        tiers,
      },
    },
    {
      at: 17600,
      note: null,
      phase: "settled",
      events: 8,
      patch: {
        status: "awaiting_approval",
        key_owner: owner,
        blast_radius: radius([launched, launchedAbroad, minted]),
        summary,
        narrator: "bedrock",
        verification,
        tiers,
      },
    },
  ];

  return steps.map((step) => ({
    at: step.at,
    note: step.note,
    phase: step.phase,
    incident: structuredClone({ ...base, ...step.patch }),
    activity: log.slice(0, step.events),
  }));
}
