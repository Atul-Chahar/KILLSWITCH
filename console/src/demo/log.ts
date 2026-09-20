// The running log the demo streams into the console.
//
// It is the workflow narrating itself: the calls it makes, what came back, and where it
// stops. Like the rest of the demo these lines are written by hand rather than emitted by
// a real run, which is why the panel that shows them says so.
//
// Timings are milliseconds from the start of the act, and are tuned to land next to the
// matching frame in script.ts — a line about CloudTrail should appear as the blast radius
// panel fills, not four seconds after it.

export type LogLevel = "cmd" | "info" | "ok" | "warn" | "err";

export interface LogLine {
  at: number;
  level: LogLevel;
  stage: string;
  text: string;
}

export interface LogCast {
  key: string;
  owner: string;
  repository: string;
  path: string;
  commit: string;
  ip: string;
  first: { id: string; region: string };
  second: { id: string; region: string };
  rogue: string;
  bystander: string;
}

// ---------- act one: the push ----------

export function leakLog(cast: LogCast): LogLine[] {
  const short = cast.commit.slice(0, 7);
  return [
    { at: 0, level: "cmd", stage: "api", text: `POST /webhook/github — push ${cast.repository}` },
    { at: 160, level: "info", stage: "detect", text: `commit ${short}, 1 file changed` },
    { at: 340, level: "info", stage: "detect", text: "scanning the diff for credential patterns" },
    {
      at: 620,
      level: "warn",
      stage: "detect",
      text: `match: AWS_ACCESS_KEY_ID at ${cast.path}:3`,
    },
    {
      at: 820,
      level: "warn",
      stage: "detect",
      text: `match: AWS_SECRET_ACCESS_KEY at ${cast.path}:4`,
    },
    {
      at: 1020,
      level: "info",
      stage: "detect",
      text: "prefix AKIA — a long-term key, not a session token",
    },
    {
      at: 1240,
      level: "ok",
      stage: "state",
      text: `dynamodb PutItem inc-${cast.key} (attribute_not_exists — idempotent)`,
    },
    { at: 1440, level: "info", stage: "state", text: "stepfunctions StartExecution response" },
    { at: 1700, level: "cmd", stage: "identify", text: "iam ListAccessKeys" },
    { at: 1960, level: "ok", stage: "identify", text: `owner ${cast.owner}, status Active` },
    { at: 2160, level: "info", stage: "identify", text: "iam GetAccessKeyLastUsed — never used" },
    {
      at: 2500,
      level: "cmd",
      stage: "radius",
      text: `cloudtrail LookupEvents --region ${cast.first.region}`,
    },
    { at: 2900, level: "info", stage: "radius", text: "0 events for this access key id" },
    {
      at: 3200,
      level: "cmd",
      stage: "radius",
      text: `cloudtrail LookupEvents --region ${cast.second.region}`,
    },
    { at: 3600, level: "info", stage: "radius", text: "0 events for this access key id" },
    {
      at: 3950,
      level: "warn",
      stage: "radius",
      text: "delivery lags up to 15 min — an empty result is not proof of nothing",
    },
    { at: 4300, level: "info", stage: "radius", text: "blast radius: 0 resources, 2 regions" },
    {
      at: 4700,
      level: "ok",
      stage: "workflow",
      text: "holding. the key is live and nothing has used it.",
    },
    { at: 5200, level: "info", stage: "watch", text: "re-reading CloudTrail every 60s" },
  ];
}

// ---------- act two: the attacker ----------

export function attackLog(cast: LogCast): LogLine[] {
  return [
    {
      at: 0,
      level: "warn",
      stage: "watch",
      text: `new CloudTrail activity for ${cast.key} from ${cast.ip}`,
    },
    {
      at: 260,
      level: "info",
      stage: "watch",
      text: "source address has never appeared in this account",
    },
    { at: 560, level: "cmd", stage: "attacker", text: "sts GetCallerIdentity" },
    { at: 800, level: "info", stage: "attacker", text: `resolved to user/${cast.owner}` },
    { at: 1160, level: "cmd", stage: "attacker", text: "ec2 DescribeRegions" },
    { at: 1400, level: "info", stage: "attacker", text: "17 regions enabled" },
    {
      at: 1760,
      level: "cmd",
      stage: "attacker",
      text: `ec2 DescribeInstances --region ${cast.first.region}`,
    },
    { at: 2000, level: "info", stage: "attacker", text: "0 running" },
    {
      at: 2300,
      level: "warn",
      stage: "triage",
      text: "recon finished in six seconds — this is automated, not a person",
    },
    {
      at: 2900,
      level: "cmd",
      stage: "attacker",
      text: `ec2 RunInstances --region ${cast.first.region}`,
    },
    { at: 3300, level: "err", stage: "attacker", text: `LAUNCHED ${cast.first.id} (t3.micro)` },
    { at: 3600, level: "ok", stage: "radius", text: "recorded: 1 resource created by this key" },
    { at: 4200, level: "cmd", stage: "attacker", text: "ec2 RunInstances --region eu-west-1" },
    {
      at: 4600,
      level: "info",
      stage: "attacker",
      text: "REFUSED UnauthorizedOperation — g5.xlarge is outside the user's policy",
    },
    {
      at: 4900,
      level: "ok",
      stage: "triage",
      text: "the account's own guardrail held. it caps this user at t3.micro in two regions.",
    },
    {
      at: 5400,
      level: "cmd",
      stage: "attacker",
      text: `ec2 RunInstances --region ${cast.second.region}`,
    },
    { at: 5800, level: "err", stage: "attacker", text: `LAUNCHED ${cast.second.id} (t3.micro)` },
    {
      at: 6100,
      level: "warn",
      stage: "triage",
      text: `${cast.second.region} has no prior activity in this account`,
    },
    { at: 6600, level: "cmd", stage: "attacker", text: "iam CreateAccessKey" },
    { at: 7000, level: "err", stage: "attacker", text: `MINTED ${cast.rogue}` },
    {
      at: 7300,
      level: "warn",
      stage: "triage",
      text: "persistence: revoking the leaked key alone would not end this access",
    },
    { at: 7900, level: "cmd", stage: "attacker", text: "cloudtrail DeleteTrail" },
    { at: 8300, level: "info", stage: "attacker", text: "REFUSED AccessDenied" },
    { at: 8600, level: "ok", stage: "triage", text: "the evidence survives. the trail is intact." },
    {
      at: 9200,
      level: "info",
      stage: "radius",
      text: "blast radius: 3 resources, 8 calls, 2 regions",
    },
    { at: 9800, level: "cmd", stage: "narrate", text: "bedrock InvokeModel — strands agent" },
    { at: 10600, level: "info", stage: "narrate", text: "drafting the incident summary" },
    { at: 11600, level: "info", stage: "narrate", text: "proposing a containment plan" },
    { at: 12400, level: "ok", stage: "narrate", text: "model returned 5 proposed actions" },
    {
      at: 12900,
      level: "cmd",
      stage: "verify",
      text: "verifier/verify.py — no model, no AWS calls",
    },
    {
      at: 13300,
      level: "ok",
      stage: "verify",
      text: `deactivate_key ${cast.key} — subject of the incident, kept`,
    },
    {
      at: 13600,
      level: "ok",
      stage: "verify",
      text: `terminate_instance ${cast.first.id} — matched to a RunInstances record, kept`,
    },
    {
      at: 13900,
      level: "ok",
      stage: "verify",
      text: `terminate_instance ${cast.second.id} — matched to a RunInstances record, kept`,
    },
    {
      at: 14200,
      level: "err",
      stage: "verify",
      text: `terminate_instance ${cast.bystander} — DROPPED, this key never created it`,
    },
    {
      at: 14500,
      level: "ok",
      stage: "verify",
      text: `open_pr ${cast.repository} — the leaking repository, kept`,
    },
    { at: 14800, level: "info", stage: "verify", text: "4 of 5 actions survived the evidence" },
    { at: 15300, level: "cmd", stage: "authorize", text: "verifiedpermissions IsAuthorized" },
    {
      at: 15700,
      level: "info",
      stage: "authorize",
      text: "cedar policy-human-for-destructive matched on all 3 action types",
    },
    { at: 16200, level: "ok", stage: "authorize", text: "tier: human required for every action" },
    {
      at: 16700,
      level: "cmd",
      stage: "approve",
      text: "stepfunctions waitForTaskToken — execution paused",
    },
    {
      at: 17300,
      level: "warn",
      stage: "approve",
      text: "nothing will run until a human presses a button.",
    },
  ];
}

// ---------- the operator decides ----------

export function containmentLog(
  cast: LogCast,
  approved: string[],
  denied: string[],
): LogLine[] {
  const lines: LogLine[] = [
    {
      at: 0,
      level: "cmd",
      stage: "approve",
      text: `SendTaskSuccess — token scoped to ${approved.length + denied.length} decisions`,
    },
    {
      at: 260,
      level: "info",
      stage: "approve",
      text: "dynamodb: recording each decision against its action signature",
    },
  ];
  let clock = 600;

  for (const signature of denied) {
    lines.push({
      at: clock,
      level: "warn",
      stage: "contain",
      text: `${signature} — DENIED by the operator, nothing run`,
    });
    clock += 400;
  }

  for (const signature of approved) {
    const [type = "", target = ""] = signature.split(":");
    lines.push({
      at: clock,
      level: "info",
      stage: "contain",
      text: `${type} ${target} — approval token found, proceeding`,
    });
    if (type === "deactivate_key") {
      lines.push({
        at: clock + 320,
        level: "cmd",
        stage: "contain",
        text: `iam UpdateAccessKey --access-key-id ${target} --status Inactive`,
      });
      lines.push({ at: clock + 700, level: "ok", stage: "contain", text: "key is Inactive" });
    } else if (type === "terminate_instance") {
      lines.push({
        at: clock + 320,
        level: "cmd",
        stage: "contain",
        text: `ec2 TerminateInstances --instance-ids ${target}`,
      });
      lines.push({
        at: clock + 700,
        level: "ok",
        stage: "contain",
        text: `${target} is shutting-down`,
      });
    } else {
      lines.push({
        at: clock + 320,
        level: "cmd",
        stage: "contain",
        text: "github: branch killswitch/remove-leaked-credentials",
      });
      lines.push({
        at: clock + 560,
        level: "info",
        stage: "contain",
        text: `git rm --cached ${cast.path}; echo ${cast.path} >> .gitignore`,
      });
      lines.push({
        at: clock + 860,
        level: "ok",
        stage: "contain",
        text: `pull request opened against ${target}`,
      });
    }
    clock += 1100;
  }

  lines.push({
    at: clock,
    level: "cmd",
    stage: "confirm",
    text: "re-reading AWS — an action is not done because the API returned 200",
  });
  clock += 400;
  for (const signature of approved) {
    const [type = "", target = ""] = signature.split(":");
    lines.push({
      at: clock,
      level: "ok",
      stage: "confirm",
      text: `${target} CONFIRMED (${type})`,
    });
    clock += 280;
  }

  lines.push({
    at: clock + 300,
    level: "warn",
    stage: "confirm",
    text: `${cast.rogue} is still active — no action was proposed for it, so none was taken`,
  });
  lines.push({
    at: clock + 800,
    level: approved.length > 0 && denied.length === 0 ? "ok" : "warn",
    stage: "workflow",
    text:
      denied.length > 0
        ? `incident declined — ${approved.length} run and confirmed, ${denied.length} withheld`
        : `incident contained — ${approved.length}/${approved.length} actions confirmed`,
  });
  return lines;
}

export function containmentDurationMs(lines: LogLine[]): number {
  const last = lines[lines.length - 1];
  return last ? last.at + 400 : 0;
}
