// What the console shows before anything has leaked.
//
// It is the screen the demo opens on, so it has to say plainly what KILLSWITCH is watching
// and what will make it move. The command is on screen because the operator runs it live
// in the next breath.

interface Props {
  repository: string;
  error: string | null;
}

const WATCHING = [
  { key: "REPOSITORY", value: "push webhook on the default branch" },
  { key: "AWS", value: "quarantine events via EventBridge" },
  { key: "REGIONS", value: "ap-south-1, us-east-1" },
  { key: "POLICY", value: "Cedar — a human approves every destructive call" },
];

export function Standby({ repository, error }: Props) {
  return (
    <div className="standby">
      <div className="standby-head">
        <span className="standby-dot" />
        <p className="standby-state">ARMED</p>
      </div>

      <h1 className="standby-title">
        Watching <em>{repository}</em>
      </h1>
      <p className="standby-lede">
        No incident open. The moment an AWS key lands in a push, this screen fills in as the
        workflow runs — identify, blast radius, narrate, verify, authorize — and stops at the
        approval.
      </p>

      <div className="standby-grid">
        {WATCHING.map((row) => (
          <div className="standby-cell" key={row.key}>
            <p className="standby-cell-key">{row.key}</p>
            <p className="standby-cell-val">{row.value}</p>
          </div>
        ))}
      </div>

      <div className="standby-cmd">
        <p className="standby-cmd-head">TO SET IT OFF</p>
        <code>./scripts/demo_leak.sh</code>
        <p className="standby-cmd-note">
          Commits a credentials file to the watched repository and pushes it. The keys it
          generates are fake and grant nothing.
        </p>
      </div>

      {error && <p className="banner banner-error standby-error">{error}</p>}
    </div>
  );
}
