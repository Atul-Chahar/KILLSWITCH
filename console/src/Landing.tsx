// The public page. Everything on it is a claim about this repository, so each one has to
// stay true: the guard table below names files and tests that exist, and the beats under
// the video are the moments that video actually shows.

import { DemoVideo, WATCH_URL } from "./components/DemoVideo";

interface Guard {
  guard: string;
  where: string;
  checked: string;
}

const GUARDS: Guard[] = [
  {
    guard: "The model gets one turn and cannot retry past the schema",
    where: "narrate/agent.py",
    checked: "tests/test_narrate.py",
  },
  { guard: "The narrator has no tools", where: "narrate/agent.py", checked: "tests/test_narrate.py" },
  {
    guard: "Only key-created resources may be targeted",
    where: "verifier/verify.py",
    checked: "21 tests in tests/test_verifier.py",
  },
  {
    guard: "Destructive actions need a human",
    where: "authorize/policies/containment.cedar",
    checked: "tests/test_authorize.py",
  },
  {
    guard: "Nothing destroys without a scoped approval token",
    where: "containment/guard.py",
    checked: "tests/test_containment.py",
  },
  {
    guard: "One IAM statement in the stack may destroy",
    where: "infra/stacks/response.py",
    checked: "tests/test_response_stack.py",
  },
  {
    guard: "Unconfirmed end state fails the execution",
    where: "infra/stacks/response.py",
    checked: "tests/test_response_stack.py",
  },
];

const BEATS: Array<[string, string]> = [
  ["0:00", "A key is pushed to a private repo"],
  ["0:50", "The console lights up with the blast radius"],
  ["1:20", "The verifier strikes out an action on camera"],
  ["2:10", "One approval, and AWS confirms the end state"],
];

export function Landing({ onOpenConsole }: { onOpenConsole: () => void }) {
  return (
    <div>
      <header className="site-head">
        <div className="pad site-head-inner">
          <p className="wordmark">KILLSWITCH</p>
          <nav className="site-nav">
            <a href="#problem">The problem</a>
            <a href="#pillars">How it works</a>
            <a href="#safety">Safety model</a>
            <a href="#demo">Demo</a>
          </nav>
          <div className="spacer" />
          <span className="head-hint">no account needed</span>
          <button className="btn btn-red btn-sm" onClick={onOpenConsole}>
            Open The Live Console
          </button>
        </div>
      </header>

      <section className="pad hero">
        <div>
          <p className="eyebrow eyebrow-yellow">
            <span>Leaked Credential Response</span>
          </p>
          <h1>
            Your AWS keys leaked.
            <br />
            KILLSWITCH <em>pulls the plug.</em>
          </h1>
          <p className="hero-lede">
            A leaked-credential responder: it catches an AWS key the moment it escapes, shows
            exactly what the attacker did with it, and after one human approval kills the key,
            terminates what the attacker launched and opens a PR that removes the secret.
          </p>
          <div className="hero-actions">
            <button className="btn btn-red" onClick={onOpenConsole}>
              Open The Live Console
            </button>
            <a className="btn btn-outline" href="#demo">
              Watch The 3-Min Demo
            </a>
          </div>
          <p className="hero-note">
            No sign-up, no AWS account.
            <br />
            The console opens in fixture mode on a worked incident.
          </p>

          <div className="tiles tiles-3 hero-tiles">
            <div className="tile">
              <p className="tile-key">STEP FUNCTIONS</p>
              <p className="tile-val">One idempotent workflow, two triggers</p>
            </div>
            <div className="tile">
              <p className="tile-key">BEDROCK + STRANDS</p>
              <p className="tile-val">Narrator with no tools, one turn</p>
            </div>
            <div className="tile">
              <p className="tile-key">CEDAR POLICY</p>
              <p className="tile-val">Decides which actions need a human</p>
            </div>
          </div>
        </div>

        <div className="hero-side">
          <div className="grid-pale" aria-hidden="true" />
          <div className="hero-side-inner">
            <p className="live-label">
              <span className="live-dot" />
              LIVE CONSOLE, RIGHT NOW
            </p>
            <button className="peek" onClick={onOpenConsole}>
              <span className="peek-bar">
                <span className="peek-bar-mark">KILLSWITCH</span>
                <span className="peek-bar-id">inc-AKIAIOSFODNN7EXAMPLE</span>
                <span className="spacer" />
                <span className="peek-bar-status">AWAITING APPROVAL</span>
              </span>
              <span className="peek-head">
                <span className="peek-head-text">What KILLSWITCH proposes</span>
              </span>
              <span className="peek-body">
                <span className="peek-card">
                  <span className="peek-card-head">
                    <span className="peek-card-type">Deactivate key</span>
                    <span className="peek-card-target">AKIAIOSFODNN7EXAMPLE</span>
                  </span>
                  <span className="peek-card-evidence">Subject of the incident itself</span>
                  <span className="peek-card-btns">
                    <span className="peek-btn peek-btn-approve">Approve</span>
                    <span className="peek-btn peek-btn-deny">Deny</span>
                  </span>
                </span>
                <span className="peek-card">
                  <span className="peek-card-head">
                    <span className="peek-card-type">Terminate instance</span>
                    <span className="peek-card-target">i-0a1b2c3d4e5f60001</span>
                  </span>
                  <span className="peek-card-evidence">
                    RunInstances at 10:12:41 UTC, event 3f1d9c02
                  </span>
                </span>
              </span>
              <span className="peek-foot">
                <span className="peek-foot-count">2 actions still need a decision.</span>
                <span className="spacer" />
                <span className="peek-foot-cta">TAKE OVER &rarr;</span>
              </span>
            </button>
            <p className="peek-caption">Same shell, same data. Clicking this opens it full size.</p>
          </div>
        </div>
      </section>

      <section id="problem" className="band">
        <div className="pad band-inner">
          <p className="eyebrow eyebrow-pink">
            <span>The Problem</span>
          </p>
          <div className="split">
            <h2>
              The tools that exist mostly <em>alert</em>. Somebody still has to do the work.
            </h2>
            <div>
              <p>
                Unit 42 tracked attackers pulling AWS keys off GitHub within five minutes of
                exposure, then launching EC2 instances across regions about seven minutes later.
                AWS auto-quarantines some leaked keys, but quarantine does not terminate what the
                attacker already launched, clean your repository, or tell you what happened.
              </p>
              <p>
                Somebody has to work out what the key touched, decide what to destroy, destroy it,
                and check it worked — at 2am, under time pressure, from whatever device is to hand.
                For a student on a free-tier account, the first sign is the bill.
              </p>
            </div>
          </div>
          <div className="tiles tiles-3 stats">
            <div className="stat stat-green">
              <p className="stat-figure">5 min</p>
              <div className="spacer" />
              <p className="stat-label">from a key hitting a public repo to a bot holding it</p>
            </div>
            <div className="stat stat-blue">
              <p className="stat-figure">~7 min</p>
              <div className="spacer" />
              <p className="stat-label">
                later, EC2 instances running in regions you have never used
              </p>
            </div>
            <div className="stat stat-pink">
              <p className="stat-figure">2am</p>
              <div className="spacer" />
              <p className="stat-label">when you find out, on the phone in your hand</p>
            </div>
          </div>
        </div>
      </section>

      <section id="pillars" className="pad section">
        <p className="eyebrow eyebrow-green">
          <span>How It Works</span>
        </p>
        <h2 className="section-title">The model proposes. Plain code verifies. A human approves.</h2>
        <p className="section-lede">
          Three stages, three different kinds of authority. None of them can do the next one&rsquo;s
          job.
        </p>

        <div className="pillars">
          <div className="pillar pillar-1">
            <div className="pillar-head">
              <p className="pillar-num">01</p>
              <h3>Proposes</h3>
            </div>
            <div className="pillar-body">
              <p>
                The Strands agent on Bedrock writes the prose and proposes the actions. It is given{" "}
                <strong>no tools</strong>, so it has nothing to act with, and one turn, so it cannot
                retry past the schema.
              </p>
              <div className="spacer" />
              <div className="snippet snippet-1">
                <p className="snippet-file">narrate/agent.py</p>
                <p>tools = []</p>
                <p>max_turns = 1</p>
                <p className="snippet-note">&rarr; prose, never evidence</p>
              </div>
            </div>
          </div>

          <div className="pillar pillar-2">
            <div className="pillar-head">
              <p className="pillar-num">02</p>
              <h3>Verifies</h3>
            </div>
            <div className="pillar-body">
              <p>
                Ordinary Python. No AWS calls, no model calls — enforced by a test that fails the
                build on a <code>boto3</code> import. It re-checks every proposed action against
                CloudTrail and drops anything the leaked key did not create.
              </p>
              <div className="spacer" />
              <div className="snippet snippet-2">
                <p className="snippet-file">verifier/verify.py</p>
                <p>
                  i-0a1b2c3d4e5f60001 <span className="snippet-kept">kept</span>
                </p>
                <p className="snippet-dropped">i-0999999999ffffff9</p>
                <p className="snippet-reason">&rarr; target_not_in_blast_radius</p>
              </div>
            </div>
          </div>

          <div className="pillar pillar-3">
            <div className="pillar-head">
              <p className="pillar-num">03</p>
              <h3>Approves</h3>
            </div>
            <div className="pillar-body">
              <p>
                A Cedar policy decides which actions need a human. Nothing destroys anything without
                an approval token scoped to that exact action <strong>and</strong> that exact
                approval round. A decision from a superseded round authorises nothing.
              </p>
              <div className="spacer" />
              <div className="snippet snippet-3">
                <p className="snippet-file">containment/guard.py</p>
                <p>token.action == action</p>
                <p>token.round == current</p>
                <p className="snippet-note">&rarr; else refuse, and record it</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="safety" className="pad safety">
        <div className="safety-box">
          <div className="safety-head">
            <p className="eyebrow eyebrow-lilac">
              <span>Safety Model</span>
            </p>
            <h2>Reads are free. Writes go through one gate, and every guard is checked by a test.</h2>
          </div>

          <div className="flow">
            <div className="flow-box flow-reads">
              <p className="flow-kind">READS</p>
              <p>CloudTrail, IAM, repo diff</p>
            </div>
            <span className="arrow" aria-hidden="true">
              &rarr;
            </span>
            <div className="flow-box flow-gate">
              <p className="flow-kind">HUMAN GATE</p>
              <p>Per-action approval, Cedar decides which</p>
            </div>
            <span className="arrow" aria-hidden="true">
              &rarr;
            </span>
            <div className="flow-box flow-writes">
              <p className="flow-kind">WRITES</p>
              <p>Deactivate key, terminate instances, open PR</p>
              <p className="flow-sub">then re-read AWS to confirm</p>
            </div>
          </div>

          <div className="guards">
            <div className="guard-head">
              <span>GUARD</span>
              <span>WHERE IT LIVES</span>
              <span>CHECKED BY</span>
            </div>
            {GUARDS.map((guard) => (
              <div className="guard-row" key={guard.guard}>
                <span className="guard-what">{guard.guard}</span>
                <span className="guard-where">{guard.where}</span>
                <span className="guard-checked">{guard.checked}</span>
              </div>
            ))}
          </div>
          <p className="safety-foot">
            What the verifier does not catch is written down, unflatteringly, in{" "}
            <code>docs/VERIFIER-LIMITS.md</code>. The short version: it cannot see omission, and it
            cannot stop the model talking to the human.
          </p>
        </div>
      </section>

      <section id="demo" className="pad demo">
        <div className="demo-head">
          <div>
            <p className="eyebrow eyebrow-yellow">
              <span>Demo</span>
            </p>
            <h2>Three minutes, one leaked key, no edits.</h2>
          </div>
          <button className="btn btn-outline btn-sm" onClick={onOpenConsole}>
            Skip The Video, Open The Console &rarr;
          </button>
        </div>
        <DemoVideo />
        <p className="demo-caption">
          Plays muted, because browsers block an unmuted autoplay.{" "}
          <a href={WATCH_URL} target="_blank" rel="noreferrer">
            Watch it with sound on YouTube &rarr;
          </a>
        </p>
        <div className="tiles tiles-4 beats">
          {BEATS.map(([time, label]) => (
            <div className="beat" key={time}>
              <p className="beat-time">{time}</p>
              <p className="beat-label">{label}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="pad cta">
        <div className="cta-box">
          <div>
            <h2>Open the console and approve a real containment plan.</h2>
            <p>
              It loads a worked incident from the repository fixture: two instances in two regions,
              one action the verifier struck out, and one resource the plan ignored.
            </p>
          </div>
          <div className="cta-side">
            <button className="btn btn-red btn-red-bright" onClick={onOpenConsole}>
              Open The Live Console &rarr;
            </button>
            <p>Nothing in this repository has ever run against AWS.</p>
          </div>
        </div>
      </section>

      <footer className="pad site-foot">
        <span className="site-foot-mark">KILLSWITCH</span>
        <span className="site-foot-meta">
          First Commit &middot; 17&ndash;20 September 2026 &middot; Ship It track
        </span>
        <div className="spacer" />
        <a href="#problem">Repository</a>
        <a href="#safety">Limitations</a>
      </footer>
    </div>
  );
}
