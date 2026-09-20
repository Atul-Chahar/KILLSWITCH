// Pick a public repository, and watch it actually get read.
//
// This is the only part of the console that does real work in the browser: it reads the
// repository through GitHub's public API and scans what it finds for committed
// credentials, using the patterns detect/patterns.py already trusts. The steps on screen
// are the requests as they return, not a timer dressed up as progress.
//
// What it is not: the rest of KILLSWITCH. Finding a key in a repository is the first of
// the workflow's seven stages. Rebuilding the blast radius from CloudTrail, verifying a
// plan against it and containing anything all need AWS, and none of that happens here —
// the panel says so rather than letting a green tick imply an account was touched.

import { useCallback, useEffect, useRef, useState } from "react";

import { parseRepoInput, ScanError, type RepoRef } from "../scan/github";
import { FINDING_LABEL } from "../scan/patterns";
import { runScan, type ScanResult, type ScanStep } from "../scan/run";

const SUGGESTIONS = ["Atul-Chahar/KILLSWITCH", "gyanranjanpanda/AI-Video-Assistant-"];

type Phase = "idle" | "scanning" | "done" | "failed";

export function RepoWatch({ onOpenIncident }: { onOpenIncident: () => void }) {
  const [input, setInput] = useState("");
  const [phase, setPhase] = useState<Phase>("idle");
  const [steps, setSteps] = useState<ScanStep[]>([]);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  // A scan that is still in flight when the user starts another must not write its
  // results over the newer one.
  const run = useRef(0);

  const start = useCallback(async (ref: RepoRef) => {
    const ticket = run.current + 1;
    run.current = ticket;
    setPhase("scanning");
    setSteps([]);
    setResult(null);
    setError(null);
    try {
      const scanned = await runScan(ref, {
        onStep: (next) => {
          if (run.current === ticket) setSteps(next);
        },
      });
      if (run.current !== ticket) return;
      setResult(scanned);
      setPhase("done");
    } catch (cause) {
      if (run.current !== ticket) return;
      setError(cause instanceof ScanError ? cause.message : String(cause));
      setPhase("failed");
    }
  }, []);

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const ref = parseRepoInput(input);
    if (!ref) {
      setError("Enter a repository as owner/name, or paste its GitHub URL.");
      setPhase("failed");
      return;
    }
    void start(ref);
  }

  // A ?repo= link scans on arrival, so a scan can be shared or shown from a slide.
  useEffect(() => {
    const fromQuery = new URLSearchParams(window.location.search).get("repo");
    if (!fromQuery) return;
    const ref = parseRepoInput(fromQuery);
    if (!ref) return;
    setInput(fromQuery);
    void start(ref);
  }, [start]);

  const busy = phase === "scanning";

  return (
    <div className="watch">
      <div className="watch-head">
        <p className="eyebrow eyebrow-lilac">
          <span>Watch a repository</span>
        </p>
        <h1 className="watch-title">
          Point it at a public repo. It reads the files and looks for keys.
        </h1>
        <p className="watch-lede">
          The scan runs in this browser against GitHub's public API. Nothing is uploaded,
          no token is asked for, and the secrets it finds are redacted before they reach
          the screen.
        </p>
      </div>

      <form className="watch-form" onSubmit={submit}>
        <input
          className="watch-input"
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder="owner/repository"
          aria-label="Public GitHub repository"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          disabled={busy}
        />
        <button className="btn btn-red btn-red-bright" type="submit" disabled={busy}>
          {busy ? "Scanning…" : "Scan Repository"}
        </button>
      </form>

      <div className="watch-suggest">
        <span>Try</span>
        {SUGGESTIONS.map((name) => (
          <button
            key={name}
            type="button"
            className="watch-chip"
            disabled={busy}
            onClick={() => {
              setInput(name);
              const ref = parseRepoInput(name);
              if (ref) void start(ref);
            }}
          >
            {name}
          </button>
        ))}
      </div>

      {steps.length > 0 && (
        <ol className="watch-steps">
          {steps.map((step, index) => (
            <li className={`watch-step watch-step-${step.state}`} key={index}>
              <span className="watch-step-mark">{step.state === "done" ? "✓" : "—"}</span>
              <span className="watch-step-label">{step.label}</span>
              {step.detail && <span className="watch-step-detail">{step.detail}</span>}
            </li>
          ))}
        </ol>
      )}

      {phase === "failed" && error && <p className="banner banner-error">{error}</p>}

      {phase === "done" && result && (
        <ScanReport result={result} onOpenIncident={onOpenIncident} />
      )}
    </div>
  );
}

function ScanReport({
  result,
  onOpenIncident,
}: {
  result: ScanResult;
  onOpenIncident: () => void;
}) {
  const { findings, info } = result;
  const clean = findings.length === 0;

  return (
    <section className="panel watch-report">
      <div className={clean ? "panel-head head-green" : "panel-head head-pink"}>
        <h2>{clean ? "No exposed credentials found" : "Exposed credentials found"}</h2>
        <span className="panel-tag">
          {result.filesScanned} FILE{result.filesScanned === 1 ? "" : "S"} READ
        </span>
      </div>

      {clean ? (
        <p className="watch-verdict">
          Nothing in the {result.filesScanned} files read matched a credential pattern.
          That is not the same as the repository being clean:{" "}
          {result.capped
            ? `it holds ${result.filesInRepo} files and this scan read the ${result.filesScanned} likeliest, `
            : ""}
          it cannot see deleted files that remain in the history, and it only knows the
          patterns listed below.
        </p>
      ) : (
        <>
          <div className="watch-find-head">
            <span>WHAT</span>
            <span>WHERE</span>
            <span>MATCH</span>
          </div>
          {findings.map((finding, index) => (
            <div className="watch-find" key={`${finding.path}-${finding.line}-${index}`}>
              <span className="watch-find-kind">{FINDING_LABEL[finding.kind]}</span>
              <a
                className="watch-find-where"
                href={`${info.htmlUrl}/blob/${info.defaultBranch}/${finding.path}#L${finding.line}`}
                target="_blank"
                rel="noreferrer"
              >
                {finding.path}:{finding.line}
              </a>
              <span className="watch-find-evidence">{finding.evidence}</span>
            </div>
          ))}
        </>
      )}

      <div className="watch-next">
        <p>
          <strong>This is stage one of seven.</strong> Finding the key is the part that can
          be done from a browser. Rebuilding what the key did from CloudTrail, verifying a
          containment plan against that evidence, and running it after an approval all need
          an AWS account, and none of it happened here.
        </p>
        <button className="btn btn-outline btn-sm" onClick={onOpenIncident}>
          See the full response on a worked incident &rarr;
        </button>
      </div>

      <p className="panel-foot">
        Patterns: AWS access key ids and session tokens, assigned AWS secret access keys,
        GitHub tokens, and private key headers. AWS's own documentation key is ignored, as
        it is in <code>detect/patterns.py</code>.
      </p>
    </section>
  );
}
