// The workflow narrating itself, line by line.
//
// It scrolls itself to the newest line, because on a projector the interesting line is
// always the last one. Like everything else in demo mode these lines are scripted rather
// than emitted by a real run, and the panel says so at the bottom.

import { useEffect, useRef } from "react";

import type { LogLine } from "./log";

export function LogPanel({ lines, live }: { lines: LogLine[]; live: boolean }) {
  const body = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const node = body.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [lines.length]);

  if (lines.length === 0) return null;

  return (
    <section className="panel">
      <div className="panel-head head-ink">
        <h2>Workflow log</h2>
        <span className="panel-tag panel-tag-invert">
          {live ? "STREAMING" : `${lines.length} LINES`}
        </span>
      </div>

      <div className="logbox" ref={body}>
        {lines.map((line, index) => (
          <p className={`logline logline-${line.level}`} key={index}>
            <span className="logline-stage">{line.stage}</span>
            <span className="logline-text">{line.text}</span>
          </p>
        ))}
        {live && (
          <p className="logline logline-caret">
            <span className="logline-stage" />
            <span className="logline-text">▊</span>
          </p>
        )}
      </div>

      <p className="panel-foot">
        Scripted for the demo, in the shape the workflow logs. Nothing on this screen calls AWS.
      </p>
    </section>
  );
}
