// Everything the leaked key did, as CloudTrail recorded it.
//
// The blast radius panel shows only what the key *created*, because that is all the
// verifier can act on. This is the wider read: the reconnaissance, the calls the account's
// own policy refused, and the attempt to delete the trail that was recording it. It is
// evidence, not a plan — no button here does anything.

import type { ActivityEvent } from "./script";

const OUTCOME_LABEL: Record<ActivityEvent["outcome"], string> = {
  created: "CREATED",
  read: "READ",
  denied: "REFUSED",
};

export function ActivityLog({ events }: { events: ActivityEvent[] }) {
  if (events.length === 0) return null;

  const created = events.filter((event) => event.outcome === "created").length;
  const denied = events.filter((event) => event.outcome === "denied").length;

  return (
    <section className="panel">
      <div className="panel-head head-ink">
        <h2>What the attacker did with the key</h2>
        <span className="panel-tag panel-tag-invert">
          {events.length} CALLS · {created} CREATED · {denied} REFUSED
        </span>
      </div>

      <ol className="log">
        {events.map((event, index) => (
          <li className={`log-row log-${event.outcome}`} key={`${event.event_name}-${index}`}>
            <time className="log-time">{event.event_time.slice(11, 19)}</time>
            <span className="log-name">
              <span className="log-service">{event.service}</span>
              {event.event_name}
            </span>
            <span className="log-region">{event.region}</span>
            <span className="log-detail">
              {event.detail}
              {event.error_code && <span className="log-code">{event.error_code}</span>}
            </span>
            <span className="log-outcome">{OUTCOME_LABEL[event.outcome]}</span>
          </li>
        ))}
      </ol>

      <p className="panel-foot">
        Read from CloudTrail by access key id. Only the calls that created something can be
        acted on, and only after the verifier has matched each one to a record above.
      </p>
    </section>
  );
}
