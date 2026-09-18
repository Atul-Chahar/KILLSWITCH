import { workflowStages } from "../stages";
import type { Incident } from "../types";
import { CostAvoided } from "./CostAvoided";

interface Fact {
  key: string;
  value: string;
}

// Only facts the record actually carries. An empty row here would read as "we looked and
// there was nothing", which is a different claim from "the workflow has not got there yet".
function facts(incident: Incident): Fact[] {
  const found: Fact[] = [];
  if (incident.repository) found.push({ key: "REPOSITORY", value: incident.repository });
  if (incident.commit_sha) found.push({ key: "COMMIT", value: incident.commit_sha.slice(0, 7) });
  if (incident.key_owner) found.push({ key: "KEY OWNER", value: incident.key_owner });
  found.push({ key: "SOURCE", value: incident.source });
  return found;
}

export function WorkflowRail({ incident, undecided }: { incident: Incident; undecided: number }) {
  const stages = workflowStages(incident, undecided);

  return (
    <aside className="rail">
      <div className="rail-box">
        <div className="rail-head rail-head-lilac">
          <p>RESPONSE WORKFLOW</p>
        </div>
        <ol className="stages">
          {stages.map((stage) => (
            <li className={`stage stage-${stage.state}`} key={stage.key}>
              <span className="stage-num">{stage.num}</span>
              <span>
                <span className="stage-name">{stage.name}</span>
                <span className="stage-note">{stage.note}</span>
              </span>
            </li>
          ))}
        </ol>
      </div>

      <CostAvoided incident={incident} />

      <div className="rail-box">
        <div className="rail-head rail-head-plain">
          <p>INCIDENT</p>
        </div>
        <div className="facts">
          {facts(incident).map((fact) => (
            <div key={fact.key}>
              <p className="fact-key">{fact.key}</p>
              <p className="fact-val">{fact.value}</p>
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
