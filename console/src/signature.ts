// Must match shared/approvals.py::action_signature exactly. A decision recorded under a
// different string authorises nothing, which is the correct failure but a confusing one.

import type { ProposedAction } from "./types";

export function actionSignature(action: ProposedAction): string {
  return `${action.action_type}:${action.target}:${action.region ?? "-"}`;
}
