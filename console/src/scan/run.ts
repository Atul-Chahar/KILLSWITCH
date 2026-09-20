// Running a scan, and reporting what it actually did.
//
// The progress a caller sees is the work as it happens, not a timer pretending to be
// work: each step is emitted when the request behind it returns. If a scan is quick, the
// steps go by quickly, and that is the truth of it.

import {
  fetchFile,
  fetchRepo,
  fetchTree,
  pickCandidates,
  ScanError,
  type RepoInfo,
  type RepoRef,
} from "./github";
import { scanText, type Finding } from "./patterns";

export interface ScanStep {
  label: string;
  detail: string | null;
  state: "running" | "done";
}

export interface ScanResult {
  info: RepoInfo;
  // How many files were actually read, and how many the repository holds in total.
  filesScanned: number;
  filesInRepo: number;
  // True when the file cap stopped the scan short of the whole repository.
  capped: boolean;
  findings: Finding[];
}

export interface ScanHandlers {
  onStep: (steps: ScanStep[]) => void;
}

export async function runScan(ref: RepoRef, handlers: ScanHandlers): Promise<ScanResult> {
  const steps: ScanStep[] = [];

  const begin = (label: string) => {
    steps.push({ label, detail: null, state: "running" });
    handlers.onStep([...steps]);
  };
  const finish = (detail: string) => {
    const step = steps[steps.length - 1];
    if (step) {
      step.detail = detail;
      step.state = "done";
    }
    handlers.onStep([...steps]);
  };

  begin(`Resolving ${ref.owner}/${ref.repo}`);
  const info = await fetchRepo(ref);
  finish(`default branch ${info.defaultBranch}`);

  begin("Listing the tracked files");
  const tree = await fetchTree(info);
  if (tree.length === 0) throw new ScanError("this repository has no files", "empty");
  finish(`${tree.length} files`);

  begin("Choosing the files worth reading");
  const candidates = pickCandidates(tree);
  finish(`${candidates.length} candidates`);

  const findings: Finding[] = [];
  let read = 0;
  begin("Reading each file and matching credential patterns");
  for (const path of candidates) {
    const text = await fetchFile(info, path);
    if (text === null) continue;
    read += 1;
    findings.push(...scanText(path, text));
    const step = steps[steps.length - 1];
    if (step) {
      step.detail = `${read}/${candidates.length} — ${path}`;
      handlers.onStep([...steps]);
    }
  }
  finish(`${read} files read, ${findings.length} match${findings.length === 1 ? "" : "es"}`);

  return {
    info,
    filesScanned: read,
    filesInRepo: tree.length,
    capped: candidates.length < tree.length,
    findings,
  };
}
