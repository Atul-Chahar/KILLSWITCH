// Demo mode: the console watches two files instead of an API.
//
// scripts/demo_leak.sh pushes a commit and drops leak.json. scripts/demo_attack.sh drops
// attack.json. This polls for both, and plays the matching act from script.ts frame by
// frame — so the dashboard moves because the operator ran a command, not because of a
// timer that would drift out of step with the demo.
//
// It exists so the whole response can be filmed without an AWS account. Every screen it
// drives is badged DEMO MODE.

import { setFixtureIncident } from "../api";
import type { Incident } from "../types";
import {
  attackLog,
  containmentDurationMs,
  containmentLog,
  leakLog,
  type LogLine,
} from "./log";
import {
  ATTACK_RUN_MS,
  buildAttackFrames,
  buildLeakFrames,
  LEAK_RUN_MS,
  logCast,
  type ActivityEvent,
  type AttackTrigger,
  type DemoFrame,
  type DemoPhase,
  type LeakTrigger,
} from "./script";

const LEAK_URL = "/demo/leak.json";
const ATTACK_URL = "/demo/attack.json";
const WATCH_MS = 700;

export interface DemoState {
  phase: DemoPhase;
  leak: LeakTrigger | null;
  incident: Incident | null;
  activity: ActivityEvent[];
  log: LogLine[];
  // True while lines are still arriving, so the panel can show a caret.
  streaming: boolean;
  // What the workflow is doing right now. Null once there is nothing left to wait for.
  note: string | null;
  progress: number;
  error: string | null;
}

export function isDemoMode(): boolean {
  return import.meta.env.VITE_DEMO === "1";
}

let state: DemoState = {
  phase: "standby",
  leak: null,
  incident: null,
  activity: [],
  log: [],
  streaming: false,
  note: null,
  progress: 0,
  error: null,
};

const listeners = new Set<(next: DemoState) => void>();
let timers: number[] = [];

function emit(patch: Partial<DemoState>): void {
  state = { ...state, ...patch };
  for (const listener of listeners) listener(state);
}

export function getDemoState(): DemoState {
  return state;
}

export function subscribeDemo(listener: (next: DemoState) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function clearTimers(): void {
  for (const timer of timers) window.clearTimeout(timer);
  timers = [];
}

// Log lines arrive on their own clock, several times a second, so that the panel keeps
// moving between the frames rather than jumping once every couple of seconds.
function playLog(lines: LogLine[], reset: boolean): number {
  if (reset) emit({ log: [] });
  emit({ streaming: true });
  for (const line of lines) {
    timers.push(
      window.setTimeout(() => emit({ log: [...state.log, line] }), line.at),
    );
  }
  const last = lines[lines.length - 1]?.at ?? 0;
  timers.push(window.setTimeout(() => emit({ streaming: false }), last + 300));
  return last;
}

function play(frames: DemoFrame[], runMs: number): void {
  for (const frame of frames) {
    timers.push(
      window.setTimeout(() => {
        // The approval round runs against the record the demo just built, so approving in
        // fixture mode contains exactly what is on screen.
        setFixtureIncident(frame.incident);
        emit({
          phase: frame.phase,
          incident: frame.incident,
          activity: frame.activity,
          note: frame.note,
          progress: Math.min(1, frame.at / runMs),
        });
      }, frame.at),
    );
  }
}

async function readTrigger<T>(url: string): Promise<T | null> {
  let response: Response;
  try {
    response = await fetch(`${url}?t=${Date.now()}`, { cache: "no-store" });
  } catch {
    // The dev server went away. Standby is the honest state, not an error banner that
    // would sit on screen for the rest of the demo.
    return null;
  }
  if (!response.ok) return null;
  try {
    return (await response.json()) as T;
  } catch {
    // Some setups answer a missing path with index.html. That is still standby.
    return null;
  }
}

// Re-running demo_leak.sh starts a fresh incident, which is how a second take works.
// Kept outside the watcher so the containment log can be replayed from the approval bar.
let currentAttack: AttackTrigger | null = null;

// Streams the containment log, and resolves when the last line has landed. The approval
// bar awaits it, so the end state appears after the work rather than before it.
export function runContainmentLog(approved: string[], denied: string[]): Promise<void> {
  const leak = state.leak;
  if (!leak) return Promise.resolve();
  const lines = containmentLog(logCast(leak, currentAttack), approved, denied);
  playLog(lines, false);
  return new Promise((resolve) =>
    window.setTimeout(resolve, containmentDurationMs(lines)),
  );
}

export function startDemoWatch(): () => void {
  let stopped = false;
  let seenLeak: string | null = null;
  let seenAttack: string | null = null;
  let currentLeak: LeakTrigger | null = null;

  async function poll(): Promise<void> {
    const leak = await readTrigger<LeakTrigger>(LEAK_URL);
    if (stopped) return;

    if (leak?.id && leak.access_key_id && leak.repository && leak.id !== seenLeak) {
      seenLeak = leak.id;
      seenAttack = null;
      currentLeak = leak;
      clearTimers();
      emit({ leak, activity: [], error: null, incident: null });
      play(buildLeakFrames(leak), LEAK_RUN_MS);
      playLog(leakLog(logCast(leak, null)), true);
      return;
    }
    if (!currentLeak) return;

    const attack = await readTrigger<AttackTrigger>(ATTACK_URL);
    if (stopped || !attack?.id || !attack.started_at) return;
    // An attack file left over from the previous take must not replay the new one.
    if (attack.leak_id && attack.leak_id !== seenLeak) return;
    if (attack.id === seenAttack) return;

    seenAttack = attack.id;
    currentAttack = attack;
    clearTimers();
    emit({ error: null });
    play(buildAttackFrames(currentLeak, attack), ATTACK_RUN_MS);
    playLog(attackLog(logCast(currentLeak, attack)), false);
  }

  void poll();
  const watcher = window.setInterval(() => void poll(), WATCH_MS);
  return () => {
    stopped = true;
    clearTimers();
    window.clearInterval(watcher);
  };
}
