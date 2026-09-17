// The money-saved estimate.
//
// It is an estimate, and the console says so on screen. The honest version of this number
// states its assumptions rather than implying a measurement.

import type { CreatedResource } from "./types";

// On-demand t3.micro, ap-south-1, Linux, at the time of writing. Not a live price feed.
export const HOURLY_USD_PER_INSTANCE = 0.0112;
export const ASSUMED_HOURS = 24 * 30;

export interface CostEstimate {
  instanceCount: number;
  hours: number;
  hourlyRate: number;
  totalUsd: number;
}

export function estimateAvoidedCost(
  resources: CreatedResource[],
  hours: number = ASSUMED_HOURS,
  hourlyRate: number = HOURLY_USD_PER_INSTANCE,
): CostEstimate {
  const instanceCount = resources.filter((item) => item.kind === "ec2_instance").length;
  return {
    instanceCount,
    hours,
    hourlyRate,
    totalUsd: Number((instanceCount * hours * hourlyRate).toFixed(2)),
  };
}

export function formatUsd(amount: number): string {
  return amount.toLocaleString("en-US", { style: "currency", currency: "USD" });
}

export function elapsedSeconds(from: string, to: string): number {
  return Math.max(0, Math.round((Date.parse(to) - Date.parse(from)) / 1000));
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const remainder = seconds % 60;
  return remainder === 0 ? `${minutes}m` : `${minutes}m ${remainder}s`;
}
