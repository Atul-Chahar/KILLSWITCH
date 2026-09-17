import { describe, expect, it } from "vitest";

import { elapsedSeconds, estimateAvoidedCost, formatDuration, formatUsd } from "./cost";
import type { CreatedResource } from "./types";

function instance(id: string): CreatedResource {
  return {
    resource_id: id,
    kind: "ec2_instance",
    event_name: "RunInstances",
    region: "ap-south-1",
    event_time: "2026-09-18T10:12:41+00:00",
    source_ip: "203.0.113.10",
    event_id: `event-${id}`,
  };
}

describe("estimateAvoidedCost", () => {
  it("is zero when the key created nothing", () => {
    expect(estimateAvoidedCost([]).totalUsd).toBe(0);
  });

  it("scales with the number of instances", () => {
    const one = estimateAvoidedCost([instance("i-1")]).totalUsd;
    const two = estimateAvoidedCost([instance("i-1"), instance("i-2")]).totalUsd;

    // Cent rounding means doubling is not exact, so this is checked to the cent.
    expect(two).toBeCloseTo(one * 2, 1);
  });

  it("reports the assumptions it used, so the number can be argued with", () => {
    const estimate = estimateAvoidedCost([instance("i-1")], 100, 0.01);

    expect(estimate).toEqual({
      instanceCount: 1,
      hours: 100,
      hourlyRate: 0.01,
      totalUsd: 1,
    });
  });
});

describe("formatting", () => {
  it("formats dollars", () => {
    expect(formatUsd(8.06)).toBe("$8.06");
  });

  it("counts the seconds between detection and containment", () => {
    expect(elapsedSeconds("2026-09-18T10:12:41+00:00", "2026-09-18T10:14:11+00:00")).toBe(90);
  });

  it("never reports a negative duration when clocks disagree", () => {
    expect(elapsedSeconds("2026-09-18T10:14:11+00:00", "2026-09-18T10:12:41+00:00")).toBe(0);
  });

  it("reads as minutes and seconds", () => {
    expect(formatDuration(45)).toBe("45s");
    expect(formatDuration(90)).toBe("1m 30s");
    expect(formatDuration(120)).toBe("2m");
  });
});
