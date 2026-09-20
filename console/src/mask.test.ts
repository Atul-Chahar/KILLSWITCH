import { describe, expect, it } from "vitest";
import {
  maskAccessKey,
  maskAccountId,
  maskActionSignature,
  maskCredential,
  maskIncidentId,
} from "./mask";

describe("maskAccessKey", () => {
  it("masks the middle segment of the standard AWS example access key", () => {
    const rawKey = "AKIAIOSFODNN7EXAMPLE";
    expect(maskAccessKey(rawKey)).toBe("AKIA••••••••EXAMPLE");
  });

  it("masks standard 20-character AWS access keys preserving 4-char suffix", () => {
    const rawKey = "AKIA" + "1234567890ABCDEF";
    expect(maskAccessKey(rawKey)).toBe("AKIA••••••••CDEF");
  });

  it("supports custom mask strings such as asterisks", () => {
    const rawKey = "AKIAIOSFODNN7EXAMPLE";
    expect(maskAccessKey(rawKey, "********")).toBe("AKIA********EXAMPLE");
  });

  it("returns short inputs without modification", () => {
    expect(maskAccessKey("AKIA123")).toBe("AKIA123");
  });
});

describe("maskIncidentId", () => {
  it("masks embedded access key in incident IDs", () => {
    const rawIncidentId = "inc-AKIAIOSFODNN7EXAMPLE";
    expect(maskIncidentId(rawIncidentId)).toBe("inc-AKIA••••••••EXAMPLE");
  });

  it("leaves incident IDs without inc- prefix untouched", () => {
    expect(maskIncidentId("custom-incident-123")).toBe("custom-incident-123");
  });
});

describe("maskAccountId", () => {
  it("redacts AWS account IDs keeping only the last four digits", () => {
    expect(maskAccountId("123456789012")).toBe("****9012");
    expect(maskAccountId("000000000000")).toBe("****0000");
  });

  it("handles account IDs shorter than four digits", () => {
    expect(maskAccountId("12")).toBe("****");
  });
});

describe("maskCredential", () => {
  it("automatically masks access keys", () => {
    expect(maskCredential("AKIAIOSFODNN7EXAMPLE")).toBe("AKIA••••••••EXAMPLE");
  });

  it("automatically masks incident IDs containing access keys", () => {
    expect(maskCredential("inc-AKIAIOSFODNN7EXAMPLE")).toBe("inc-AKIA••••••••EXAMPLE");
  });

  it("automatically masks 12-digit AWS account IDs", () => {
    expect(maskCredential("123456789012")).toBe("****9012");
  });

  it("preserves non-sensitive target identifiers such as EC2 instance IDs", () => {
    const instanceId = "i-0a1b2c3d4e5f60001";
    expect(maskCredential(instanceId)).toBe(instanceId);
  });

  it("preserves repository names and usernames", () => {
    expect(maskCredential("octo/private-demo-repo")).toBe("octo/private-demo-repo");
    expect(maskCredential("demo-leaky-user")).toBe("demo-leaky-user");
  });
});

describe("maskActionSignature", () => {
  it("masks access key inside action signatures", () => {
    const signature = "deactivate_key:AKIAIOSFODNN7EXAMPLE:-";
    expect(maskActionSignature(signature)).toBe("deactivate_key:AKIA••••••••EXAMPLE:-");
  });

  it("preserves non-credential targets in action signatures", () => {
    const signature = "terminate_instance:i-0a1b2c3d4e5f60001:ap-south-1";
    expect(maskActionSignature(signature)).toBe("terminate_instance:i-0a1b2c3d4e5f60001:ap-south-1");
  });
});
