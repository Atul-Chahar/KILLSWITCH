import { describe, expect, it } from "vitest";

import { isExampleKey, scanText } from "./patterns";

const REAL_KEY = "AKIA" + "QWERTYUIOPASDFGH";
const EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE";

describe("scanText", () => {
  it("finds an access key and reports the line it sits on", () => {
    const text = `# config\nAWS_ACCESS_KEY_ID=${REAL_KEY}\n`;
    const [finding] = scanText("config/aws.env", text);
    expect(finding?.kind).toBe("aws_access_key");
    expect(finding?.line).toBe(2);
    expect(finding?.path).toBe("config/aws.env");
  });

  it("never returns the secret it matched", () => {
    const [finding] = scanText("a.env", `KEY=${REAL_KEY}`);
    expect(finding?.evidence).not.toContain(REAL_KEY);
    expect(finding?.evidence).toContain("•");
  });

  it("ignores AWS's own documentation key, as detect/patterns.py does", () => {
    expect(scanText("README.md", `KEY=${EXAMPLE_KEY}`)).toEqual([]);
    expect(isExampleKey(EXAMPLE_KEY)).toBe(true);
    expect(isExampleKey(REAL_KEY)).toBe(false);
  });

  it("finds a secret access key only when it is assigned a value", () => {
    expect(scanText("a.py", "aws_secret_access_key = os.environ['X']")).toEqual([]);
    const assigned = scanText("a.env", `aws_secret_access_key=${"a".repeat(40)}`);
    expect(assigned[0]?.kind).toBe("aws_secret_key");
  });

  it("finds github tokens and private key headers", () => {
    expect(scanText("a.sh", `token=ghp_${"a".repeat(36)}`)[0]?.kind).toBe("github_token");
    expect(scanText("id.pem", "-----BEGIN " + "RSA PRIVATE KEY-----")[0]?.kind).toBe("private_key");
  });

  it("reports one finding per distinct match, not one per regex pass", () => {
    const text = `${REAL_KEY}\n${REAL_KEY}\n`;
    expect(scanText("a.env", text)).toHaveLength(2);
    expect(scanText("a.env", text).map((f) => f.line)).toEqual([1, 2]);
  });

  it("returns nothing for a clean file", () => {
    expect(scanText("index.ts", "export const x = 1;\n")).toEqual([]);
  });
});
