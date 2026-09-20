// Credential patterns, mirroring the ones the backend already trusts.
//
// The access key rule is a direct port of detect/patterns.py, including its refusal to
// raise an incident for AWS's own documentation key — a false positive in front of a
// judge is worse than a missed one in a scanner that is only the first of several gates.
//
// The rest mirror scripts/check_secrets.sh, which is the check this repository runs on
// itself before every commit.

export type FindingKind =
  | "aws_access_key"
  | "aws_secret_key"
  | "github_token"
  | "private_key";

export interface Finding {
  kind: FindingKind;
  path: string;
  line: number;
  // The matched text, already redacted. The raw secret is never kept.
  evidence: string;
}

export const FINDING_LABEL: Record<FindingKind, string> = {
  aws_access_key: "AWS access key id",
  aws_secret_key: "AWS secret access key",
  github_token: "GitHub token",
  private_key: "Private key",
};

const ACCESS_KEY = /\bAKIA[0-9A-Z]{16}\b/g;
const SESSION_KEY = /\bASIA[0-9A-Z]{16}\b/g;
const SECRET_KEY = /aws_secret_access_key["']?\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})\b/gi;
const GITHUB_TOKEN = /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g;
const PRIVATE_KEY = /-----BEGIN [A-Z ]*PRIVATE KEY-----/g;

// AWS uses this in its own documentation. It is not a credential.
const EXAMPLE_SUFFIX = "EXAMPLE";

export function isExampleKey(accessKeyId: string): boolean {
  return accessKeyId.endsWith(EXAMPLE_SUFFIX);
}

// Nothing here ever returns a whole secret. A scanner that prints the key it found has
// leaked it a second time, into a browser tab that may well be on a projector.
function redact(value: string): string {
  if (value.length <= 8) return "•".repeat(value.length);
  return `${value.slice(0, 4)}${"•".repeat(8)}${value.slice(-4)}`;
}

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

interface Rule {
  kind: FindingKind;
  pattern: RegExp;
  // Which capture group holds the secret. 0 is the whole match.
  group: number;
  skip?: (value: string) => boolean;
}

const RULES: Rule[] = [
  { kind: "aws_access_key", pattern: ACCESS_KEY, group: 0, skip: isExampleKey },
  { kind: "aws_access_key", pattern: SESSION_KEY, group: 0 },
  { kind: "aws_secret_key", pattern: SECRET_KEY, group: 1 },
  { kind: "github_token", pattern: GITHUB_TOKEN, group: 0 },
  { kind: "private_key", pattern: PRIVATE_KEY, group: 0 },
];

export function scanText(path: string, text: string): Finding[] {
  const found: Finding[] = [];
  const seen = new Set<string>();

  for (const rule of RULES) {
    // The rule patterns are module-level and global, so each scan restarts the cursor.
    rule.pattern.lastIndex = 0;
    let match = rule.pattern.exec(text);
    while (match !== null) {
      const value = match[rule.group] ?? match[0];
      if (!rule.skip?.(value)) {
        const line = lineOf(text, match.index);
        const key = `${rule.kind}:${line}:${value}`;
        if (!seen.has(key)) {
          seen.add(key);
          found.push({
            kind: rule.kind,
            path,
            line,
            evidence: rule.kind === "private_key" ? match[0] : redact(value),
          });
        }
      }
      match = rule.pattern.exec(text);
    }
  }
  return found.sort((a, b) => a.line - b.line);
}
