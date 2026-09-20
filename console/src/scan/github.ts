// Reading a public repository from the browser.
//
// Two calls go to the GitHub API, which allows sixty an hour from one address without a
// token — so the file contents come from raw.githubusercontent.com instead, which is a
// CDN and costs nothing against that budget. Both send CORS headers, so no server of
// ours sits in the middle and no token of yours is needed or asked for.
//
// Public repositories only. There is no sign-in here, deliberately: a scanner that asks
// for a GitHub token in order to read your private code is asking for the wrong thing.

const API = "https://api.github.com";
const RAW = "https://raw.githubusercontent.com";

// Enough to find a committed credentials file, few enough to finish while someone
// watches. A real deployment reads the push diff instead and has no such ceiling.
export const MAX_FILES = 40;
const MAX_BYTES = 256 * 1024;

export interface RepoRef {
  owner: string;
  repo: string;
}

export interface RepoInfo extends RepoRef {
  defaultBranch: string;
  pushedAt: string;
  htmlUrl: string;
}

export class ScanError extends Error {
  constructor(
    message: string,
    readonly kind: "not_found" | "rate_limited" | "network" | "empty" = "network",
  ) {
    super(message);
    this.name = "ScanError";
  }
}

// Accepts "owner/repo", a full github.com URL, or either with a trailing .git or slash.
export function parseRepoInput(input: string): RepoRef | null {
  const trimmed = input.trim().replace(/\.git$/, "").replace(/\/+$/, "");
  if (!trimmed) return null;
  const withoutHost = trimmed
    .replace(/^https?:\/\//, "")
    .replace(/^(www\.)?github\.com\//, "");
  const parts = withoutHost.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const [owner, repo] = parts;
  if (!owner || !repo) return null;
  if (!/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) return null;
  return { owner, repo };
}

async function api<T>(path: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API}${path}`, {
      headers: { Accept: "application/vnd.github+json" },
    });
  } catch (cause) {
    throw new ScanError(`could not reach GitHub: ${(cause as Error).message}`, "network");
  }
  if (response.status === 404) {
    throw new ScanError("no public repository with that name", "not_found");
  }
  if (response.status === 403 || response.status === 429) {
    // The unauthenticated budget is per address, so this is usually shared, not personal.
    throw new ScanError(
      "GitHub's hourly limit for anonymous requests is used up. It resets within the hour.",
      "rate_limited",
    );
  }
  if (!response.ok) {
    throw new ScanError(`GitHub returned ${response.status}`, "network");
  }
  return (await response.json()) as T;
}

export async function fetchRepo(ref: RepoRef): Promise<RepoInfo> {
  const data = await api<{
    default_branch: string;
    pushed_at: string;
    html_url: string;
    private: boolean;
  }>(`/repos/${ref.owner}/${ref.repo}`);
  return {
    ...ref,
    defaultBranch: data.default_branch,
    pushedAt: data.pushed_at,
    htmlUrl: data.html_url,
  };
}

interface TreeEntry {
  path: string;
  type: string;
  size?: number;
}

export async function fetchTree(info: RepoInfo): Promise<TreeEntry[]> {
  const data = await api<{ tree: TreeEntry[]; truncated: boolean }>(
    `/repos/${info.owner}/${info.repo}/git/trees/${encodeURIComponent(info.defaultBranch)}?recursive=1`,
  );
  return data.tree.filter((entry) => entry.type === "blob");
}

// Directories whose contents are fetched, generated or vendored. A key found in one is
// almost always a copy of a key that also sits somewhere worth reporting.
const SKIP_DIRS = /(^|\/)(node_modules|dist|build|vendor|\.git|coverage|__pycache__)(\/|$)/;

const SKIP_FILES = /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock)$/;

const TEXT_EXTENSIONS =
  /\.(env|ya?ml|json|tf|tfvars|properties|ini|cfg|conf|toml|sh|bash|zsh|py|js|jsx|ts|tsx|rb|go|java|php|cs|txt|md|xml|gradle|dockerfile)$/i;

// Names that carry credentials often enough to be worth reading whatever their extension.
const INTERESTING_NAMES =
  /(^|\/)(\.env[\w.-]*|credentials?|secrets?|keys?|tokens?|auth|config|settings|application|terraform\.tfvars|Dockerfile|docker-compose[\w.-]*)$/i;

// A file with no extension at all is nearly always text — a script, an rc file, or the
// credentials file somebody saved without thinking. Skipping them misses the obvious
// hiding places, so they are read and simply produce no matches if they turn out to be
// binary.
function hasNoExtension(path: string): boolean {
  const name = path.slice(path.lastIndexOf("/") + 1);
  return name.length > 0 && !name.slice(1).includes(".");
}

// The most likely hiding places first, so the cap spends its budget where it matters.
function weight(path: string): number {
  if (/(^|\/)\.env/i.test(path)) return 0;
  if (/(credential|secret|\bkeys?\b|\btokens?\b)/i.test(path)) return 1;
  if (/\.(tfvars|tf|properties|ini|cfg|conf)$/i.test(path)) return 2;
  if (/(^|\/)(config|settings|application)[\w.-]*\./i.test(path)) return 3;
  if (/\.(ya?ml|json|toml)$/i.test(path)) return 4;
  if (/\.(sh|bash|zsh|py|js|ts|rb|go|java)$/i.test(path)) return 5;
  return 6;
}

export function pickCandidates(tree: TreeEntry[], limit: number = MAX_FILES): string[] {
  return tree
    .filter((entry) => !SKIP_DIRS.test(entry.path))
    .filter((entry) => !SKIP_FILES.test(entry.path))
    .filter((entry) => (entry.size ?? 0) <= MAX_BYTES)
    .filter(
      (entry) =>
        TEXT_EXTENSIONS.test(entry.path) ||
        INTERESTING_NAMES.test(entry.path) ||
        hasNoExtension(entry.path),
    )
    .sort((a, b) => weight(a.path) - weight(b.path) || a.path.localeCompare(b.path))
    .slice(0, limit)
    .map((entry) => entry.path);
}

export async function fetchFile(info: RepoInfo, path: string): Promise<string | null> {
  const url = `${RAW}/${info.owner}/${info.repo}/${info.defaultBranch}/${path
    .split("/")
    .map(encodeURIComponent)
    .join("/")}`;
  try {
    const response = await fetch(url);
    // A file that cannot be read is skipped rather than failing the scan; the summary
    // reports how many were actually read so the number on screen stays honest.
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  }
}
