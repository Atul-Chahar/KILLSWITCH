import { describe, expect, it } from "vitest";

import { parseRepoInput, pickCandidates } from "./github";

describe("parseRepoInput", () => {
  it("accepts the shorthand, a URL, and a clone URL", () => {
    const expected = { owner: "octo", repo: "hello" };
    expect(parseRepoInput("octo/hello")).toEqual(expected);
    expect(parseRepoInput("https://github.com/octo/hello")).toEqual(expected);
    expect(parseRepoInput("github.com/octo/hello/")).toEqual(expected);
    expect(parseRepoInput("https://github.com/octo/hello.git")).toEqual(expected);
    expect(parseRepoInput("  octo/hello  ")).toEqual(expected);
  });

  it("keeps the two path segments and drops any deeper ones", () => {
    expect(parseRepoInput("https://github.com/octo/hello/tree/main/src")).toEqual({
      owner: "octo",
      repo: "hello",
    });
  });

  it("rejects anything that is not a repository", () => {
    expect(parseRepoInput("")).toBeNull();
    expect(parseRepoInput("octo")).toBeNull();
    expect(parseRepoInput("https://github.com/octo")).toBeNull();
    expect(parseRepoInput("octo/hello world")).toBeNull();
  });
});

describe("pickCandidates", () => {
  const blob = (path: string, size = 100) => ({ path, type: "blob", size });

  it("reads the likeliest hiding places first", () => {
    const picked = pickCandidates([
      blob("src/index.ts"),
      blob("terraform.tfvars"),
      blob(".env"),
      blob("config/settings.json"),
    ]);
    expect(picked[0]).toBe(".env");
    expect(picked.indexOf("terraform.tfvars")).toBeLessThan(picked.indexOf("src/index.ts"));
  });

  it("skips vendored trees, lock files and anything too large to be config", () => {
    const picked = pickCandidates([
      blob("node_modules/pkg/.env"),
      blob("package-lock.json"),
      blob("dist/bundle.js"),
      blob("huge.json", 999_999),
      blob("app.py"),
    ]);
    expect(picked).toEqual(["app.py"]);
  });

  it("reads files with no extension, where credentials are often parked", () => {
    const picked = pickCandidates([blob("keys"), blob("new_key"), blob("Makefile")]);
    expect(picked).toContain("keys");
    expect(picked).toContain("new_key");
    expect(picked).toContain("Makefile");
  });

  it("ranks a file named for credentials above ordinary source", () => {
    const picked = pickCandidates([blob("src/app.py"), blob("keys")]);
    expect(picked[0]).toBe("keys");
  });

  it("skips binaries, and honours the cap", () => {
    expect(pickCandidates([blob("logo.png"), blob("a.zip")])).toEqual([]);
    const many = Array.from({ length: 80 }, (_, i) => blob(`f${i}.py`));
    expect(pickCandidates(many, 40)).toHaveLength(40);
  });
});
