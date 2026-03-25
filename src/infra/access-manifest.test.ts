import { describe, expect, it } from "vitest";
import {
  parseAccessManifest,
  aggregateAccessPolicy,
  type AccessManifestSource,
} from "./access-manifest.js";

describe("parseAccessManifest", () => {
  it("returns undefined for null/undefined input", () => {
    expect(parseAccessManifest(null)).toBeUndefined();
    expect(parseAccessManifest(undefined)).toBeUndefined();
  });

  it("returns undefined for non-object input", () => {
    expect(parseAccessManifest("string")).toBeUndefined();
    expect(parseAccessManifest(42)).toBeUndefined();
  });

  it("returns empty manifest for empty object (explicit opt-out)", () => {
    expect(parseAccessManifest({})).toEqual({});
  });

  it("returns empty manifest for object with empty arrays (explicit opt-out)", () => {
    expect(parseAccessManifest({ domains: [], read: [], write: [] })).toEqual({});
  });

  it("parses domains only", () => {
    const result = parseAccessManifest({ domains: ["api.example.com"] });
    expect(result).toEqual({ domains: ["api.example.com"] });
  });

  it("parses all fields", () => {
    const result = parseAccessManifest({
      domains: ["api.example.com", "*.cdn.com"],
      read: ["~/.config/example"],
      write: ["~/.cache/example"],
    });
    expect(result).toEqual({
      domains: ["api.example.com", "*.cdn.com"],
      read: ["~/.config/example"],
      write: ["~/.cache/example"],
    });
  });

  it("filters out non-string values from arrays", () => {
    const result = parseAccessManifest({
      domains: ["valid.com", 42, null, "also-valid.com"],
    });
    expect(result).toEqual({ domains: ["valid.com", "also-valid.com"] });
  });

  it("filters out empty/whitespace strings", () => {
    const result = parseAccessManifest({
      domains: ["valid.com", "", "  ", "also-valid.com"],
    });
    expect(result).toEqual({ domains: ["valid.com", "also-valid.com"] });
  });
});

describe("aggregateAccessPolicy", () => {
  it("returns base paths for empty sources", () => {
    const result = aggregateAccessPolicy([]);
    expect(result.domains).toContain("api.anthropic.com");
    expect(result.domains).toContain("registry.npmjs.org");
    expect(result.domains).toContain("localhost");
    expect(result.read).toContain(".");
    expect(result.read).toContain("~/.openclaw");
    expect(result.write).toContain(".");
    expect(result.write).toContain("~/.openclaw");
    expect(result.write).toContain("/tmp/openclaw");
    expect(result.denyRead.length).toBeGreaterThan(0);
    expect(result.denyWrite.length).toBeGreaterThan(0);
    expect(result.undeclared).toEqual([]);
  });

  it("aggregates domains from multiple sources", () => {
    const sources: AccessManifestSource[] = [
      { id: "notion", kind: "skill", access: { domains: ["api.notion.com"] } },
      { id: "github", kind: "skill", access: { domains: ["github.com", "api.github.com"] } },
    ];
    const result = aggregateAccessPolicy(sources);
    expect(result.domains).toContain("api.notion.com");
    expect(result.domains).toContain("github.com");
    expect(result.domains).toContain("api.github.com");
    // Also includes base domains
    expect(result.domains).toContain("api.anthropic.com");
  });

  it("deduplicates domains", () => {
    const sources: AccessManifestSource[] = [
      { id: "a", kind: "skill", access: { domains: ["api.example.com"] } },
      { id: "b", kind: "plugin", access: { domains: ["api.example.com"] } },
    ];
    const result = aggregateAccessPolicy(sources);
    // api.example.com appears only once despite two sources
    expect(result.domains.filter((d) => d === "api.example.com")).toHaveLength(1);
  });

  it("includes channel domains when channels option provided", () => {
    const result = aggregateAccessPolicy([], { channels: ["discord"] });
    expect(result.domains).toContain("discord.com");
    expect(result.domains).toContain("gateway.discord.gg");
    expect(result.domains).toContain("cdn.discordapp.com");
  });

  it("includes provider domains when providers option provided", () => {
    const result = aggregateAccessPolicy([], { providers: ["openai"] });
    expect(result.domains).toContain("api.openai.com");
  });

  it("tracks undeclared sources (access: undefined)", () => {
    const sources: AccessManifestSource[] = [
      { id: "notion", kind: "skill", access: { domains: ["api.notion.com"] } },
      { id: "tmux", kind: "skill", access: undefined },
      { id: "coding-agent", kind: "skill", access: undefined },
    ];
    const result = aggregateAccessPolicy(sources);
    expect(result.undeclared).toEqual([
      { id: "tmux", kind: "skill" },
      { id: "coding-agent", kind: "skill" },
    ]);
  });

  it("does not flag explicit opt-out (access: {}) as undeclared", () => {
    const sources: AccessManifestSource[] = [
      { id: "notion", kind: "skill", access: { domains: ["api.notion.com"] } },
      { id: "discord", kind: "skill", access: {} },
    ];
    const result = aggregateAccessPolicy(sources);
    expect(result.undeclared).toEqual([]);
  });

  it("merges read and write paths", () => {
    const sources: AccessManifestSource[] = [
      {
        id: "notion",
        kind: "skill",
        access: { read: ["~/.config/notion"], write: ["~/.cache/notion"] },
      },
      { id: "github", kind: "skill", access: { read: ["~/.config/gh"], write: ["~/.config/gh"] } },
    ];
    const result = aggregateAccessPolicy(sources);
    expect(result.read).toContain("~/.config/notion");
    expect(result.read).toContain("~/.config/gh");
    expect(result.write).toContain("~/.cache/notion");
    expect(result.write).toContain("~/.config/gh");
  });

  it("preserves hardcoded deny lists", () => {
    const result = aggregateAccessPolicy([]);
    expect(result.denyRead).toContain("~/.ssh/id_*");
    expect(result.denyRead).toContain("~/.gnupg/**");
    expect(result.denyRead).toContain(".env");
    expect(result.denyWrite).toContain("~/.bashrc");
    expect(result.denyWrite).toContain("~/.ssh");
  });
});
