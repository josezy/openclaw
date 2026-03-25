/**
 * Access manifest types for declaring what network domains and filesystem
 * paths a skill or plugin needs. Used by the greywall policy generator
 * to produce least-privilege sandbox configurations.
 */

/** Declarative access requirements for a skill or plugin. */
export type AccessManifest = {
  /** Network domains required (supports globs like "*.googleapis.com"). */
  domains?: string[];
  /** Filesystem paths that need read access (supports ~ shorthand). */
  read?: string[];
  /** Filesystem paths that need write access (supports ~ shorthand). */
  write?: string[];
};

/** Provenance-tracked access entry from a single skill/plugin. */
export type AccessManifestSource = {
  id: string;
  kind: "skill" | "plugin" | "provider" | "channel" | "base";
  /**
   * Access requirements. `undefined` means the source never declared an access
   * manifest (undeclared). An empty `{}` means the source explicitly opted out
   * — it intentionally needs no network or filesystem access.
   */
  access: AccessManifest | undefined;
};

/** Aggregated access policy ready for Greywall config generation. */
export type ResolvedAccessPolicy = {
  domains: string[];
  read: string[];
  write: string[];
  denyRead: string[];
  denyWrite: string[];
  sources: AccessManifestSource[];
  undeclared: Array<{ id: string; kind: string }>;
};

// ── Hardcoded base domains ──────────────────────────────────────────

/**
 * Domains the gateway always needs regardless of configuration.
 * GreyProxy uses these as allow rules so the sandbox doesn't block core traffic.
 */
const BASE_DOMAINS: readonly string[] = [
  // Anthropic (default provider)
  "api.anthropic.com",
  // npm registry (version checks)
  "registry.npmjs.org",
  // Loopback (GreyProxy API, gateway RPC, browser control).
  // All variants needed: gateway self-connections use 127.0.0.1 (call.ts),
  // dual-stack listeners may bind [::1], and some tools resolve "localhost".
  "localhost",
  "127.0.0.1",
  "[::1]",
];

/**
 * Domains required per channel. Looked up by channel identifier.
 * Only included when the channel is detected in the active config.
 */
export const CHANNEL_DOMAINS: Record<string, readonly string[]> = {
  discord: ["discord.com", "gateway.discord.gg", "cdn.discordapp.com", "media.discordapp.net"],
  telegram: ["api.telegram.org", "*.telegram.org"],
  slack: ["slack.com", "*.slack.com", "files.slack.com"],
  signal: ["textsecure-service.whispersystems.org", "cdn.signal.org", "cdn2.signal.org"],
  whatsapp: ["web.whatsapp.com", "*.whatsapp.net"],
};

/**
 * Domains required per LLM provider. Looked up by provider identifier.
 * Only included when the provider is detected in the active config.
 */
export const PROVIDER_DOMAINS: Record<string, readonly string[]> = {
  openai: ["api.openai.com"],
  anthropic: ["api.anthropic.com"],
  google: ["generativelanguage.googleapis.com", "oauth2.googleapis.com"],
  mistral: ["api.mistral.ai"],
  xai: ["api.x.ai"],
  copilot: ["api.individual.githubcopilot.com", "api.github.com"],
  ollama: ["localhost"],
};

// ── Hardcoded base paths ─────────────────────────────────────────────

const BASE_DENY_READ: readonly string[] = ["~/.ssh/id_*", "~/.gnupg/**", ".env", ".env.*"];

const BASE_DENY_WRITE: readonly string[] = [
  "~/.bashrc",
  "~/.bash_profile",
  "~/.zshrc",
  "~/.zprofile",
  "~/.profile",
  "~/.ssh",
  "~/.gnupg",
];

const BASE_READ: readonly string[] = [".", "~/.openclaw"];

const BASE_WRITE: readonly string[] = [".", "~/.openclaw", "/tmp/openclaw"];

// ── Helpers ──────────────────────────────────────────────────────────

function dedup(arr: string[]): string[] {
  return [...new Set(arr)].sort();
}

/**
 * Parse an AccessManifest from an untyped object (frontmatter or JSON).
 * Returns `undefined` when the input is not an object (field absent).
 * Returns `{}` when the input is a valid object with no entries (explicit opt-out).
 */
export function parseAccessManifest(raw: unknown): AccessManifest | undefined {
  if (raw === undefined || raw === null) {
    return undefined;
  }
  if (typeof raw !== "object") {
    return undefined;
  }
  const obj = raw as Record<string, unknown>;
  const domains = parseStringArray(obj.domains);
  const read = parseStringArray(obj.read);
  const write = parseStringArray(obj.write);
  if (!domains.length && !read.length && !write.length) {
    // Explicitly declared but empty — intentional opt-out.
    return {};
  }
  return {
    ...(domains.length ? { domains } : {}),
    ...(read.length ? { read } : {}),
    ...(write.length ? { write } : {}),
  };
}

function parseStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((v): v is string => typeof v === "string" && v.trim().length > 0);
}

/** Aggregate multiple access sources into a single resolved policy. */
export function aggregateAccessPolicy(
  sources: AccessManifestSource[],
  opts?: { channels?: string[]; providers?: string[] },
): ResolvedAccessPolicy {
  const allDomains: string[] = [...BASE_DOMAINS];

  // Add channel-specific domains for configured channels
  if (opts?.channels) {
    for (const ch of opts.channels) {
      const domains = CHANNEL_DOMAINS[ch];
      if (domains) allDomains.push(...domains);
    }
  }

  // Add provider-specific domains for configured providers
  if (opts?.providers) {
    for (const p of opts.providers) {
      const domains = PROVIDER_DOMAINS[p];
      if (domains) allDomains.push(...domains);
    }
  }

  const allRead: string[] = [...BASE_READ];
  const allWrite: string[] = [...BASE_WRITE];
  const undeclared: Array<{ id: string; kind: string }> = [];

  for (const source of sources) {
    const a = source.access;
    if (a === undefined) {
      // No access field at all — truly undeclared.
      undeclared.push({ id: source.id, kind: source.kind });
      continue;
    }
    // access: {} means explicit opt-out (no network/fs needed) — not undeclared.
    if (a.domains) {
      allDomains.push(...a.domains);
    }
    if (a.read) {
      allRead.push(...a.read);
    }
    if (a.write) {
      allWrite.push(...a.write);
    }
  }

  return {
    domains: dedup(allDomains),
    read: dedup(allRead),
    write: dedup(allWrite),
    denyRead: [...BASE_DENY_READ],
    denyWrite: [...BASE_DENY_WRITE],
    sources,
    undeclared,
  };
}
