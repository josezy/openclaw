import { Type } from "@sinclair/typebox";
import type { OpenClawPluginApi, AnyAgentTool } from "openclaw/plugin-sdk/core";
import { GreyProxyClient } from "./greyproxy-client.js";

function resolveClient(): GreyProxyClient {
  return new GreyProxyClient();
}

function formatHost(entry: {
  destination_host: string;
  resolved_hostname?: string | null;
  destination_port?: number | null;
}): string {
  const host = entry.resolved_hostname || entry.destination_host;
  const port = entry.destination_port;
  return port ? `${host}:${port}` : host;
}

export function createGreywallStatusTool(_api: OpenClawPluginApi): AnyAgentTool {
  return {
    name: "greywall_status",
    description:
      "Show GreyProxy sandbox proxy health, pending request count, and recent traffic stats.",
    schema: Type.Object({}),
    async run() {
      const client = resolveClient();
      try {
        const [health, stats] = await Promise.all([client.health(), client.dashboard()]);
        const pending = await client.pendingCount();
        const lines: string[] = [
          `GreyProxy ${health.version} — ${health.status}`,
          `Pending requests: ${pending}`,
          `Today: ${stats.total_requests} total, ${stats.allowed} allowed, ${stats.blocked} blocked`,
        ];
        if (stats.top_blocked.length > 0) {
          lines.push("", "Top blocked destinations:");
          for (const b of stats.top_blocked.slice(0, 5)) {
            const host = b.resolved_hostname || b.host;
            lines.push(`  ${host}:${b.port} — ${b.count} attempts`);
          }
        }
        return { output: lines.join("\n") };
      } catch (err) {
        return {
          output: `GreyProxy unavailable: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  } as AnyAgentTool;
}

export function createGreywallPendingTool(_api: OpenClawPluginApi): AnyAgentTool {
  return {
    name: "greywall_pending",
    description:
      "List network requests currently pending a policy decision in the GreyProxy sandbox proxy.",
    schema: Type.Object({
      limit: Type.Optional(
        Type.Number({ description: "Max items to return (default 20).", minimum: 1, maximum: 100 }),
      ),
    }),
    async run(_args: { limit?: number }) {
      const client = resolveClient();
      try {
        const { items, total } = await client.pendingList(_args.limit ?? 20);
        if (items.length === 0) {
          return { output: "No pending network requests." };
        }
        const lines = [`${total} pending request(s):`, ""];
        for (const p of items) {
          const host = formatHost(p);
          const ago = timeSince(p.first_seen);
          const from = p.container_name ? ` (from: ${p.container_name})` : "";
          lines.push(
            `  [id:${p.id}] ${host} — ${p.attempt_count} attempt(s), first seen ${ago}${from}`,
          );
        }
        return { output: lines.join("\n") };
      } catch (err) {
        return {
          output: `GreyProxy unavailable: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  } as AnyAgentTool;
}

export function createGreywallLogsTool(_api: OpenClawPluginApi): AnyAgentTool {
  return {
    name: "greywall_logs",
    description: "Query recent network request logs from the GreyProxy sandbox proxy.",
    schema: Type.Object({
      destination: Type.Optional(Type.String({ description: "Filter by destination host." })),
      result: Type.Optional(
        Type.String({ description: 'Filter by result: "allowed" or "blocked".' }),
      ),
      limit: Type.Optional(
        Type.Number({ description: "Max items (default 20).", minimum: 1, maximum: 100 }),
      ),
    }),
    async run(args: { destination?: string; result?: string; limit?: number }) {
      const client = resolveClient();
      try {
        const { items, total } = await client.logs({
          destination: args.destination,
          result: args.result,
          limit: args.limit ?? 20,
        });
        if (items.length === 0) {
          return { output: "No matching log entries." };
        }
        const lines = [`${total} log entries (showing ${items.length}):`, ""];
        for (const l of items) {
          const host = formatHost(l);
          const icon = l.result === "allowed" ? "✅" : "🚫";
          const method = l.method ? ` ${l.method}` : "";
          lines.push(`  ${icon}${method} ${host} — ${l.result}`);
        }
        return { output: lines.join("\n") };
      } catch (err) {
        return {
          output: `GreyProxy unavailable: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    },
  } as AnyAgentTool;
}

function timeSince(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  return `${Math.round(diff / 3_600_000)}h ago`;
}
