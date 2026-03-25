import type { OpenClawPluginApi, OpenClawPluginCommandDefinition } from "openclaw/plugin-sdk/core";
import { GreyProxyClient } from "./greyproxy-client.js";
import {
  readNotifyState,
  writeNotifyState,
  resolveSubscriberFromCommandContext,
  upsertSubscriber,
  removeSubscriber,
  findSubscriber,
  subscriberKey,
  resolveNotifyStatePath,
} from "./greywall-subscribers.js";

// ── Subcommand handlers ────────────────────────────────────────────

async function handleNotifyOn(
  api: OpenClawPluginApi,
  ctx: Parameters<OpenClawPluginCommandDefinition["handler"]>[0],
): Promise<{ text: string }> {
  const sub = resolveSubscriberFromCommandContext(ctx);
  if (!sub) {
    return { text: "Could not resolve your chat identity. Try again from a supported channel." };
  }

  const stateDir = api.runtime?.state?.resolveStateDir?.();
  if (!stateDir) {
    return { text: "State directory unavailable." };
  }

  const statePath = resolveNotifyStatePath(stateDir);
  const state = await readNotifyState(statePath);
  const isNew = upsertSubscriber(state, sub);
  await writeNotifyState(statePath, state);

  return {
    text: isNew
      ? `Greywall notifications enabled for this chat (${sub.channel}).`
      : `Greywall notifications already active for this chat.`,
  };
}

async function handleNotifyOff(
  api: OpenClawPluginApi,
  ctx: Parameters<OpenClawPluginCommandDefinition["handler"]>[0],
): Promise<{ text: string }> {
  const sub = resolveSubscriberFromCommandContext(ctx);
  if (!sub) {
    return { text: "Could not resolve your chat identity." };
  }

  const stateDir = api.runtime?.state?.resolveStateDir?.();
  if (!stateDir) {
    return { text: "State directory unavailable." };
  }

  const statePath = resolveNotifyStatePath(stateDir);
  const state = await readNotifyState(statePath);
  const removed = removeSubscriber(state, sub.id);
  if (removed) {
    await writeNotifyState(statePath, state);
  }

  return {
    text: removed
      ? "Greywall notifications disabled for this chat."
      : "Greywall notifications were not active for this chat.",
  };
}

async function handleNotifyStatus(
  api: OpenClawPluginApi,
  ctx: Parameters<OpenClawPluginCommandDefinition["handler"]>[0],
): Promise<{ text: string }> {
  const stateDir = api.runtime?.state?.resolveStateDir?.();
  if (!stateDir) {
    return { text: "State directory unavailable." };
  }

  const statePath = resolveNotifyStatePath(stateDir);
  const state = await readNotifyState(statePath);

  const sub = resolveSubscriberFromCommandContext(ctx);
  const key = sub ? sub.id : null;
  const isSubscribed = key ? !!findSubscriber(state, key) : false;

  const lines: string[] = [
    `Notifications: ${isSubscribed ? "enabled" : "disabled"} for this chat`,
    `Total subscribers: ${state.subscribers.length}`,
  ];

  // Try to get pending count from GreyProxy
  try {
    const client = new GreyProxyClient();
    const pending = await client.pendingCount();
    lines.push(`Pending requests: ${pending}`);
  } catch {
    lines.push("GreyProxy: unavailable");
  }

  return { text: lines.join("\n") };
}

async function handleNotifyList(): Promise<{ text: string }> {
  try {
    const client = new GreyProxyClient();
    const { items, total } = await client.pendingList(20);
    if (items.length === 0) {
      return { text: "No pending requests." };
    }
    const lines = [`Pending requests (${total}):\n`];
    for (const p of items) {
      const port = p.destination_port ? `:${p.destination_port}` : "";
      const host = p.resolved_hostname ?? p.destination_host;
      const ago = formatAge(p.first_seen);
      const from = p.container_name ? `  from: ${p.container_name}` : "";
      lines.push(`#${p.id}  ${host}${port}  (${p.attempt_count}x, ${ago})${from}`);
    }
    if (total > items.length) {
      lines.push(`\n... and ${total - items.length} more`);
    }
    return { text: lines.join("\n") };
  } catch {
    return { text: "GreyProxy: unavailable" };
  }
}

function formatAge(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 60_000) return `${Math.round(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m ago`;
  return `${Math.round(ms / 3_600_000)}h ago`;
}

// ── Command handler for /greywall allow|always|deny <id> ──────────

async function handleDecideCommand(action: string, idStr: string): Promise<{ text: string }> {
  const pendingId = parseInt(idStr, 10);
  if (isNaN(pendingId)) {
    return { text: `Invalid pending request ID: ${idStr}` };
  }

  const client = new GreyProxyClient();

  try {
    if (action === "allow") {
      const result = await client.pendingAllow(pendingId, {
        scope: "exact",
        duration: "session",
      });
      return {
        text: `Allowed ${result.rule.destination_pattern} (rule #${result.rule.id}, session)`,
      };
    } else if (action === "always") {
      const result = await client.pendingAllow(pendingId, {
        scope: "exact",
        duration: "permanent",
      });
      return {
        text: `Allowed ${result.rule.destination_pattern} (rule #${result.rule.id}, permanent)`,
      };
    } else if (action === "deny") {
      const result = await client.pendingDeny(pendingId, {
        scope: "exact",
        duration: "permanent",
      });
      return { text: `Denied ${result.rule.destination_pattern} (rule #${result.rule.id})` };
    }
    return { text: `Unknown action: ${action}` };
  } catch (err) {
    return { text: `Failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}

// ── Main command definition ────────────────────────────────────────

export function createGreywallCommand(api: OpenClawPluginApi): OpenClawPluginCommandDefinition {
  return {
    name: "greywall",
    description: "Manage Greywall network monitoring notifications.",
    acceptsArgs: true,
    handler: async (ctx) => {
      const tokens = (ctx.args?.trim() ?? "").split(/\s+/).filter(Boolean);
      const action = tokens[0]?.toLowerCase() ?? "";
      const subAction = tokens[1]?.toLowerCase() ?? "";

      if (action === "notify") {
        if (subAction === "on") return handleNotifyOn(api, ctx);
        if (subAction === "off") return handleNotifyOff(api, ctx);
        if (subAction === "list") return handleNotifyList();
        return handleNotifyStatus(api, ctx);
      }

      // Direct decision commands: /greywall allow|always|deny <id>
      if (action === "allow" || action === "always" || action === "deny") {
        if (!subAction) {
          return { text: `Usage: /greywall ${action} <pending-request-id>` };
        }
        return handleDecideCommand(action, subAction);
      }

      return {
        text: [
          "Greywall commands:",
          "  /greywall notify on    - Enable notifications for this chat",
          "  /greywall notify off   - Disable notifications",
          "  /greywall notify       - Show notification status",
          "  /greywall notify list  - List pending requests",
          "  /greywall allow <id>   - Allow a pending request (session)",
          "  /greywall always <id>  - Allow a pending request (permanent)",
          "  /greywall deny <id>    - Deny a pending request",
        ].join("\n"),
      };
    },
  };
}
