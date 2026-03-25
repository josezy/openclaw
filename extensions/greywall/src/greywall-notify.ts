import path from "node:path";
import type { OpenClawPluginApi, OpenClawPluginService } from "openclaw/plugin-sdk/core";
import type { PluginInteractiveButtons } from "../../../src/plugins/types.js";
import { GreyProxyClient, type GreyProxyPendingRequest } from "./greyproxy-client.js";
import {
  readNotifyState,
  writeNotifyState,
  sendToSubscriber,
  sendToAllSubscribers,
  type GreywallNotifyState,
} from "./greywall-subscribers.js";

// ── Constants ──────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 5_000;
const STALE_NOTIFICATION_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// ── Notification formatting ────────────────────────────────────────

function formatHost(item: GreyProxyPendingRequest): string {
  const host = item.resolved_hostname || item.destination_host;
  return item.destination_port ? `${host}:${item.destination_port}` : host;
}

function timeSince(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return `${Math.round(diff / 1000)}s ago`;
  if (diff < 3_600_000) return `${Math.round(diff / 60_000)}m ago`;
  return `${Math.round(diff / 3_600_000)}h ago`;
}

function formatPendingNotification(item: GreyProxyPendingRequest): string {
  const host = formatHost(item);
  const lines = [
    `Network request needs approval`,
    "",
    `Host: ${host}`,
    ...(item.container_name ? [`Container: ${item.container_name}`] : []),
    `Attempts: ${item.attempt_count}`,
    `First seen: ${timeSince(item.first_seen)}`,
  ];
  return lines.join("\n");
}

function formatTextFallbackNotification(item: GreyProxyPendingRequest): string {
  const host = formatHost(item);
  return [
    formatPendingNotification(item),
    "",
    `Reply to decide:`,
    `/greywall allow ${item.id}`,
    `/greywall always ${item.id}`,
    `/greywall deny ${item.id}`,
  ].join("\n");
}

function buildPendingButtons(pendingId: number): PluginInteractiveButtons {
  return [
    [
      { text: "Allow", callback_data: `greywall:allow:${pendingId}`, style: "success" as const },
      {
        text: "Allow Always",
        callback_data: `greywall:always:${pendingId}`,
        style: "primary" as const,
      },
      { text: "Deny", callback_data: `greywall:deny:${pendingId}`, style: "danger" as const },
    ],
  ];
}

// ── Polling logic ──────────────────────────────────────────────────

async function pollAndNotifyPending(params: {
  api: OpenClawPluginApi;
  client: GreyProxyClient;
  statePath: string;
}): Promise<void> {
  const { api, client, statePath } = params;
  const state = await readNotifyState(statePath);

  if (state.subscribers.length === 0) {
    return; // No one to notify
  }

  let pendingItems: GreyProxyPendingRequest[];
  try {
    const result = await client.pendingList(50);
    pendingItems = result.items;
  } catch {
    return; // GreyProxy unreachable; skip this tick
  }

  let changed = false;

  // Notify for new pending requests
  for (const item of pendingItems) {
    const idStr = String(item.id);
    if (state.notifiedPendingIds[idStr]) {
      continue; // Already notified
    }

    const buttons = buildPendingButtons(item.id);

    for (const sub of state.subscribers) {
      // Telegram gets interactive buttons; others get text fallback
      if (sub.channel === "telegram") {
        await sendToSubscriber(api, sub, formatPendingNotification(item), { buttons });
      } else {
        await sendToSubscriber(api, sub, formatTextFallbackNotification(item));
      }
    }

    state.notifiedPendingIds[idStr] = Date.now();
    changed = true;
  }

  // Prune stale notification records
  const now = Date.now();
  const pendingIdSet = new Set(pendingItems.map((p) => String(p.id)));
  for (const [idStr, timestamp] of Object.entries(state.notifiedPendingIds)) {
    if (now - timestamp > STALE_NOTIFICATION_AGE_MS || !pendingIdSet.has(idStr)) {
      delete state.notifiedPendingIds[idStr];
      changed = true;
    }
  }

  if (changed) {
    await writeNotifyState(statePath, state);
  }
}

// ── Notifier service ───────────────────────────────────────────────

export function createGreywallNotifierService(api: OpenClawPluginApi): OpenClawPluginService {
  let pollInterval: ReturnType<typeof setInterval> | null = null;

  return {
    id: "greywall-notifier",
    async start(ctx) {
      const statePath = path.join(ctx.stateDir, "greywall-notify.json");
      const client = new GreyProxyClient();

      const tick = async () => {
        await pollAndNotifyPending({ api, client, statePath });
      };

      // Initial tick (non-blocking on failure)
      tick().catch((err) => {
        ctx.logger.warn(`greywall: initial notify poll failed: ${err?.message ?? String(err)}`);
      });

      pollInterval = setInterval(() => {
        tick().catch((err) => {
          ctx.logger.warn(`greywall: notify poll failed: ${err?.message ?? String(err)}`);
        });
      }, POLL_INTERVAL_MS);
      pollInterval.unref?.();
    },
    async stop() {
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
    },
  } as OpenClawPluginService;
}

// ── Interactive handlers ───────────────────────────────────────────

type CallbackContext = {
  payload: string;
  isAuthorized: boolean;
  respond: {
    editMessage: (params: { text: string; buttons?: PluginInteractiveButtons }) => Promise<void>;
  };
};

async function handleGreywallCallback(
  _api: OpenClawPluginApi,
  ctx: CallbackContext,
): Promise<{ handled: boolean }> {
  if (!ctx.isAuthorized) {
    await ctx.respond.editMessage({ text: "Unauthorized: only the owner can approve requests." });
    return { handled: true };
  }

  // Payload format: "allow:42", "always:42", "deny:42"
  const parts = ctx.payload.split(":");
  if (parts.length < 2) {
    return { handled: false };
  }

  const action = parts[0];
  const pendingId = parseInt(parts[1], 10);
  if (isNaN(pendingId)) {
    return { handled: false };
  }

  const client = new GreyProxyClient();

  try {
    let resultText: string;

    if (action === "allow") {
      const result = await client.pendingAllow(pendingId, {
        scope: "exact",
        duration: "session",
      });
      resultText = `Allowed ${result.rule.destination_pattern} (rule #${result.rule.id}, session)`;
    } else if (action === "always") {
      const result = await client.pendingAllow(pendingId, {
        scope: "exact",
        duration: "permanent",
      });
      resultText = `Allowed ${result.rule.destination_pattern} (rule #${result.rule.id}, permanent)`;
    } else if (action === "deny") {
      const result = await client.pendingDeny(pendingId, {
        scope: "exact",
        duration: "permanent",
      });
      resultText = `Denied ${result.rule.destination_pattern} (rule #${result.rule.id})`;
    } else {
      return { handled: false };
    }

    await ctx.respond.editMessage({ text: resultText, buttons: [] });
    return { handled: true };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    await ctx.respond.editMessage({ text: `Failed: ${msg}` });
    return { handled: true };
  }
}

export function registerGreywallInteractiveHandlers(api: OpenClawPluginApi): void {
  // Telegram
  api.registerInteractiveHandler({
    channel: "telegram",
    namespace: "greywall",
    handler: async (ctx) => {
      return handleGreywallCallback(api, {
        payload: ctx.callback.payload,
        isAuthorized: ctx.auth.isAuthorizedSender,
        respond: {
          editMessage: async (params) => {
            await ctx.respond.editMessage({
              text: params.text,
              buttons: params.buttons,
            });
          },
        },
      });
    },
  });

  // Discord
  api.registerInteractiveHandler({
    channel: "discord",
    namespace: "greywall",
    handler: async (ctx) => {
      await ctx.respond.acknowledge();
      return handleGreywallCallback(api, {
        payload: ctx.interaction.payload,
        isAuthorized: ctx.auth.isAuthorizedSender,
        respond: {
          editMessage: async (params) => {
            await ctx.respond.editMessage({ text: params.text });
          },
        },
      });
    },
  });

  // Slack
  api.registerInteractiveHandler({
    channel: "slack",
    namespace: "greywall",
    handler: async (ctx) => {
      await ctx.respond.acknowledge();
      return handleGreywallCallback(api, {
        payload: ctx.interaction.payload,
        isAuthorized: ctx.auth.isAuthorizedSender,
        respond: {
          editMessage: async (params) => {
            await ctx.respond.editMessage({ text: params.text });
          },
        },
      });
    },
  });
}
