import fs from "node:fs";
import path from "node:path";
import type { OpenClawPluginApi } from "openclaw/plugin-sdk/core";
import type { PluginCommandContext, PluginInteractiveButtons } from "../../../src/plugins/types.js";

// ── Types ──────────────────────────────────────────────────────────

export type SubscriberChannel = "telegram" | "discord" | "slack" | string;

export type GreywallSubscriber = {
  /** Deterministic key for deduplication. */
  id: string;
  /** Channel this subscriber is on. */
  channel: SubscriberChannel;
  /** Target chat/user/channel ID. */
  to: string;
  /** Multi-account identifier (Telegram, Discord, Slack). */
  accountId?: string;
  /** Telegram forum thread ID. */
  messageThreadId?: number;
  /** Slack thread timestamp. */
  threadTs?: string;
  /** When this subscriber was added. */
  addedAtMs: number;
};

export type GreywallNotifyState = {
  subscribers: GreywallSubscriber[];
  /** Maps pending request IDs (stringified) to the timestamp they were notified. */
  notifiedPendingIds: Record<string, number>;
};

export type SendResult = {
  sent: boolean;
  messageId?: string;
  error?: string;
};

// ── Subscriber key ─────────────────────────────────────────────────

export function subscriberKey(sub: {
  channel: string;
  to: string;
  accountId?: string;
  messageThreadId?: number;
  threadTs?: string;
}): string {
  return [sub.channel, sub.to, sub.accountId ?? "", sub.messageThreadId ?? sub.threadTs ?? ""].join(
    "|",
  );
}

// ── State persistence ──────────────────────────────────────────────

const NOTIFY_STATE_FILE = "greywall-notify.json";

export function resolveNotifyStatePath(stateDir: string): string {
  return path.join(stateDir, NOTIFY_STATE_FILE);
}

function normalizeNotifyState(raw: unknown): GreywallNotifyState {
  if (!raw || typeof raw !== "object") {
    return { subscribers: [], notifiedPendingIds: {} };
  }
  const obj = raw as Record<string, unknown>;
  const subscribers = Array.isArray(obj.subscribers) ? obj.subscribers : [];
  const notifiedPendingIds =
    obj.notifiedPendingIds && typeof obj.notifiedPendingIds === "object"
      ? (obj.notifiedPendingIds as Record<string, number>)
      : {};
  return {
    subscribers: subscribers.filter(
      (s): s is GreywallSubscriber =>
        !!s && typeof s === "object" && typeof (s as Record<string, unknown>).id === "string",
    ),
    notifiedPendingIds,
  };
}

export async function readNotifyState(filePath: string): Promise<GreywallNotifyState> {
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    return normalizeNotifyState(JSON.parse(content));
  } catch {
    return { subscribers: [], notifiedPendingIds: {} };
  }
}

export async function writeNotifyState(
  filePath: string,
  state: GreywallNotifyState,
): Promise<void> {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(state, null, 2) + "\n");
}

// ── Subscriber management ──────────────────────────────────────────

export function upsertSubscriber(
  state: GreywallNotifyState,
  subscriber: GreywallSubscriber,
): boolean {
  const key = subscriber.id;
  const existing = state.subscribers.findIndex((s) => s.id === key);
  if (existing >= 0) {
    // Already subscribed; update metadata.
    state.subscribers[existing] = subscriber;
    return false;
  }
  state.subscribers.push(subscriber);
  return true;
}

export function removeSubscriber(state: GreywallNotifyState, key: string): boolean {
  const before = state.subscribers.length;
  state.subscribers = state.subscribers.filter((s) => s.id !== key);
  return state.subscribers.length < before;
}

export function findSubscriber(
  state: GreywallNotifyState,
  key: string,
): GreywallSubscriber | undefined {
  return state.subscribers.find((s) => s.id === key);
}

// ── Resolve subscriber from command context ────────────────────────

/**
 * Strip channel-scoped prefix from `from`/`to` values.
 * Discord uses `discord:channel:ID` or `discord:ID` (DMs).
 * `sendMessageDiscord` expects `channel:ID` or `user:ID`.
 */
function resolveDiscordTarget(ctx: PluginCommandContext): string | null {
  const raw = ctx.from ?? ctx.to;
  if (!raw) {
    return null;
  }
  // "discord:channel:123" → "channel:123"
  if (raw.startsWith("discord:channel:")) {
    return raw.slice("discord:".length);
  }
  // "discord:123" (DM) → "user:123"
  if (raw.startsWith("discord:")) {
    return `user:${raw.slice("discord:".length)}`;
  }
  // Already in "channel:ID" or "user:ID" format
  if (raw.startsWith("channel:") || raw.startsWith("user:")) {
    return raw;
  }
  return null;
}

export function resolveSubscriberFromCommandContext(
  ctx: PluginCommandContext,
): GreywallSubscriber | null {
  const channel = ctx.channel;

  let to: string | null;
  if (channel === "discord") {
    to = resolveDiscordTarget(ctx);
  } else {
    to = ctx.senderId || ctx.from || ctx.to || null;
  }

  if (!to) {
    return null;
  }

  const sub: GreywallSubscriber = {
    id: subscriberKey({
      channel,
      to,
      accountId: ctx.accountId,
      messageThreadId: ctx.messageThreadId,
    }),
    channel,
    to,
    accountId: ctx.accountId,
    messageThreadId: ctx.messageThreadId,
    addedAtMs: Date.now(),
  };
  return sub;
}

// ── Multi-channel send ─────────────────────────────────────────────

export async function sendToSubscriber(
  api: OpenClawPluginApi,
  sub: GreywallSubscriber,
  text: string,
  opts?: { buttons?: PluginInteractiveButtons },
): Promise<SendResult> {
  try {
    switch (sub.channel) {
      case "telegram": {
        const send = api.runtime?.channel?.telegram?.sendMessageTelegram;
        if (!send) {
          return { sent: false, error: "telegram runtime unavailable" };
        }
        const result = await send(sub.to, text, {
          ...(sub.accountId ? { accountId: sub.accountId } : {}),
          ...(sub.messageThreadId != null ? { messageThreadId: sub.messageThreadId } : {}),
          ...(opts?.buttons ? { buttons: opts.buttons } : {}),
        });
        return { sent: true, messageId: result?.messageId };
      }
      case "discord": {
        const send = api.runtime?.channel?.discord?.sendMessageDiscord;
        if (!send) {
          return { sent: false, error: "discord runtime unavailable" };
        }
        const result = await send(sub.to, text, {
          ...(sub.accountId ? { accountId: sub.accountId } : {}),
        });
        return { sent: true, messageId: result?.messageId };
      }
      case "slack": {
        const send = api.runtime?.channel?.slack?.sendMessageSlack;
        if (!send) {
          return { sent: false, error: "slack runtime unavailable" };
        }
        const result = await send(sub.to, text, {
          ...(sub.accountId ? { accountId: sub.accountId } : {}),
          ...(sub.threadTs ? { threadTs: sub.threadTs } : {}),
        });
        return { sent: true, messageId: result?.messageId };
      }
      default: {
        // Attempt generic channel send via known runtime channels.
        // For unsupported channels, log and skip.
        return { sent: false, error: `unsupported channel: ${sub.channel}` };
      }
    }
  } catch (err) {
    return { sent: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export async function sendToAllSubscribers(
  api: OpenClawPluginApi,
  state: GreywallNotifyState,
  text: string,
  opts?: { buttons?: PluginInteractiveButtons },
): Promise<void> {
  for (const sub of state.subscribers) {
    const result = await sendToSubscriber(api, sub, text, opts);
    if (!result.sent) {
      api.logger?.warn?.(`greywall: failed to notify ${sub.channel}/${sub.to}: ${result.error}`);
    }
  }
}
