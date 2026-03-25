/**
 * HTTP + WebSocket client for GreyProxy REST API.
 * Default base: http://localhost:43080
 *
 * When running inside a greywall sandbox, Seatbelt blocks direct TCP to port
 * 43080. The client detects the HTTP CONNECT proxy env var (HTTP_PROXY) set by
 * greywall and routes API calls through it, tunnelling via port 43051 which
 * Seatbelt allows.
 */

import { ProxyAgent } from "undici";

const DEFAULT_BASE_URL = "http://localhost:43080";

export type GreyProxyHealth = {
  service: string;
  version: string;
  status: string;
  ports: Record<string, number>;
};

export type GreyProxyPendingRequest = {
  id: number;
  container_name: string;
  container_id: string;
  destination_host: string;
  destination_port: number;
  resolved_hostname: string | null;
  first_seen: string;
  last_seen: string;
  attempt_count: number;
};

export type GreyProxyRequestLog = {
  id: number;
  timestamp: string;
  container_name: string;
  destination_host: string;
  destination_port: number | null;
  resolved_hostname: string | null;
  method: string | null;
  result: string;
  rule_id: number | null;
  response_time_ms: number | null;
  rule_summary: string | null;
};

export type GreyProxyRule = {
  id: number;
  container_pattern: string;
  destination_pattern: string;
  port_pattern: string;
  rule_type: string;
  action: string;
  created_at: string;
  expires_at: string | null;
  last_used_at: string | null;
  created_by: string;
  notes: string | null;
  is_active: boolean;
};

export type GreyProxyDashboardStats = {
  period: { from: string; to: string };
  total_requests: number;
  allowed: number;
  blocked: number;
  allow_rate: number;
  by_container: Array<{ name: string; total: number; allowed: number; blocked: number }>;
  top_blocked: Array<{ host: string; port: number; resolved_hostname: string; count: number }>;
  timeline: Array<{ timestamp: string; allowed: number; blocked: number }>;
  recent: GreyProxyRequestLog[];
};

export type GreyProxyEvent = {
  type: string;
  data?: unknown;
  message?: string;
  timestamp?: string;
};

export type GreyProxyClientOptions = {
  baseUrl?: string;
};

/**
 * Resolve the HTTP CONNECT proxy URL when running inside a greywall sandbox.
 * Returns undefined when no proxy is configured (direct access).
 */
function resolveProxyUrl(): string | undefined {
  return (
    process.env.http_proxy?.trim() ||
    process.env.HTTP_PROXY?.trim() ||
    process.env.https_proxy?.trim() ||
    process.env.HTTPS_PROXY?.trim() ||
    undefined
  );
}

export class GreyProxyClient {
  private readonly baseUrl: string;
  private readonly dispatcher: ProxyAgent | undefined;

  constructor(opts?: GreyProxyClientOptions) {
    const raw = opts?.baseUrl ?? DEFAULT_BASE_URL;
    this.baseUrl = raw.replace(/\/+$/, "");
    const proxyUrl = resolveProxyUrl();
    this.dispatcher = proxyUrl ? new ProxyAgent(proxyUrl) : undefined;
  }

  private async get<T>(path: string, params?: Record<string, string>): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (params) {
      for (const [k, v] of Object.entries(params)) {
        if (v) url.searchParams.set(k, v);
      }
    }
    const res = await fetch(url.toString(), {
      signal: AbortSignal.timeout(10_000),
      ...(this.dispatcher ? { dispatcher: this.dispatcher } : {}),
    } as RequestInit);
    if (!res.ok) {
      throw new Error(`GreyProxy ${path}: ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  }

  private async post<T>(path: string, body?: unknown): Promise<T> {
    const res = await fetch(new URL(path, this.baseUrl).toString(), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000),
      ...(this.dispatcher ? { dispatcher: this.dispatcher } : {}),
    } as RequestInit);
    if (!res.ok) {
      throw new Error(`GreyProxy ${path}: ${res.status} ${res.statusText}`);
    }
    return (await res.json()) as T;
  }

  async health(): Promise<GreyProxyHealth> {
    return this.get("/api/health");
  }

  async dashboard(period = "today"): Promise<GreyProxyDashboardStats> {
    return this.get("/api/dashboard", { period });
  }

  async pendingCount(): Promise<number> {
    const res = await this.get<{ count: number }>("/api/pending/count");
    return res.count;
  }

  async pendingList(limit = 50): Promise<{ items: GreyProxyPendingRequest[]; total: number }> {
    return this.get("/api/pending", { limit: String(limit) });
  }

  async pendingAllow(
    id: number,
    opts?: { scope?: string; duration?: string; notes?: string },
  ): Promise<{ rule: GreyProxyRule }> {
    return this.post(`/api/pending/${id}/allow`, {
      scope: opts?.scope ?? "exact",
      duration: opts?.duration ?? "permanent",
      ...(opts?.notes ? { notes: opts.notes } : {}),
    });
  }

  async pendingDeny(
    id: number,
    opts?: { scope?: string; duration?: string; notes?: string },
  ): Promise<{ rule: GreyProxyRule }> {
    return this.post(`/api/pending/${id}/deny`, {
      scope: opts?.scope ?? "exact",
      duration: opts?.duration ?? "permanent",
      ...(opts?.notes ? { notes: opts.notes } : {}),
    });
  }

  async logs(params?: {
    container?: string;
    destination?: string;
    result?: string;
    limit?: number;
  }): Promise<{ items: GreyProxyRequestLog[]; total: number }> {
    return this.get("/api/logs", {
      ...(params?.container ? { container: params.container } : {}),
      ...(params?.destination ? { destination: params.destination } : {}),
      ...(params?.result ? { result: params.result } : {}),
      limit: String(params?.limit ?? 25),
    });
  }

  async rulesIngest(
    rules: Array<{
      destination_pattern: string;
      container_pattern?: string;
      action: string;
      created_by?: string;
      notes?: string;
    }>,
  ): Promise<unknown> {
    return this.post("/api/rules/ingest", rules);
  }

  /** Build a WebSocket URL for the event stream. */
  wsUrl(): string {
    const url = new URL("/ws", this.baseUrl);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    return url.toString();
  }
}
