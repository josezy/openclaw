import type { Dispatcher } from "undici";
import { logWarn } from "../../logger.js";
import { buildTimeoutAbortSignal } from "../../utils/fetch-timeout.js";
import { hasProxyEnvConfigured } from "./proxy-env.js";
import {
  closeDispatcher,
  createPinnedDispatcher,
  resolvePinnedHostnameWithPolicy,
  type LookupFn,
  type PinnedDispatcherPolicy,
  SsrFBlockedError,
  type SsrFPolicy,
} from "./ssrf.js";
import { loadUndiciRuntimeDeps } from "./undici-runtime.js";

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

export const GUARDED_FETCH_MODE = {
  STRICT: "strict",
  TRUSTED_ENV_PROXY: "trusted_env_proxy",
} as const;

export type GuardedFetchMode = (typeof GUARDED_FETCH_MODE)[keyof typeof GUARDED_FETCH_MODE];

export type GuardedFetchOptions = {
  url: string;
  fetchImpl?: FetchLike;
  init?: RequestInit;
  maxRedirects?: number;
  timeoutMs?: number;
  signal?: AbortSignal;
  policy?: SsrFPolicy;
  lookupFn?: LookupFn;
  dispatcherPolicy?: PinnedDispatcherPolicy;
  mode?: GuardedFetchMode;
  pinDns?: boolean;
  /** @deprecated use `mode: "trusted_env_proxy"` for trusted/operator-controlled URLs. */
  proxy?: "env";
  /**
   * @deprecated use `mode: "trusted_env_proxy"` instead.
   */
  dangerouslyAllowEnvProxyWithoutPinnedDns?: boolean;
  auditContext?: string;
};

export type GuardedFetchResult = {
  response: Response;
  finalUrl: string;
  release: () => Promise<void>;
};

type GuardedFetchPresetOptions = Omit<
  GuardedFetchOptions,
  "mode" | "proxy" | "dangerouslyAllowEnvProxyWithoutPinnedDns"
>;

const DEFAULT_MAX_REDIRECTS = 3;
const CROSS_ORIGIN_REDIRECT_SAFE_HEADERS = new Set([
  "accept",
  "accept-encoding",
  "accept-language",
  "cache-control",
  "content-language",
  "content-type",
  "if-match",
  "if-modified-since",
  "if-none-match",
  "if-unmodified-since",
  "pragma",
  "range",
  "user-agent",
]);

export function withStrictGuardedFetchMode(params: GuardedFetchPresetOptions): GuardedFetchOptions {
  return { ...params, mode: GUARDED_FETCH_MODE.STRICT };
}

export function withTrustedEnvProxyGuardedFetchMode(
  params: GuardedFetchPresetOptions,
): GuardedFetchOptions {
  return { ...params, mode: GUARDED_FETCH_MODE.TRUSTED_ENV_PROXY };
}

/**
 * Resolve a SOCKS5 proxy URL from env vars, normalizing `socks5h://` to `socks5://`.
 * `socks5h` means remote DNS via the proxy — undici's Socks5ProxyAgent sends domain
 * names as SOCKS5 DOMAIN address type which achieves the same behavior.
 */
function resolveSocksProxyUrl(env: NodeJS.ProcessEnv = process.env): string | null {
  const keys = ["all_proxy", "ALL_PROXY", "http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY"];
  for (const key of keys) {
    const value = env[key]?.trim();
    if (value && /^socks5?h?:\/\//i.test(value)) {
      return value.replace(/^socks5?h?:\/\//i, "socks5://");
    }
  }
  return null;
}

function resolveGuardedFetchMode(params: GuardedFetchOptions): GuardedFetchMode {
  if (params.mode) {
    return params.mode;
  }
  if (params.proxy === "env" && params.dangerouslyAllowEnvProxyWithoutPinnedDns === true) {
    return GUARDED_FETCH_MODE.TRUSTED_ENV_PROXY;
  }
  return GUARDED_FETCH_MODE.STRICT;
}

function assertExplicitProxySupportsPinnedDns(
  url: URL,
  dispatcherPolicy?: PinnedDispatcherPolicy,
  pinDns?: boolean,
): void {
  if (
    pinDns !== false &&
    dispatcherPolicy?.mode === "explicit-proxy" &&
    url.protocol !== "https:"
  ) {
    throw new Error(
      "Explicit proxy SSRF pinning requires HTTPS targets; plain HTTP targets are not supported",
    );
  }
}

function isRedirectStatus(status: number): boolean {
  return status === 301 || status === 302 || status === 303 || status === 307 || status === 308;
}

function retainSafeHeadersForCrossOriginRedirect(init?: RequestInit): RequestInit | undefined {
  if (!init?.headers) {
    return init;
  }
  const incoming = new Headers(init.headers);
  const headers = new Headers();
  for (const [key, value] of incoming.entries()) {
    if (CROSS_ORIGIN_REDIRECT_SAFE_HEADERS.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  }
  return { ...init, headers };
}

export async function fetchWithSsrFGuard(params: GuardedFetchOptions): Promise<GuardedFetchResult> {
  const fetcher: FetchLike | undefined = params.fetchImpl ?? globalThis.fetch;
  if (!fetcher) {
    throw new Error("fetch is not available");
  }

  const maxRedirects =
    typeof params.maxRedirects === "number" && Number.isFinite(params.maxRedirects)
      ? Math.max(0, Math.floor(params.maxRedirects))
      : DEFAULT_MAX_REDIRECTS;
  const mode = resolveGuardedFetchMode(params);

  const { signal, cleanup } = buildTimeoutAbortSignal({
    timeoutMs: params.timeoutMs,
    signal: params.signal,
  });

  let released = false;
  const release = async (dispatcher?: Dispatcher | null) => {
    if (released) {
      return;
    }
    released = true;
    cleanup();
    await closeDispatcher(dispatcher ?? undefined);
  };

  const visited = new Set<string>();
  let currentUrl = params.url;
  let currentInit = params.init ? { ...params.init } : undefined;
  let redirectCount = 0;

  while (true) {
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(currentUrl);
    } catch {
      await release();
      throw new Error("Invalid URL: must be http or https");
    }
    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      await release();
      throw new Error("Invalid URL: must be http or https");
    }

    let dispatcher: Dispatcher | null = null;
    try {
      assertExplicitProxySupportsPinnedDns(parsedUrl, params.dispatcherPolicy, params.pinDns);
      const canUseTrustedEnvProxy =
        mode === GUARDED_FETCH_MODE.TRUSTED_ENV_PROXY && hasProxyEnvConfigured();

      // When using an env proxy (greywall sandbox), skip DNS pinning — the proxy
      // handles DNS resolution, and Seatbelt may block direct DNS lookups.
      const pinned = canUseTrustedEnvProxy
        ? null
        : await resolvePinnedHostnameWithPolicy(parsedUrl.hostname, {
            lookupFn: params.lookupFn,
            policy: params.policy,
          });
      if (canUseTrustedEnvProxy) {
        // Prefer SOCKS5 proxy (from ALL_PROXY) — undici's EnvHttpProxyAgent only
        // handles HTTP CONNECT proxies and may fail in sandboxed environments
        // where DNS or direct TCP is restricted.
        const socksUrl = resolveSocksProxyUrl();
        if (socksUrl) {
          const { ProxyAgent } = loadUndiciRuntimeDeps();
          dispatcher = new ProxyAgent({ uri: socksUrl });
        } else {
          const { EnvHttpProxyAgent } = loadUndiciRuntimeDeps();
          dispatcher = new EnvHttpProxyAgent();
        }
      } else if (params.pinDns !== false && pinned) {
        dispatcher = createPinnedDispatcher(pinned, params.dispatcherPolicy, params.policy);
      }

      const init: RequestInit & { dispatcher?: Dispatcher } = {
        ...(currentInit ? { ...currentInit } : {}),
        redirect: "manual",
        ...(dispatcher ? { dispatcher } : {}),
        ...(signal ? { signal } : {}),
      };

      const response = await fetcher(parsedUrl.toString(), init);

      if (isRedirectStatus(response.status)) {
        const location = response.headers.get("location");
        if (!location) {
          await release(dispatcher);
          throw new Error(`Redirect missing location header (${response.status})`);
        }
        redirectCount += 1;
        if (redirectCount > maxRedirects) {
          await release(dispatcher);
          throw new Error(`Too many redirects (limit: ${maxRedirects})`);
        }
        const nextParsedUrl = new URL(location, parsedUrl);
        const nextUrl = nextParsedUrl.toString();
        if (visited.has(nextUrl)) {
          await release(dispatcher);
          throw new Error("Redirect loop detected");
        }
        if (nextParsedUrl.origin !== parsedUrl.origin) {
          currentInit = retainSafeHeadersForCrossOriginRedirect(currentInit);
        }
        visited.add(nextUrl);
        void response.body?.cancel();
        await closeDispatcher(dispatcher);
        currentUrl = nextUrl;
        continue;
      }

      return {
        response,
        finalUrl: currentUrl,
        release: async () => release(dispatcher),
      };
    } catch (err) {
      if (err instanceof SsrFBlockedError) {
        const context = params.auditContext ?? "url-fetch";
        logWarn(
          `security: blocked URL fetch (${context}) target=${parsedUrl.origin}${parsedUrl.pathname} reason=${err.message}`,
        );
      } else if (err instanceof Error && err.cause) {
        // Surface the real cause for network errors (undici wraps them as
        // TypeError: fetch failed with the underlying error in .cause).
        const cause = err.cause instanceof Error ? err.cause.message : String(err.cause);
        logWarn(
          `fetch-guard: ${err.message} cause=${cause} target=${parsedUrl.origin}${parsedUrl.pathname}`,
        );
      }
      await release(dispatcher);
      throw err;
    }
  }
}
