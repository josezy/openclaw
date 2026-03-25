import type { OpenClawPluginService } from "openclaw/plugin-sdk/core";
import { CHANNEL_DOMAINS, PROVIDER_DOMAINS } from "../../../src/infra/access-manifest.js";
import { GreyProxyClient } from "./greyproxy-client.js";

type ServiceContext = {
  logger: {
    info: (message: string) => void;
    warn: (message: string) => void;
    error: (message: string) => void;
    debug?: (message: string) => void;
  };
  config: Record<string, unknown>;
};

/**
 * Background service that monitors GreyProxy health on startup
 * and auto-seeds domain allow rules from the gateway configuration.
 */
export function createGreywallService(): OpenClawPluginService {
  let stopped = false;

  return {
    id: "greywall",
    async start(ctx: ServiceContext) {
      stopped = false;
      const client = new GreyProxyClient();

      try {
        const health = await client.health();
        ctx.logger.info(`greywall: GreyProxy ${health.version} is ${health.status}`);

        // Auto-seed domain allow rules from config
        await seedDomainRules(client, ctx);

        const pending = await client.pendingCount();
        if (pending > 0) {
          ctx.logger.info(`greywall: ${pending} pending network request(s) awaiting decision`);
        }
      } catch {
        ctx.logger.warn(
          "greywall: GreyProxy not reachable at localhost:43080. Network monitoring tools will be unavailable.",
        );
      }
    },
    async stop() {
      stopped = true;
    },
  } as OpenClawPluginService;
}

/**
 * Detect configured channels and providers from the config object
 * and ingest their required domains as GreyProxy allow rules.
 */
async function seedDomainRules(client: GreyProxyClient, ctx: ServiceContext): Promise<void> {
  const rules: Array<{
    destination_pattern: string;
    container_pattern: string;
    action: string;
    created_by: string;
    notes?: string;
  }> = [];

  // Base domains (always needed)
  for (const domain of ["api.anthropic.com", "registry.npmjs.org", "localhost"]) {
    rules.push({
      destination_pattern: domain,
      container_pattern: "*",
      action: "allow",
      created_by: "openclaw-gateway",
      notes: "base",
    });
  }

  // Channel-specific domains
  const channelsSection = ctx.config.channels;
  if (channelsSection && typeof channelsSection === "object") {
    for (const key of Object.keys(channelsSection as Record<string, unknown>)) {
      const domains = CHANNEL_DOMAINS[key];
      if (domains) {
        for (const domain of domains) {
          rules.push({
            destination_pattern: domain,
            container_pattern: "*",
            action: "allow",
            created_by: "openclaw-gateway",
            notes: `channel:${key}`,
          });
        }
      }
    }
  }

  // Provider-specific domains (detect from agents.defaults.model.primary)
  const agentsSection = ctx.config.agents;
  if (agentsSection && typeof agentsSection === "object") {
    const defaults = (agentsSection as Record<string, unknown>).defaults;
    if (defaults && typeof defaults === "object") {
      const model = (defaults as Record<string, unknown>).model;
      if (model && typeof model === "object") {
        const primary = (model as Record<string, unknown>).primary;
        if (typeof primary === "string") {
          const providerPrefix = primary.split("/")[0];
          const domains = providerPrefix ? PROVIDER_DOMAINS[providerPrefix] : undefined;
          if (domains) {
            for (const domain of domains) {
              rules.push({
                destination_pattern: domain,
                container_pattern: "*",
                action: "allow",
                created_by: "openclaw-gateway",
                notes: `provider:${providerPrefix}`,
              });
            }
          }
        }
      }
    }
  }

  if (rules.length === 0) {
    return;
  }

  try {
    await client.rulesIngest(rules);
    ctx.logger.info(`greywall: seeded ${rules.length} domain allow rule(s) into GreyProxy`);
  } catch (err) {
    ctx.logger.warn(
      `greywall: failed to seed domain rules: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}
