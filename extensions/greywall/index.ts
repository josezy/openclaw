import { definePluginEntry } from "openclaw/plugin-sdk/core";
import { createGreywallCommand } from "./src/greywall-command.js";
import {
  createGreywallNotifierService,
  registerGreywallInteractiveHandlers,
} from "./src/greywall-notify.js";
import { createGreywallService } from "./src/greywall-service.js";
import {
  createGreywallStatusTool,
  createGreywallPendingTool,
  createGreywallLogsTool,
} from "./src/greywall-tools.js";

export default definePluginEntry({
  id: "greywall",
  name: "Greywall",
  description: "Network monitoring and control via GreyProxy sandbox proxy",
  register(api) {
    // Health-check service
    api.registerService(createGreywallService());

    // Agent tools for querying GreyProxy (read-only; allow/deny is human-only via commands + buttons)
    api.registerTool(createGreywallStatusTool(api));
    api.registerTool(createGreywallPendingTool(api));
    api.registerTool(createGreywallLogsTool(api));

    // Notification polling service (pending request alerts)
    api.registerService(createGreywallNotifierService(api));

    // Interactive button handlers (Telegram, Discord, Slack)
    registerGreywallInteractiveHandlers(api);

    // /greywall command (notify on/off/status, allow/deny)
    api.registerCommand(createGreywallCommand(api));
  },
});
