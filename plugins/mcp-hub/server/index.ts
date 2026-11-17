import Logger from "@server/logging/Logger";
import { Hook, PluginManager } from "@server/utils/PluginManager";
import config from "../plugin.json";
import admin, { AdminPath } from "./admin";
import { authenticateEntraToken, entraRateLimitIdentifier } from "./entraAuth";
import env from "./env";
import { isBlocked, normalizeEmail, recordCall } from "./store";
import { toolNames } from "./tools";

/** The message a blocked person gets on every MCP call. */
const BlockedMessage = "Your access to this MCP was turned off by an admin.";

// Always mounted: without MCP_HUB_TOKEN every route answers 404, rather than
// falling through to the app.
PluginManager.add({
  ...config,
  type: Hook.Mount,
  value: { path: AdminPath, app: admin },
});

PluginManager.add({
  ...config,
  type: Hook.MCP,
  value: {
    // Off without AUTH_ENTRA_TENANT_ID and AUTH_ENTRA_CLIENT_ID.
    authenticate: authenticateEntraToken,
    rateLimitIdentifier: entraRateLimitIdentifier,
    refuse: async (user) => {
      const email = normalizeEmail(user.email);
      return email && (await isBlocked(email)) ? BlockedMessage : undefined;
    },
    onToolCall: async (call) => {
      // Requests may name any tool, only real ones are counted as usage.
      if (toolNames().has(call.tool)) {
        await recordCall(call);
      }
    },
  },
});

if (env.MCP_HUB_TOKEN) {
  Logger.info("plugins", "MCP hub contract enabled");
}

if (env.AUTH_ENTRA_TENANT_ID && env.AUTH_ENTRA_CLIENT_ID) {
  Logger.info("plugins", "MCP accepts Microsoft Entra access tokens");
}
