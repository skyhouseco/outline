import Logger from "@server/logging/Logger";
import { Hook, PluginManager } from "@server/utils/PluginManager";
import config from "../plugin.json";
import router from "./auth/forwardAuth";
import env from "./env";

// Trusting identity headers is only safe behind the proxy, so the plugin stays
// off unless it is explicitly enabled.
if (env.FORWARD_AUTH_ENABLED) {
  PluginManager.add({
    ...config,
    type: Hook.AuthProvider,
    value: { router, id: config.id },
    name: env.FORWARD_AUTH_DISPLAY_NAME,
  });
  Logger.info("plugins", "Forward auth plugin registered");
}
