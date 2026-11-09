import { PadlockIcon } from "outline-icons";
import { Hook, PluginManager } from "~/utils/PluginManager";
import config from "../plugin.json";

PluginManager.add([
  {
    ...config,
    type: Hook.Icon,
    value: PadlockIcon,
  },
]);
