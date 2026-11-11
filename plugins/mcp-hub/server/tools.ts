import { Scope } from "@shared/types";
import { createMcpServer } from "@server/mcp";
import env from "./env";

let cached: ReadonlySet<string> | undefined;

/**
 * The names of the MCP tools available with every scope granted. The list is
 * fixed at build time, so it is read once.
 *
 * @returns the tool names.
 */
export function toolNames(): ReadonlySet<string> {
  if (!cached) {
    const server = createMcpServer(env.URL, Object.values(Scope));

    // The SDK keeps registered tools in a private map and has no public list.
    const tools: unknown = Reflect.get(server, "_registeredTools");
    cached = new Set(
      tools && typeof tools === "object" ? Object.keys(tools) : []
    );
  }
  return cached;
}
