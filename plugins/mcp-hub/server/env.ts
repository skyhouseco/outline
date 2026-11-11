import { IsOptional } from "class-validator";
import { Environment } from "@server/env";
import environment from "@server/utils/environment";

class McpHubPluginEnvironment extends Environment {
  /**
   * The secret the SkyHouse MCP hub sends as a bearer token on /admin/mcp.
   * When unset every /admin/mcp route answers 404.
   */
  @IsOptional()
  public MCP_HUB_TOKEN = this.toOptionalString(environment.MCP_HUB_TOKEN);
}

export default new McpHubPluginEnvironment();
