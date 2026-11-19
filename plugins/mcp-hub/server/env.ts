import { IsOptional } from "class-validator";
import { Environment } from "@server/env";
import environment from "@server/utils/environment";
import { CannotUseWithout } from "@server/utils/validators";

class McpHubPluginEnvironment extends Environment {
  /**
   * The secret the SkyHouse MCP hub sends as a bearer token on /admin/mcp.
   * When unset every /admin/mcp route answers 404.
   */
  @IsOptional()
  public MCP_HUB_TOKEN = this.toOptionalString(environment.MCP_HUB_TOKEN);

  /**
   * The Microsoft Entra tenant of the company's SSO app. With the client id,
   * /mcp also accepts the person's own Microsoft access token, which the MCP
   * hub forwards unchanged. When unset only Outline's own tokens are accepted.
   */
  @IsOptional()
  @CannotUseWithout("AUTH_ENTRA_CLIENT_ID")
  public AUTH_ENTRA_TENANT_ID = this.toOptionalString(
    environment.AUTH_ENTRA_TENANT_ID
  );

  /**
   * The client id of the SSO app, which Microsoft access tokens for /mcp must
   * be issued for (their `aud`).
   */
  @IsOptional()
  @CannotUseWithout("AUTH_ENTRA_TENANT_ID")
  public AUTH_ENTRA_CLIENT_ID = this.toOptionalString(
    environment.AUTH_ENTRA_CLIENT_ID
  );

  /**
   * The SSO app's delegated scope a Microsoft access token must carry (in its
   * `scp`) to use the wiki's MCP server.
   */
  public MCP_ENTRA_SCOPE =
    this.toOptionalString(environment.MCP_ENTRA_SCOPE) ?? "wiki.mcp.access";

  /**
   * The client apps a Microsoft access token may be issued to (its `azp`),
   * comma separated. Defaults to the Claude MCP Client.
   */
  public MCP_CLIENT_APP_IDS = (
    this.toOptionalCommaList(environment.MCP_CLIENT_APP_IDS) ?? [
      "967d3a14-9da0-43d4-8031-8d1185a9bda7",
    ]
  ).filter(Boolean);
}

export default new McpHubPluginEnvironment();
