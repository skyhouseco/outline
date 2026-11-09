import { IsBoolean, IsOptional } from "class-validator";
import { Environment } from "@server/env";
import environment from "@server/utils/environment";

class ForwardAuthPluginEnvironment extends Environment {
  /**
   * Trust the identity headers set by a forward-auth proxy. Only enable this
   * when the proxy is the only way to reach Outline, otherwise anyone that can
   * reach the app directly can forge the headers and sign in as any user.
   */
  @IsOptional()
  @IsBoolean()
  public FORWARD_AUTH_ENABLED = this.toOptionalBoolean(
    environment.FORWARD_AUTH_ENABLED
  );

  /**
   * The name shown on the sign-in button.
   */
  public FORWARD_AUTH_DISPLAY_NAME =
    environment.FORWARD_AUTH_DISPLAY_NAME || "Single sign-on";

  /**
   * Proxy roles that make a user a workspace admin, comma separated.
   */
  @IsOptional()
  public FORWARD_AUTH_ADMIN_ROLES = this.toOptionalCommaList(
    environment.FORWARD_AUTH_ADMIN_ROLES
  );

  /**
   * Proxy roles that make a user a workspace member, comma separated. When
   * set, users without an admin, member or viewer role are refused. When not
   * set, the role of users without a listed role is left unchanged.
   */
  @IsOptional()
  public FORWARD_AUTH_MEMBER_ROLES = this.toOptionalCommaList(
    environment.FORWARD_AUTH_MEMBER_ROLES
  );

  /**
   * Proxy roles that make a user a workspace viewer, comma separated.
   */
  @IsOptional()
  public FORWARD_AUTH_VIEWER_ROLES = this.toOptionalCommaList(
    environment.FORWARD_AUTH_VIEWER_ROLES
  );

  /**
   * The proxy's sign out path or URL. Outline appends `rd` with the URL to
   * return to afterwards.
   */
  public FORWARD_AUTH_LOGOUT_URL =
    environment.FORWARD_AUTH_LOGOUT_URL || "/oauth2/sign_out";
}

export default new ForwardAuthPluginEnvironment();
