import { createHash } from "node:crypto";
import type { Context } from "koa";
import { Op, Sequelize } from "sequelize";
import { AuthenticationType } from "@shared/types";
import serverEnv from "@server/env";
import { AuthenticationError, ServiceUnavailableError } from "@server/errors";
import Logger from "@server/logging/Logger";
import { User } from "@server/models";
import { OAuthHelper } from "@server/utils/oauth/OAuthHelper";
import { getTeamFromContext } from "@server/utils/passport";
import type {
  McpAuthentication,
  McpRefusal,
} from "@server/utils/PluginManager";
import env from "./env";
import {
  type EntraTokenConfig,
  isMicrosoftToken,
  verifyEntraToken,
} from "./entraToken";

/**
 * Signs a request to /mcp in with the person's own Microsoft Entra access
 * token, as forwarded by the MCP hub. The token must pass every check in
 * entraToken.ts and name an existing, active wiki user, who then uses the MCP
 * server with their own role and permissions. Users are never created here.
 *
 * A valid token for a person who may not use the wiki, with no account or a
 * suspended one, is refused with a sentence saying why and what to do. The
 * route answers it with a 403, as signing in again would not help.
 *
 * @param ctx the request context, used to find the team.
 * @param token the bearer token.
 * @returns the user, the refusal, or undefined when Entra sign-in is off or
 * the token is not a Microsoft one.
 * @throws {AuthenticationError} when the token is not valid.
 * @throws {ServiceUnavailableError} when Microsoft's keys cannot be loaded.
 */
export async function authenticateEntraToken(
  ctx: Context,
  token: string
): Promise<McpAuthentication | McpRefusal | undefined> {
  const config = entraConfig();
  if (!config || !isMicrosoftToken(token)) {
    return undefined;
  }

  const result = await verifyEntraToken(token, config);
  if (!result.ok) {
    Logger.info("authentication", "Microsoft access token refused on /mcp", {
      reason: result.reason,
      detail: result.detail,
      email: result.email,
    });
    if (result.unavailable) {
      throw ServiceUnavailableError(
        "The wiki could not check your Microsoft sign-in right now. Try again in a moment."
      );
    }
    throw AuthenticationError(
      `Your Microsoft sign-in was not accepted (${result.reason}). Sign in again and retry.`
    );
  }

  const { email } = result;
  const user = await findUser(ctx, email);

  // Accounts are only made by signing in to the wiki, never from an MCP call.
  if (!user || user.isInvited) {
    Logger.info("authentication", "No wiki account for Microsoft sign-in", {
      email,
    });
    return {
      refused: `There is no wiki account for ${email} yet. Sign in to the wiki once at ${serverEnv.URL}, then try again.`,
    };
  }

  if (user.isSuspended) {
    Logger.info("authentication", "Suspended wiki account on /mcp", {
      email,
    });
    return {
      refused:
        "Your wiki account is suspended. Ask a wiki admin to restore it, then try again.",
    };
  }

  // The token grants the whole MCP server, the user's own role and document
  // permissions decide what they can do with it.
  return {
    user,
    type: AuthenticationType.OAUTH,
    scope: [...OAuthHelper.mcpScopes],
  };
}

/**
 * Keys the rate limit of /mcp on the person a Microsoft access token names,
 * as the MCP hub sends every person's calls from one address. Only a token
 * that passes every check is keyed this way, any other is left to the usual
 * limit by address, so a bad token cannot dodge it.
 *
 * @param token the bearer token.
 * @returns the person's rate limit identifier, or undefined.
 */
export async function entraRateLimitIdentifier(
  token: string
): Promise<string | undefined> {
  const config = entraConfig();
  if (!config || !isMicrosoftToken(token)) {
    return undefined;
  }

  const result = await verifyEntraToken(token, config);
  if (!result.ok) {
    return undefined;
  }

  // Hashed, so emails do not appear in the rate limiter's store.
  const hash = createHash("sha256").update(result.email).digest("hex");
  return `entra:${hash.slice(0, 32)}`;
}

/**
 * The settings Microsoft access tokens are checked against.
 *
 * @returns the settings, or undefined when Entra sign-in is off.
 */
function entraConfig(): EntraTokenConfig | undefined {
  if (!env.AUTH_ENTRA_TENANT_ID || !env.AUTH_ENTRA_CLIENT_ID) {
    return undefined;
  }
  return {
    tenantId: env.AUTH_ENTRA_TENANT_ID,
    clientId: env.AUTH_ENTRA_CLIENT_ID,
    scope: env.MCP_ENTRA_SCOPE,
    clientAppIds: env.MCP_CLIENT_APP_IDS,
  };
}

/**
 * Finds the wiki user with an email in the request's team, as signing in
 * through the forward-auth plugin matches them: case-insensitive equality.
 *
 * @param ctx the request context.
 * @param email the person's email, lower-cased.
 * @returns the user with their team, or null.
 */
async function findUser(ctx: Context, email: string) {
  const team = await getTeamFromContext(ctx, { includeOAuthState: false });
  if (!team) {
    return null;
  }

  return User.scope("withTeam").findOne({
    where: {
      [Op.and]: [
        Sequelize.where(Sequelize.fn("lower", Sequelize.col("email")), email),
      ],
      teamId: team.id,
    },
  });
}
