import Router from "@koa/router";
import JWT from "jsonwebtoken";
import type { Context } from "koa";
import { Client, UserRole } from "@shared/types";
import { slugifyDomain } from "@shared/utils/domains";
import { parseEmail } from "@shared/utils/email";
import { toError } from "@shared/utils/error";
import { UserRoleHelper } from "@shared/utils/UserRoleHelper";
import accountProvisioner from "@server/commands/accountProvisioner";
import { createContext } from "@server/context";
import Logger from "@server/logging/Logger";
import { Team, User } from "@server/models";
import { sequelize } from "@server/storage/database";
import { signIn } from "@server/utils/authentication";
import { getTeamFromContext } from "@server/utils/passport";
import config from "../../plugin.json";
import env from "../env";
import { parseRoles, resolveRole } from "../roles";

const router = new Router();

/** The identity headers set by the proxy, see oauth2-proxy `--set-xauthrequest`. */
const Headers = {
  email: "x-auth-request-email",
  roles: "x-auth-request-groups",
  userId: "x-auth-request-user",
  authorization: "authorization",
};

interface IdTokenClaims {
  name?: string;
  given_name?: string;
  family_name?: string;
}

/**
 * Signs the user in from the proxy's identity headers. The proxy has already
 * authenticated the request before it reaches Outline.
 */
router.get(config.id, async (ctx: Context) => {
  const email = ctx.request.get(Headers.email).trim().toLowerCase();

  if (!email) {
    Logger.warn("Forward auth request is missing the email header");
    return ctx.redirect("/?notice=auth-error");
  }

  const proxyRoles = parseRoles(ctx.request.get(Headers.roles));
  const mapping = {
    admin: env.FORWARD_AUTH_ADMIN_ROLES,
    member: env.FORWARD_AUTH_MEMBER_ROLES,
    viewer: env.FORWARD_AUTH_VIEWER_ROLES,
  };

  if (resolveRole(proxyRoles, mapping) === null) {
    Logger.info("authentication", "Forward auth user has no allowed role", {
      email,
      proxyRoles,
    });
    return ctx.redirect("/?notice=invalid-authentication");
  }

  try {
    const { local, domain } = parseEmail(email);
    // Identity only ever comes from the X-Auth-Request-* headers, the ID token
    // may not have been set by the proxy and is only used for the name.
    const claims = decodeIdToken(ctx.request.get(Headers.authorization));
    const name =
      claims.name ||
      [claims.given_name, claims.family_name].filter(Boolean).join(" ") ||
      local;
    const profileId = ctx.request.get(Headers.userId) || email;
    const team = await getTeamFromContext(ctx);

    // No actor is passed, an existing Outline session must never decide which
    // account the proxy's identity signs in to.
    const result = await accountProvisioner(createContext({ ip: ctx.ip }), {
      team: {
        teamId: team?.id,
        name: env.APP_NAME,
        domain,
        subdomain: slugifyDomain(domain),
      },
      user: {
        name,
        email,
        emailVerified: true,
      },
      authenticationProvider: {
        name: config.id,
        providerId: config.id,
      },
      authentication: {
        providerId: profileId,
        scopes: [],
      },
    });

    // Suspended accounts are refused by signIn, their role is left alone.
    const role = resolveRole(proxyRoles, mapping, result.user.role);
    if (role && !result.user.isSuspended) {
      await syncRole(result.user, role, ctx.ip);
    }

    const client =
      ctx.query.client === Client.Desktop ? Client.Desktop : Client.Web;
    return signIn(ctx, config.id, { ...result, client });
  } catch (err) {
    const error = toError(err);
    const id = "id" in error && typeof error.id === "string" ? error.id : null;

    if (id) {
      Logger.warn(`Forward auth sign-in refused: ${error.message}`, { email });
      return ctx.redirect(`/?notice=${id.replace(/_/g, "-")}`);
    }

    Logger.error("Forward auth sign-in failed", error, { email });
    return ctx.redirect("/?notice=auth-error");
  }
});

/**
 * Ends the session at the proxy, which signs the user out of every tool behind
 * it. Outline's own session is removed by the client before it arrives here.
 */
router.get(`${config.id}.logout`, (ctx: Context) => {
  const url = env.FORWARD_AUTH_LOGOUT_URL;
  const separator = url.includes("?") ? "&" : "?";
  ctx.redirect(`${url}${separator}rd=${encodeURIComponent(env.URL)}`);
});

/**
 * Reads the profile claims from the ID token the proxy forwards, if any. The
 * signature is not verified, so the claims must only be used for display and
 * never to identify the user.
 *
 * @param header the Authorization header value.
 * @returns the decoded claims, or an empty object.
 */
function decodeIdToken(header: string): IdTokenClaims {
  const [scheme, token] = header.split(" ");

  if (!token || !/^Bearer$/i.test(scheme)) {
    return {};
  }

  const decoded = JWT.decode(token);

  if (!decoded || typeof decoded !== "object") {
    return {};
  }

  const claim = (key: keyof IdTokenClaims) =>
    typeof decoded[key] === "string" ? decoded[key] : undefined;

  return {
    name: claim("name"),
    given_name: claim("given_name"),
    family_name: claim("family_name"),
  };
}

/**
 * Updates the user's workspace role to match the proxy. The last active admin
 * is never demoted, so the workspace cannot be left without an admin.
 *
 * @param user the signed in user.
 * @param role the role resolved from the proxy.
 * @param ip the request IP address, recorded on the event.
 */
async function syncRole(user: User, role: UserRole, ip: string) {
  if (user.role === role) {
    return;
  }

  await sequelize.transaction(async (transaction) => {
    // Lock the team first so concurrent role changes are serialized and the
    // admin count below cannot be stale, as in users.update_role.
    await Team.findByPk(user.teamId, {
      transaction,
      lock: transaction.LOCK.UPDATE,
      rejectOnEmpty: true,
    });
    const locked = await User.findByPk(user.id, {
      transaction,
      lock: transaction.LOCK.UPDATE,
      rejectOnEmpty: true,
    });

    if (locked.role === role) {
      return;
    }

    if (locked.role === UserRole.Admin) {
      const admins = await User.count({
        where: {
          teamId: locked.teamId,
          role: UserRole.Admin,
          suspendedAt: null,
        },
        transaction,
      });

      if (admins <= 1) {
        Logger.warn("Forward auth kept the last admin's role", {
          userId: locked.id,
          role,
        });
        return;
      }
    }

    const name = UserRoleHelper.canPromote(locked, role) ? "promote" : "demote";
    await locked.updateWithCtx(
      createContext({ user: locked, ip, transaction }),
      { role },
      { name }
    );
  });

  await user.reload();
}

export default router;
