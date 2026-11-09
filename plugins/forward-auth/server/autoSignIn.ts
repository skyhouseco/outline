import type { Context } from "koa";
import { getUserForJWT } from "@server/utils/jwt";
import config from "../plugin.json";

/** The proxy header that identifies the visitor. */
export const EmailHeader = "x-auth-request-email";

/** Set while a sign-in started by a page request is in progress. */
const AttemptCookie = "forwardAuthAttempt";

/** How long a page request waits before it starts another sign-in. */
const AttemptSeconds = 30;

/** App paths that must load without signing in first. */
const ExcludedPaths = ["/desktop-redirect"];

/**
 * Returns the URL to sign in at when a page is requested through the proxy
 * without an Outline session, so the visitor does not see the login page.
 *
 * Requests with a `notice` or `logout` parameter are left alone, a failed
 * sign-in redirects with a notice and must not start another one. A short
 * lived cookie also stops repeated attempts, in case the session cookie is
 * not stored.
 *
 * @param ctx the request context.
 * @returns the sign-in URL, or undefined to serve the app.
 */
export async function autoSignInUrl(ctx: Context): Promise<string | undefined> {
  if (ctx.method !== "GET" || !ctx.request.get(EmailHeader)) {
    return undefined;
  }
  if (
    ctx.query.notice ||
    ctx.query.logout ||
    ExcludedPaths.includes(ctx.path)
  ) {
    return undefined;
  }
  if (ctx.cookies.get(AttemptCookie) || (await hasSession(ctx))) {
    return undefined;
  }

  ctx.cookies.set(AttemptCookie, "1", {
    httpOnly: true,
    sameSite: "lax",
    maxAge: AttemptSeconds * 1000,
  });

  const url = `/auth/${config.id}`;
  return ctx.path === "/"
    ? url
    : `${url}?path=${encodeURIComponent(ctx.originalUrl)}`;
}

/**
 * Ends the sign-in attempt started by a page request, once the user has a
 * session.
 *
 * @param ctx the request context.
 */
export function clearAutoSignInAttempt(ctx: Context) {
  ctx.cookies.set(AttemptCookie, null);
}

/**
 * Returns a path that is safe to redirect to after signing in, only paths on
 * this host are allowed.
 *
 * @param value the requested path.
 * @returns the path, or undefined when it is missing or not safe.
 */
export function safeReturnPath(value: unknown): string | undefined {
  if (typeof value !== "string" || !value.startsWith("/")) {
    return undefined;
  }
  if (value.startsWith("//") || value.includes("\\")) {
    return undefined;
  }
  return value;
}

/**
 * Whether the request has a valid Outline session.
 *
 * @param ctx the request context.
 * @returns true when the session cookie belongs to an active user.
 */
async function hasSession(ctx: Context): Promise<boolean> {
  const token = ctx.cookies.get("accessToken");

  if (!token) {
    return false;
  }

  try {
    await getUserForJWT(token, ["session"]);
    return true;
  } catch {
    return false;
  }
}
