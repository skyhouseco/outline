import { createHash, timingSafeEqual } from "node:crypto";
import Koa from "koa";
import type { Context, Next } from "koa";
import bodyParser from "koa-body";
import Router from "@koa/router";
import { Scope } from "@shared/types";
import { toError } from "@shared/utils/error";
import Logger from "@server/logging/Logger";
import { createMcpServer } from "@server/mcp";
import { sequelize } from "@server/storage/database";
import { version as packageVersion } from "../../../package.json";
import env from "./env";
import {
  block,
  blockedPeople,
  claudeConnections,
  keyConnections,
  normalizeEmail,
  revokeKey,
  unblock,
  usage,
} from "./store";

/** The contract version served, see mcp-hub/docs/CONTRACT.md. */
export const ContractVersion = 1;

/** Where the contract is mounted. */
export const AdminPath = "/admin/mcp";

/** The widest usage window the hub may ask for, in days. */
const MaxUsageDays = 92;

/** Headers that claim to be a person, never trusted on these routes. */
const IdentityHeader =
  /^(x-auth-request-|x-forwarded-(email|user|groups|preferred-username)$)/i;

/** The routes served, to answer 405 rather than 404 for a wrong method. */
const RoutePaths = [
  "/health",
  "/usage",
  "/connections",
  "/keys/:keyId/revoke",
  "/people/:email/block",
  "/limits",
  "/limits/:key",
];

/**
 * Why a usage window is refused, or undefined.
 *
 * @param from the first day.
 * @param to the last day.
 * @returns the reason, or undefined when the window is valid.
 */
export function usageRangeProblem(
  from: unknown,
  to: unknown
): string | undefined {
  const start = parseDay(from);
  const end = parseDay(to);
  if (start === undefined || end === undefined) {
    return "from and to must both be days written YYYY-MM-DD.";
  }
  if (start > end) {
    return "from must be on or before to.";
  }
  if ((end - start) / 86_400_000 > MaxUsageDays) {
    return `from and to can be at most ${MaxUsageDays} days apart.`;
  }
  return undefined;
}

const router = new Router();

router.get("/health", async (ctx) => {
  // Every tool reads the database, so it decides whether calls can be served.
  let ok = true;
  try {
    await sequelize.query("SELECT 1");
  } catch (error) {
    Logger.warn("MCP hub health: database check failed", toError(error));
    ok = false;
  }

  ctx.body = {
    contract: ContractVersion,
    app: "wiki",
    version: env.VERSION?.slice(0, 12) || packageVersion,
    tools: toolCount(),
    ok,
  };
});

router.get("/usage", async (ctx) => {
  const { from, to } = ctx.query;
  const problem = usageRangeProblem(from, to);
  if (problem || typeof from !== "string" || typeof to !== "string") {
    ctx.status = 400;
    ctx.body = { error: problem ?? "from and to are required." };
    return;
  }

  ctx.body = { from, to, cost_unit: null, rows: await usage(from, to) };
});

router.get("/connections", async (ctx) => {
  const [keys, connectors, blocked] = await Promise.all([
    keyConnections(),
    claudeConnections(),
    blockedPeople(),
  ]);
  ctx.body = { connections: [...keys, ...connectors], blocked };
});

router.post("/keys/:keyId/revoke", requireActingAdmin, async (ctx) => {
  const admin: string = ctx.state.actingAdmin;
  const keyId = ctx.params.keyId;
  const result = await revokeKey(keyId, admin);
  if (!result) {
    ctx.status = 404;
    ctx.body = { error: "There is no API key with that id." };
    return;
  }
  if (!result.already) {
    Logger.info("plugins", "API key revoked via the MCP hub", {
      keyId,
      admin,
    });
  }
  ctx.body = { key_id: keyId, revoked: true, already: result.already };
});

router.post("/people/:email/block", requireActingAdmin, async (ctx) => {
  const email = normalizeEmail(ctx.params.email);
  if (!email) {
    ctx.status = 400;
    ctx.body = { error: "That is not an email address." };
    return;
  }
  const admin: string = ctx.state.actingAdmin;
  const changed = await block(email, admin);
  if (changed) {
    Logger.info("plugins", "MCP access blocked via the MCP hub", {
      email,
      admin,
    });
  }
  ctx.body = { email, blocked: true, already: !changed };
});

router.delete("/people/:email/block", requireActingAdmin, async (ctx) => {
  const email = normalizeEmail(ctx.params.email);
  if (!email) {
    ctx.status = 400;
    ctx.body = { error: "That is not an email address." };
    return;
  }
  const changed = await unblock(email);
  if (changed) {
    Logger.info("plugins", "MCP access unblocked via the MCP hub", {
      email,
      admin: ctx.state.actingAdmin,
    });
  }
  ctx.body = { email, blocked: false, already: !changed };
});

router.get("/limits", (ctx) => {
  ctx.body = { limits: [] };
});

router.put("/limits/:key", requireActingAdmin, noSuchLimit);
router.delete("/limits/:key", requireActingAdmin, noSuchLimit);

router.all(RoutePaths, (ctx) => {
  ctx.status = 405;
  ctx.body = { error: "That admin route does not take this method." };
});

router.all("{/*path}", (ctx) => {
  ctx.status = 404;
  ctx.body = { error: "There is no such admin route." };
});

const app = new Koa();

app.use(async (ctx, next) => {
  for (const name of Object.keys(ctx.req.headers)) {
    if (IdentityHeader.test(name)) {
      delete ctx.req.headers[name];
    }
  }

  // Admin data, no proxy or browser may keep a copy.
  ctx.set("Cache-Control", "no-store");

  const failure = gateFailure(ctx);
  if (failure) {
    ctx.status = failure.status;
    ctx.body = { error: failure.error };
    return;
  }

  try {
    await next();
  } catch (error) {
    const err = toError(error);
    const status =
      "status" in err && typeof err.status === "number" ? err.status : 500;
    if (status >= 500) {
      Logger.error("MCP hub request failed", err);
    }
    ctx.status = status;
    ctx.body = {
      error:
        status < 500
          ? err.message
          : "The wiki hit an error answering the hub. Try again shortly.",
    };
  }
});
app.use(bodyParser());
app.use(router.routes());

export default app;

/**
 * Parses a real UTC calendar day.
 *
 * @param value the raw value, YYYY-MM-DD.
 * @returns the day as epoch milliseconds, or undefined.
 */
function parseDay(value: unknown): number | undefined {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return undefined;
  }
  const time = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(time) &&
    new Date(time).toISOString().slice(0, 10) === value
    ? time
    : undefined;
}

/**
 * Why the request may not go further, or undefined.
 *
 * @param ctx the request context.
 * @returns the status and message to answer with.
 */
function gateFailure(
  ctx: Context
): { status: number; error: string } | undefined {
  const token = env.MCP_HUB_TOKEN;
  if (!token) {
    return { status: 404, error: "Not found." };
  }

  const match = /^Bearer\s+(.+)$/i.exec(ctx.get("authorization"));
  if (!match || !tokensMatch(match[1].trim(), token)) {
    return {
      status: 401,
      error: "The hub's token for the wiki is missing or wrong.",
    };
  }
  return undefined;
}

/**
 * Compares two secrets in constant time, whatever their length.
 *
 * @param given the token sent.
 * @param expected the configured token.
 * @returns true when they are equal.
 */
function tokensMatch(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * Requires the email of the admin making a change, kept for the audit trail.
 *
 * @param ctx the request context.
 * @param next the next middleware.
 */
async function requireActingAdmin(ctx: Context, next: Next) {
  const admin = normalizeEmail(ctx.get("x-acting-admin"));
  if (!admin) {
    ctx.status = 400;
    ctx.body = {
      error:
        "Changes need the X-Acting-Admin header with the email of the admin making them.",
    };
    return;
  }
  ctx.state.actingAdmin = admin;
  await next();
}

/**
 * Answers a change to a limit, the wiki has none.
 *
 * @param ctx the request context.
 */
function noSuchLimit(ctx: Context) {
  ctx.status = 404;
  ctx.body = { error: "The wiki has no limit with that key." };
}

/**
 * Counts the MCP tools available with every scope granted.
 *
 * @returns the number of tools.
 */
function toolCount(): number {
  const server = createMcpServer(env.URL, Object.values(Scope));

  // The SDK keeps registered tools in a private map and has no public count.
  const tools: unknown = Reflect.get(server, "_registeredTools");
  return tools && typeof tools === "object" ? Object.keys(tools).length : 0;
}
