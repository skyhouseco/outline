import Koa from "koa";
import bodyParser from "koa-body";
import Router from "@koa/router";
import { Readable } from "node:stream";
import type { Context, Next } from "koa";
import {
  createMcpHandler,
  type McpServerFactory,
  ProtocolErrorCode,
} from "@modelcontextprotocol/server";
import { toError } from "@shared/utils/error";
import { TeamPreference } from "@shared/types";
import env from "@server/env";
import { NotFoundError } from "@server/errors";
import Logger from "@server/logging/Logger";
import { createMcpServer } from "@server/mcp";
import auth from "@server/middlewares/authentication";
import { rateLimiter } from "@server/middlewares/rateLimiter";
import requestTracer from "@server/middlewares/requestTracer";
import type { User } from "@server/models";
import { UserFlag } from "@server/models/User";
import { AuthenticationType, type APIContext } from "@server/types";
import { OAuthHelper } from "@server/utils/oauth/OAuthHelper";
import { Hook, PluginManager } from "@server/utils/PluginManager";
import { RateLimiterStrategy } from "@server/utils/RateLimiter";

const app = new Koa();
const router = new Router();

// Connection-level headers that Node must set itself, see RFC 9110 §7.6.1.
const hopByHopHeaders = new Set([
  "connection",
  "keep-alive",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

interface McpAuthExtra {
  user: User;
  scope: string[];
  ip: string;
  origin: string;
}

/**
 * Reports transport errors. These are client-side 4xx conditions (bad Accept
 * header, etc) that the SDK already answers, so warn keeps visibility without
 * reporting client mistakes to Sentry.
 *
 * @param error - the error to report.
 */
function handleTransportError(error: Error) {
  // Clients probe with their latest version and fall back on this error.
  if (error.message.includes("Unsupported protocol version")) {
    return;
  }
  Logger.warn("MCP transport error", error);
}

/**
 * Builds a fresh MCP server for one request, from the auth info set by the route.
 *
 * @param context - the request context with the auth info.
 * @returns a configured MCP server.
 */
const createServer: McpServerFactory = ({ authInfo }) => {
  const extra = authInfo?.extra as McpAuthExtra | undefined;
  if (!extra) {
    throw new Error("MCP request is missing auth info");
  }
  return createMcpServer(
    extra.origin,
    extra.scope,
    extra.user.team.guidanceMCP ?? undefined
  );
};

// Plain JSON replies for 2026-era clients, which reverse proxies handle more
// reliably than SSE. The SDK still replies to 2025-era clients over SSE.
const mcpHandler = createMcpHandler(createServer, {
  responseMode: "json",
  onerror: handleTransportError,
});

/**
 * Rejects browser requests from origins other than the app or the team's own
 * subdomain or custom domain. Requests without an Origin header pass.
 *
 * @param ctx - the authenticated Koa context.
 * @param next - the next middleware.
 */
async function validateOrigin(ctx: APIContext, next: Next) {
  const { user } = ctx.state.auth;
  const origin = ctx.get("origin");
  const allowedOrigins = [
    new URL(env.URL).origin,
    new URL(user.team.url).origin,
  ];
  if (origin && !allowedOrigins.includes(origin)) {
    ctx.status = 403;
    ctx.body = {
      jsonrpc: "2.0",
      error: { code: -32000, message: `Invalid Origin: ${origin}` },
      id: null,
    };
    return;
  }
  return next();
}

/**
 * Converts the Koa request to a web request. The body is not copied, as the
 * SDK reads the parsed body instead.
 *
 * @param ctx - the Koa context.
 * @returns the web request.
 */
function toWebRequest(ctx: Context): Request {
  const headers = new Headers();
  for (const [key, value] of Object.entries(ctx.req.headers)) {
    for (const item of Array.isArray(value) ? value : [value ?? ""]) {
      headers.append(key, item);
    }
  }
  return new Request(ctx.request.URL, { method: ctx.method, headers });
}

// RFC 9728 / MCP auth spec: 401 responses from the /mcp endpoint must include
// a WWW-Authenticate header pointing at the OAuth protected resource metadata
// document, and the scopes to request, so clients can bootstrap authorization.
app.use(async (ctx, next) => {
  try {
    await next();
  } catch (err: unknown) {
    if (
      typeof err === "object" &&
      err !== null &&
      (err as { status?: number }).status === 401
    ) {
      const headersHost = err as { headers?: Record<string, string> };
      const existingHeaders = headersHost.headers ?? {};
      const hasWwwAuth = Object.keys(existingHeaders).some(
        (k) => k.toLowerCase() === "www-authenticate"
      );
      if (!hasWwwAuth) {
        headersHost.headers = {
          ...existingHeaders,
          "WWW-Authenticate": OAuthHelper.mcpBearerChallenge(
            OAuthHelper.getIssuer(ctx)
          ),
        };
      }
    }
    throw err;
  }
});

router.post(
  "/",
  rateLimiter(RateLimiterStrategy.OneThousandPerHour),
  auth({
    type: [
      AuthenticationType.MCP,
      AuthenticationType.OAUTH,
      AuthenticationType.API,
    ],
  }),
  validateOrigin,
  async (ctx) => {
    const { user, token, scope, type } = ctx.state.auth;

    if (!user.team.getPreference(TeamPreference.MCP)) {
      throw NotFoundError();
    }

    const hooks = PluginManager.getHooks(Hook.MCP);
    for (const hook of hooks) {
      const message = await hook.value.refuse?.(user);
      if (message) {
        ctx.status = 403;
        ctx.body = {
          jsonrpc: "2.0",
          error: { code: -32000, message },
          id: null,
        };
        return;
      }
    }

    user.setFlag(UserFlag.MCP);
    await user.save({ hooks: false });

    const extra: McpAuthExtra = {
      user,
      scope: scope ?? [],
      ip: ctx.request.ip,
      origin: OAuthHelper.getIssuer(ctx),
    };
    const options = {
      authInfo: {
        token,
        clientId: "",
        scopes: scope ?? [],
        extra: { ...extra },
      },
      parsedBody: ctx.request.body,
    };
    const request = toWebRequest(ctx);

    // The SDK answers known protocol failures itself with a 4xx and a
    // JSON-RPC body. Anything that escapes here is unexpected.
    try {
      const startedAt = Date.now();
      const response = await mcpHandler.fetch(request, options);
      const tool = toolCallName(ctx.request.body);

      if (tool && type && hooks.some((hook) => hook.value.onToolCall)) {
        void reportToolCall(response.clone(), {
          user,
          tool,
          authType: type,
          startedAt,
        });
      }

      ctx.status = response.status;
      response.headers.forEach((value, key) => {
        if (!hopByHopHeaders.has(key)) {
          ctx.set(key, value);
        }
      });
      ctx.body = response.body ? Readable.from(response.body) : "";
    } catch (error) {
      Logger.error(
        "MCP request handling failed",
        toError(error),
        undefined,
        ctx.req
      );

      ctx.status = 500;
      ctx.body = {
        jsonrpc: "2.0",
        error: {
          code: ProtocolErrorCode.InternalError,
          message: "Internal server error",
        },
        id: null,
      };
    }
  }
);

/**
 * Returns the tool name when the request body is a single tools/call request.
 *
 * @param body - the parsed request body.
 * @returns the tool name, or undefined for any other request.
 */
function toolCallName(body: unknown): string | undefined {
  if (!body || typeof body !== "object" || !("method" in body)) {
    return undefined;
  }
  if (body.method !== "tools/call" || !("params" in body)) {
    return undefined;
  }
  const { params } = body;
  return params &&
    typeof params === "object" &&
    "name" in params &&
    typeof params.name === "string"
    ? params.name
    : undefined;
}

/**
 * Whether a JSON-RPC response reports an error, either as a protocol error or
 * as a tool result with isError.
 *
 * @param text - the response body, JSON or server-sent events.
 * @returns true when any message in the body is an error.
 */
function responseFailed(text: string): boolean {
  const payloads = text.trimStart().startsWith("{")
    ? [text]
    : text
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length));

  return payloads.some((payload) => {
    try {
      const message: unknown = JSON.parse(payload);
      if (!message || typeof message !== "object") {
        return false;
      }
      if ("error" in message) {
        return true;
      }
      return (
        "result" in message &&
        !!message.result &&
        typeof message.result === "object" &&
        "isError" in message.result &&
        message.result.isError === true
      );
    } catch {
      return false;
    }
  });
}

/**
 * Reports a tool call to the MCP plugins once its response has been read,
 * which for streamed responses is when the tool has finished.
 *
 * @param response - a copy of the response sent to the client.
 * @param call - the call details.
 */
async function reportToolCall(
  response: Response,
  call: {
    user: User;
    tool: string;
    authType: AuthenticationType;
    startedAt: number;
  }
) {
  try {
    const text = await response.text();
    const ok = response.ok && !responseFailed(text);
    const durationMs = Date.now() - call.startedAt;

    for (const hook of PluginManager.getHooks(Hook.MCP)) {
      await hook.value.onToolCall?.({
        user: call.user,
        tool: call.tool,
        authType: call.authType,
        ok,
        durationMs,
      });
    }
  } catch (error) {
    Logger.warn("MCP tool call could not be reported", toError(error));
  }
}

router.get("/", async (ctx) => {
  ctx.status = 405;
  ctx.set("Allow", "POST");
  ctx.body = { error: "Method not allowed. Use POST for MCP requests." };
});

router.delete("/", async (ctx) => {
  ctx.status = 405;
  ctx.set("Allow", "POST");
  ctx.body = { error: "Method not allowed. Use POST for MCP requests." };
});

// Clients probing for a transport we do not implement, such as the legacy
// HTTP+SSE endpoints, must not fall through to the application shell
router.all("{/*path}", async (ctx) => {
  ctx.status = 404;
  ctx.body = { error: "Not found. MCP requests must be sent to /mcp." };
});

app.use(requestTracer());
app.use(bodyParser());
app.use(router.routes());

export default app;
