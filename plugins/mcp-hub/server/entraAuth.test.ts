import { generateKeyPairSync, type KeyObject, randomUUID } from "node:crypto";
import JWT from "jsonwebtoken";
import Koa from "koa";
import mount from "koa-mount";
import { http, HttpResponse } from "msw";
import { QueryTypes } from "sequelize";
import serverEnv from "@server/env";
import { defaultRateLimiter } from "@server/middlewares/rateLimiter";
import type { User } from "@server/models";
import { UserFlag } from "@server/models/User";
import onerror from "@server/onerror";
import webService from "@server/services/web";
import { sequelize } from "@server/storage/database";
import Redis from "@server/storage/redis";
import {
  buildApiKey,
  buildOAuthAuthentication,
  buildSubdomain,
  buildTeam,
  buildUser,
} from "@server/test/factories";
import {
  mcpHeaders,
  mcpRequest,
  parseMcpResponse,
} from "@server/test/McpHelper";
import { server as msw } from "@server/test/msw";
import { getTestServer } from "@server/test/support";
import TestServer from "@server/test/TestServer";
import RateLimiter from "@server/utils/RateLimiter";
import { Scope } from "@shared/types";
import env from "./env";
import { entraIssuer, entraKeysUrl } from "./entraToken";

const server = getTestServer();
const tenantId = "aa08167d-feb6-4390-9e0a-d8744267dcb4";
const clientId = "e10e22d5-dc15-43a8-afba-1e044eb2a72e";
const claudeClient = "967d3a14-9da0-43d4-8031-8d1185a9bda7";
const signing = generateKeyPairSync("rsa", { modulusLength: 2048 });

/**
 * Exports a private key for jsonwebtoken.
 *
 * @param key the private key.
 * @returns the key in PEM.
 */
function pem(key: KeyObject) {
  return key.export({ type: "pkcs8", format: "pem" });
}

/**
 * Signs an access token like Entra would for the MCP hub.
 *
 * @param email the person's email.
 * @param claims claims to add or replace.
 * @returns the token.
 */
function entraToken(
  email: string,
  claims: Record<string, unknown> = {}
): string {
  const now = Math.floor(Date.now() / 1000);
  return JWT.sign(
    {
      iss: entraIssuer(tenantId),
      aud: clientId,
      tid: tenantId,
      azp: claudeClient,
      scp: "hub.mcp.access wiki.mcp.access",
      email,
      ver: "2.0",
      nbf: now - 60,
      exp: now + 3600,
      ...claims,
    },
    pem(signing.privateKey),
    { algorithm: "RS256", keyid: "k1", noTimestamp: true }
  );
}

/**
 * Builds a user in a team with its own subdomain, so the request finds the
 * team by its host as it would in production.
 *
 * @param overrides user attributes.
 * @returns the user and the host to send requests to.
 */
async function buildEntraUser(overrides: Partial<User> = {}) {
  const subdomain = buildSubdomain();
  const team = await buildTeam({ subdomain });
  const user = await buildUser({ teamId: team.id, ...overrides });
  return { user, team, host: `${subdomain}.outline.dev` };
}

/**
 * Sends an MCP request with a bearer token.
 *
 * @param host the host of the team.
 * @param token the bearer token.
 * @param method the JSON-RPC method.
 * @param params the JSON-RPC params.
 * @returns the response.
 */
function mcp(
  host: string,
  token: string,
  method = "tools/list",
  params?: Record<string, unknown>
) {
  return server.post("/mcp/", {
    headers: { ...mcpHeaders(token), host },
    body: mcpRequest(method, params).body,
  });
}

/**
 * Waits for the tool calls recorded for a user, they are recorded after the
 * response is sent.
 *
 * @param userId the user id.
 * @returns the recorded calls.
 */
async function waitForCalls(userId: string) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const rows = await sequelize.query<{
      email: string;
      tool: string;
      via: string;
    }>(`SELECT email, tool, via FROM mcp_tool_calls WHERE "userId" = $userId`, {
      bind: { userId },
      type: QueryTypes.SELECT,
    });
    if (rows.length) {
      return rows;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return [];
}

beforeEach(() => {
  env.AUTH_ENTRA_TENANT_ID = tenantId;
  env.AUTH_ENTRA_CLIENT_ID = clientId;
  msw.use(
    http.get(entraKeysUrl(tenantId), () =>
      HttpResponse.json({
        keys: [{ ...signing.publicKey.export({ format: "jwk" }), kid: "k1" }],
      })
    )
  );
});

afterAll(() => {
  env.AUTH_ENTRA_TENANT_ID = undefined;
  env.AUTH_ENTRA_CLIENT_ID = undefined;
});

describe("POST /mcp/ with a Microsoft access token", () => {
  it("should reach the MCP server as the existing user", async () => {
    const { user, host } = await buildEntraUser();
    const token = entraToken(user.email!.toUpperCase());

    const list = await mcp(host, token);
    expect(list.status).toEqual(200);
    const listed = (await parseMcpResponse(list))?.result as {
      tools: { name: string }[];
    };
    expect(listed.tools.map((tool) => tool.name)).toEqual(
      expect.arrayContaining(["list_users", "create_document"])
    );

    const call = await mcp(host, token, "tools/call", {
      name: "list_users",
      arguments: { query: user.name },
    });
    expect(call.status).toEqual(200);
    const called = (await parseMcpResponse(call))?.result as {
      isError?: boolean;
      content: { text: string }[];
    };
    expect(called.isError).toBeFalsy();
    expect(called.content[0].text).toContain(user.id);

    await user.reload();
    expect(user.getFlag(UserFlag.MCP)).toEqual(1);
    expect(await waitForCalls(user.id)).toEqual([
      { email: user.email, tool: "list_users", via: "claude" },
    ]);
  });

  it("should refuse a person without a wiki account with a 403", async () => {
    const { host } = await buildEntraUser();
    const res = await mcp(host, entraToken("Nobody@SkyHouse.ai"));

    expect(res.status).toEqual(403);
    expect(await res.json()).toEqual({
      error: `There is no wiki account for nobody@skyhouse.ai yet. Sign in to the wiki once at ${serverEnv.URL}, then try again.`,
    });
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("should refuse a person who was invited but never signed in", async () => {
    const { user, host } = await buildEntraUser({ lastActiveAt: null });
    const res = await mcp(host, entraToken(user.email!));

    expect(res.status).toEqual(403);
    expect((await res.json()).error).toContain(
      `There is no wiki account for ${user.email} yet.`
    );
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("should not find a user from another team", async () => {
    const { user } = await buildEntraUser();
    const { host } = await buildEntraUser();
    const res = await mcp(host, entraToken(user.email!));

    expect(res.status).toEqual(403);
    expect((await res.json()).error).toContain(
      `There is no wiki account for ${user.email} yet.`
    );
  });

  it("should refuse a suspended user with a 403", async () => {
    const { user, host } = await buildEntraUser({ suspendedAt: new Date() });
    const res = await mcp(host, entraToken(user.email!));

    expect(res.status).toEqual(403);
    expect(await res.json()).toEqual({
      error:
        "Your wiki account is suspended. Ask a wiki admin to restore it, then try again.",
    });
    expect(res.headers.get("www-authenticate")).toBeNull();
  });

  it("should refuse a token without the wiki's scope", async () => {
    const { user, host } = await buildEntraUser();
    const res = await mcp(
      host,
      entraToken(user.email!, { scp: "hub.mcp.access" })
    );

    expect(res.status).toEqual(401);
    expect((await res.json()).message).toContain("missing scope");
    expect(res.headers.get("www-authenticate")).toContain(
      "/.well-known/oauth-protected-resource/mcp"
    );
  });

  it("should refuse a token signed with another key", async () => {
    const { user, host } = await buildEntraUser();
    const forged = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const token = JWT.sign(
      JWT.decode(entraToken(user.email!)) ?? {},
      pem(forged.privateKey),
      { algorithm: "RS256", keyid: "k1" }
    );
    const res = await mcp(host, token);

    expect(res.status).toEqual(401);
  });

  it("should refuse Microsoft tokens when Entra sign-in is off", async () => {
    env.AUTH_ENTRA_TENANT_ID = undefined;
    env.AUTH_ENTRA_CLIENT_ID = undefined;
    const { user, host } = await buildEntraUser();
    const res = await mcp(host, entraToken(user.email!));

    expect(res.status).toEqual(401);
  });

  it("should not accept the token on the rest of the API", async () => {
    const { user, host } = await buildEntraUser();
    const res = await server.post("/api/auth.info", {
      headers: {
        host,
        Authorization: `Bearer ${entraToken(user.email!)}`,
      },
    });

    expect(res.status).toEqual(401);
  });

  it("should still accept Outline's own tokens", async () => {
    const { user, host } = await buildEntraUser();
    const oauth = await buildOAuthAuthentication({
      user,
      scope: [Scope.Read, Scope.Write],
    });
    const apiKey = await buildApiKey({ userId: user.id });

    expect((await mcp(host, oauth.accessToken!)).status).toEqual(200);
    expect((await mcp(host, apiKey.value!)).status).toEqual(200);
  });
});

describe("rate limits on /mcp with a Microsoft access token", () => {
  // The default rate limiter runs in front of every service, as in main.ts.
  const app = new Koa();
  onerror(app);
  app.use(defaultRateLimiter());
  app.use(mount(webService()));
  const limited = new TestServer(app);
  const enabled = serverEnv.RATE_LIMITER_ENABLED;

  /**
   * Sends an MCP request through the rate limited server.
   *
   * @param host the host of the team.
   * @param token the bearer token.
   * @returns the response.
   */
  function limitedMcp(host: string, token: string) {
    return limited.post("/mcp/", {
      headers: { ...mcpHeaders(token), host },
      body: mcpRequest("tools/list").body,
    });
  }

  beforeEach(() => {
    serverEnv.RATE_LIMITER_ENABLED = true;

    // Two requests a minute for this test only, in its own keys.
    RateLimiter.setRateLimiter("/mcp", {
      points: 2,
      duration: 60,
      keyPrefix: `rl-test-${randomUUID()}`,
      storeClient: Redis.ephemeralClient,
    });
  });

  afterEach(() => {
    serverEnv.RATE_LIMITER_ENABLED = enabled;
    RateLimiter.rateLimiterMap.delete("/mcp");
  });

  afterAll(() => limited.close());

  it("should limit each person on their own, not the address they share", async () => {
    const { user, team, host } = await buildEntraUser();
    const other = await buildUser({ teamId: team.id });
    const token = entraToken(user.email!);

    expect((await limitedMcp(host, token)).status).toEqual(200);
    expect((await limitedMcp(host, token)).status).toEqual(200);
    expect((await limitedMcp(host, token)).status).toEqual(429);

    // Same address, another person: their own bucket.
    const otherToken = entraToken(other.email!);
    expect((await limitedMcp(host, otherToken)).status).toEqual(200);
    expect((await limitedMcp(host, otherToken)).status).toEqual(200);
    expect((await limitedMcp(host, otherToken)).status).toEqual(429);
  });

  it("should limit tokens that fail the checks by address", async () => {
    const { user, host } = await buildEntraUser();
    const bad = (scp: string) =>
      limitedMcp(host, entraToken(user.email!, { scp }));

    expect((await bad("one.scope")).status).toEqual(401);
    expect((await bad("another.scope")).status).toEqual(401);
    expect((await bad("third.scope")).status).toEqual(429);

    // The address is used up, the person's own bucket is not.
    expect((await limitedMcp(host, entraToken(user.email!))).status).toEqual(
      200
    );
  });
});
