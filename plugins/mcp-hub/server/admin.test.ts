import { faker } from "@faker-js/faker";
import { ApiKey } from "@server/models";
import { buildApiKey } from "@server/test/factories";
import {
  buildOAuthUser,
  callMcpTool,
  mcpHeaders,
  mcpRequest,
} from "@server/test/McpHelper";
import { getTestServer } from "@server/test/support";
import { usageRangeProblem } from "./admin";
import env from "./env";
import { isBlocked } from "./store";

const server = getTestServer();
const token = "hub-secret";
const admin = "admin@skyhouseagency.com";

/**
 * Requests an admin route as the hub.
 *
 * @param method the HTTP method.
 * @param path the path below /admin/mcp.
 * @param headers extra headers.
 * @returns the response.
 */
function hub(
  method: "get" | "post" | "put" | "delete",
  path: string,
  headers: Record<string, string> = {}
) {
  return server[method](`/admin/mcp${path}`, {
    headers: {
      authorization: `Bearer ${token}`,
      "x-acting-admin": admin,
      ...headers,
    },
  });
}

/**
 * Today as a UTC day.
 *
 * @returns the day, YYYY-MM-DD.
 */
function today() {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Waits for the usage of a person to show a call, tool calls are recorded
 * after the response is sent.
 *
 * @param email the person's email.
 * @returns the person's usage rows.
 */
async function waitForUsage(email: string) {
  for (let attempt = 0; attempt < 50; attempt++) {
    const res = await hub("get", `/usage?from=${today()}&to=${today()}`);
    const body = await res.json();
    const rows = body.rows.filter(
      (row: { email: string }) => row.email === email
    );
    if (rows.length) {
      return rows;
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return [];
}

beforeAll(() => {
  env.MCP_HUB_TOKEN = token;
});

afterAll(() => {
  env.MCP_HUB_TOKEN = undefined;
});

describe("/admin/mcp", () => {
  it("should answer 404 when no token is configured", async () => {
    env.MCP_HUB_TOKEN = undefined;
    try {
      const res = await hub("get", "/health");
      expect(res.status).toEqual(404);
    } finally {
      env.MCP_HUB_TOKEN = token;
    }
  });

  it("should refuse a wrong token", async () => {
    const res = await hub("get", "/health", { authorization: "Bearer nope" });
    expect(res.status).toEqual(401);
    expect((await res.json()).error).toBeTruthy();
  });

  it("should not cache answers", async () => {
    const res = await hub("get", "/health");
    expect(res.headers.get("cache-control")).toEqual("no-store");
  });

  it("should report health", async () => {
    const res = await hub("get", "/health");
    const body = await res.json();

    expect(res.status).toEqual(200);
    expect(body).toMatchObject({ contract: 1, app: "wiki", ok: true });
    expect(typeof body.version).toEqual("string");
    expect(body.tools).toBeGreaterThan(0);
  });

  it("should answer JSON 404 and 405", async () => {
    const missing = await hub("get", "/nope");
    expect(missing.status).toEqual(404);
    expect((await missing.json()).error).toBeTruthy();

    const wrongMethod = await hub("post", "/health");
    expect(wrongMethod.status).toEqual(405);
  });

  describe("usage", () => {
    it("should refuse an invalid window", async () => {
      const res = await hub("get", "/usage?from=2026-01-01&to=2026-06-01");
      expect(res.status).toEqual(400);
      expect(usageRangeProblem("2026-02-30", "2026-03-01")).toBeTruthy();
      expect(usageRangeProblem("2026-03-02", "2026-03-01")).toBeTruthy();
      expect(usageRangeProblem("2026-03-01", "2026-03-01")).toBeUndefined();
    });

    it("should count connector tool calls", async () => {
      const { user, accessToken } = await buildOAuthUser();
      await callMcpTool(server, accessToken, "list_users");
      await callMcpTool(server, accessToken, "list_users");

      const rows = await waitForUsage(user.email!);
      expect(rows).toEqual([
        expect.objectContaining({
          day: today(),
          email: user.email,
          tool: "list_users",
          via: "claude",
          failures: 0,
          cost: null,
        }),
      ]);
      expect(rows[0].calls).toBeGreaterThanOrEqual(1);
      expect(typeof rows[0].ms_p95).toEqual("number");
    });

    it("should not count tools that do not exist", async () => {
      const { user, accessToken } = await buildOAuthUser();
      await callMcpTool(server, accessToken, "made_up_tool");
      await callMcpTool(server, accessToken, "list_users");

      const rows = await waitForUsage(user.email!);
      expect(rows.map((row: { tool: string }) => row.tool)).toEqual([
        "list_users",
      ]);
    });

    it("should count API key calls and failures", async () => {
      const { user } = await buildOAuthUser();
      const key = await buildApiKey({ userId: user.id });
      await callMcpTool(server, key.value!, "fetch", {
        resource: "document",
        id: faker.string.uuid(),
      });

      const rows = await waitForUsage(user.email!);
      expect(rows).toEqual([
        expect.objectContaining({ tool: "fetch", via: "key", failures: 1 }),
      ]);
    });
  });

  describe("connections", () => {
    it("should list keys and connector users", async () => {
      const { user, accessToken } = await buildOAuthUser();
      const key = await buildApiKey({ userId: user.id });
      await callMcpTool(server, accessToken, "list_users");
      await waitForUsage(user.email!);

      const res = await hub("get", "/connections");
      const body = await res.json();

      expect(body.connections).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            via: "key",
            email: user.email,
            key_id: key.id,
            key_prefix: `ol_api_…${key.last4}`,
            revoked_at: null,
          }),
          expect.objectContaining({ via: "claude", email: user.email }),
        ])
      );
      expect(JSON.stringify(body)).not.toContain(key.value);
    });

    it("should revoke a key once", async () => {
      const key = await buildApiKey();

      const first = await hub("post", `/keys/${key.id}/revoke`);
      expect(await first.json()).toEqual({
        key_id: key.id,
        revoked: true,
        already: false,
      });
      expect(await ApiKey.findByPk(key.id)).toBeNull();

      const second = await hub("post", `/keys/${key.id}/revoke`);
      expect((await second.json()).already).toEqual(true);
    });

    it("should answer 404 for an unknown key", async () => {
      const res = await hub("post", `/keys/${faker.string.uuid()}/revoke`);
      expect(res.status).toEqual(404);
    });

    it("should require the acting admin on changes", async () => {
      const key = await buildApiKey();
      const res = await hub("post", `/keys/${key.id}/revoke`, {
        "x-acting-admin": "",
      });
      expect(res.status).toEqual(400);
    });
  });

  describe("blocking", () => {
    it("should refuse MCP calls from a blocked person", async () => {
      const { user, accessToken } = await buildOAuthUser();
      const path = `/people/${encodeURIComponent(user.email!.toUpperCase())}/block`;

      const blocked = await hub("post", path);
      expect(await blocked.json()).toEqual({
        email: user.email,
        blocked: true,
        already: false,
      });
      expect(await isBlocked(user.email!)).toEqual(true);

      const { body } = mcpRequest("tools/list");
      const refused = await server.post("/mcp/", {
        headers: mcpHeaders(accessToken),
        body,
      });
      expect(refused.status).toEqual(403);
      expect(JSON.stringify(await refused.json())).toContain(
        "turned off by an admin"
      );

      const list = await hub("get", "/connections");
      expect((await list.json()).blocked).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ email: user.email, blocked_by: admin }),
        ])
      );

      const again = await hub("post", path);
      expect((await again.json()).already).toEqual(true);

      const unblocked = await hub("delete", path);
      expect(await unblocked.json()).toEqual({
        email: user.email,
        blocked: false,
        already: false,
      });

      const allowed = await server.post("/mcp/", {
        headers: mcpHeaders(accessToken),
        body: mcpRequest("tools/list").body,
      });
      expect(allowed.status).toEqual(200);
    });
  });

  describe("limits", () => {
    it("should have none", async () => {
      const res = await hub("get", "/limits");
      expect(await res.json()).toEqual({ limits: [] });

      const change = await hub("put", "/limits/daily_spend");
      expect(change.status).toEqual(404);
    });
  });
});
