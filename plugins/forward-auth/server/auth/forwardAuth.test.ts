// @vitest-isolate true
import { faker } from "@faker-js/faker";
import JWT from "jsonwebtoken";
import { UserRole } from "@shared/types";
import { User } from "@server/models";
import {
  buildAdmin,
  buildSubdomain,
  buildTeam,
  buildUser,
} from "@server/test/factories";
import { Hook, PluginManager } from "@server/utils/PluginManager";
import config from "../../plugin.json";
import { autoSignInUrl } from "../autoSignIn";
import env from "../env";
import router from "./forwardAuth";

// The plugin is off by default, so other tests do not see an extra provider.
// It must be registered before the auth routes are loaded with the server.
env.FORWARD_AUTH_ENABLED = true;
env.FORWARD_AUTH_ADMIN_ROLES = ["outline-admins"];
env.FORWARD_AUTH_MEMBER_ROLES = ["outline-users"];
env.FORWARD_AUTH_VIEWER_ROLES = ["outline-viewers"];
PluginManager.add({
  ...config,
  type: Hook.AuthProvider,
  value: { router, id: config.id, autoSignInUrl },
});

const { getTestServer } = await import("@server/test/support");
const server = getTestServer();

/**
 * Builds a team that uses the forward-auth provider, as the proxy would create.
 *
 * @returns the team and the host to send requests to.
 */
async function buildForwardAuthTeam() {
  const subdomain = buildSubdomain();
  const team = await buildTeam({
    subdomain,
    authenticationProviders: [
      { name: "forward-auth", providerId: "forward-auth" },
    ],
  });
  return { team, host: `${subdomain}.outline.dev` };
}

/**
 * Requests the forward-auth sign-in route with the given proxy headers.
 *
 * @param host the host of the team.
 * @param headers the identity headers the proxy would set.
 * @returns the response.
 */
function signIn(host: string, headers: Record<string, string>) {
  return server.get("/auth/forward-auth", {
    redirect: "manual",
    headers: { host, ...headers },
  });
}

/**
 * Returns the path and query a response redirects to.
 *
 * @param res the response.
 * @returns the redirect path and query.
 */
function location(res: { headers: { get(name: string): string | null } }) {
  const url = new URL(res.headers.get("location") ?? "", "http://localhost");
  return `${url.pathname}${url.search}`;
}

describe("forward-auth", () => {
  it("should refuse a request without the email header", async () => {
    const { host } = await buildForwardAuthTeam();
    const res = await signIn(host, {});

    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).toContain("notice=auth-error");
  });

  it("should create a user with the role from the proxy", async () => {
    const { team, host } = await buildForwardAuthTeam();
    const email = faker.internet.email().toLowerCase();
    const res = await signIn(host, {
      "x-auth-request-email": email,
      "x-auth-request-groups": "outline-viewers",
      "x-auth-request-user": faker.string.uuid(),
    });

    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).not.toContain("notice=");

    const user = await User.findOne({ where: { email, teamId: team.id } });
    expect(user?.role).toEqual(UserRole.Viewer);
  });

  it("should use the name from the forwarded ID token", async () => {
    const { team, host } = await buildForwardAuthTeam();
    const email = faker.internet.email().toLowerCase();
    const token = JWT.sign({ name: "Ada Lovelace" }, "unverified");
    await signIn(host, {
      "x-auth-request-email": email,
      "x-auth-request-groups": "outline-users",
      authorization: `Bearer ${token}`,
    });

    const user = await User.findOne({ where: { email, teamId: team.id } });
    expect(user?.name).toEqual("Ada Lovelace");
  });

  it("should update the role of an existing user on sign-in", async () => {
    const { team, host } = await buildForwardAuthTeam();
    await buildAdmin({ teamId: team.id });
    const user = await buildUser({ teamId: team.id, role: UserRole.Member });
    await signIn(host, {
      "x-auth-request-email": user.email!,
      "x-auth-request-groups": "outline-admins",
    });

    await user.reload();
    expect(user.role).toEqual(UserRole.Admin);
  });

  it("should not demote the last admin", async () => {
    const { team, host } = await buildForwardAuthTeam();
    const admin = await buildAdmin({ teamId: team.id });
    await signIn(host, {
      "x-auth-request-email": admin.email!,
      "x-auth-request-groups": "outline-users",
    });

    await admin.reload();
    expect(admin.role).toEqual(UserRole.Admin);
  });

  it("should refuse a user without an allowed role", async () => {
    const { team, host } = await buildForwardAuthTeam();
    const email = faker.internet.email().toLowerCase();
    const res = await signIn(host, {
      "x-auth-request-email": email,
      "x-auth-request-groups": "scraper-admins",
    });

    expect(res.headers.get("location")).toContain(
      "notice=invalid-authentication"
    );
    const user = await User.findOne({ where: { email, teamId: team.id } });
    expect(user).toBeNull();
  });

  describe("with only admin roles configured", () => {
    beforeEach(() => {
      env.FORWARD_AUTH_ADMIN_ROLES = ["outline-admins", "admin"];
      env.FORWARD_AUTH_MEMBER_ROLES = undefined;
      env.FORWARD_AUTH_VIEWER_ROLES = undefined;
    });

    afterEach(() => {
      env.FORWARD_AUTH_ADMIN_ROLES = ["outline-admins"];
      env.FORWARD_AUTH_MEMBER_ROLES = ["outline-users"];
      env.FORWARD_AUTH_VIEWER_ROLES = ["outline-viewers"];
    });

    it("should sign in a user without any role as a member", async () => {
      const { team, host } = await buildForwardAuthTeam();
      const email = faker.internet.email().toLowerCase();
      const res = await signIn(host, { "x-auth-request-email": email });

      expect(res.headers.get("location")).not.toContain("notice=");
      const user = await User.findOne({ where: { email, teamId: team.id } });
      expect(user?.role).toEqual(UserRole.Member);
    });

    it("should make a user with the admin role an admin", async () => {
      const { team, host } = await buildForwardAuthTeam();
      const email = faker.internet.email().toLowerCase();
      await signIn(host, {
        "x-auth-request-email": email,
        "x-auth-request-groups": "admin",
      });

      const user = await User.findOne({ where: { email, teamId: team.id } });
      expect(user?.role).toEqual(UserRole.Admin);
    });

    it("should demote an admin who lost the admin role", async () => {
      const { team, host } = await buildForwardAuthTeam();
      await buildAdmin({ teamId: team.id });
      const admin = await buildAdmin({ teamId: team.id });
      await signIn(host, { "x-auth-request-email": admin.email! });

      await admin.reload();
      expect(admin.role).toEqual(UserRole.Member);
    });

    it("should keep a viewer set in Outline", async () => {
      const { team, host } = await buildForwardAuthTeam();
      const viewer = await buildUser({
        teamId: team.id,
        role: UserRole.Viewer,
      });
      await signIn(host, { "x-auth-request-email": viewer.email! });

      await viewer.reload();
      expect(viewer.role).toEqual(UserRole.Viewer);
    });
  });

  it("should not let the ID token choose the account", async () => {
    const { team, host } = await buildForwardAuthTeam();
    const victimId = faker.string.uuid();
    const victimEmail = faker.internet.email().toLowerCase();
    await signIn(host, {
      "x-auth-request-email": victimEmail,
      "x-auth-request-groups": "outline-users",
      "x-auth-request-user": victimId,
    });

    const attackerEmail = faker.internet.email().toLowerCase();
    const token = JWT.sign({ oid: victimId, name: "Mallory" }, "forged");
    await signIn(host, {
      "x-auth-request-email": attackerEmail,
      "x-auth-request-groups": "outline-users",
      authorization: `Bearer ${token}`,
    });

    const victim = await User.findOne({
      where: { email: victimEmail, teamId: team.id },
    });
    const attacker = await User.findOne({
      where: { email: attackerEmail, teamId: team.id },
    });
    expect(victim).not.toBeNull();
    expect(attacker).not.toBeNull();
    expect(attacker?.id).not.toEqual(victim?.id);
  });

  it("should not change the role of a suspended user", async () => {
    const { team, host } = await buildForwardAuthTeam();
    await buildAdmin({ teamId: team.id });
    const user = await buildUser({
      teamId: team.id,
      role: UserRole.Member,
      suspendedAt: new Date(),
    });
    const res = await signIn(host, {
      "x-auth-request-email": user.email!,
      "x-auth-request-groups": "outline-admins",
    });

    expect(res.headers.get("location")).toContain("notice=user-suspended");
    await user.reload();
    expect(user.role).toEqual(UserRole.Member);
  });

  it("should return to the requested page after signing in", async () => {
    const { host } = await buildForwardAuthTeam();
    const res = await server.get("/auth/forward-auth?path=%2Fdoc%2Fabc", {
      redirect: "manual",
      headers: {
        host,
        "x-auth-request-email": faker.internet.email().toLowerCase(),
        "x-auth-request-groups": "outline-users",
      },
    });

    expect(res.status).toEqual(302);
    expect(location(res)).toEqual("/doc/abc");
  });

  it("should not return to another host after signing in", async () => {
    const { host } = await buildForwardAuthTeam();
    const res = await server.get("/auth/forward-auth?path=%2F%2Fevil.com", {
      redirect: "manual",
      headers: {
        host,
        "x-auth-request-email": faker.internet.email().toLowerCase(),
        "x-auth-request-groups": "outline-users",
      },
    });

    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).not.toContain("evil.com");
  });

  describe("page requests", () => {
    /**
     * Requests an app page through the proxy.
     *
     * @param path the page path.
     * @param headers extra request headers.
     * @returns the response.
     */
    async function page(path: string, headers: Record<string, string> = {}) {
      const { host } = await buildForwardAuthTeam();
      return server.get(path, {
        redirect: "manual",
        headers: {
          host,
          "x-auth-request-email": faker.internet.email().toLowerCase(),
          ...headers,
        },
      });
    }

    it("should sign in without showing the login page", async () => {
      const res = await page("/");

      expect(res.status).toEqual(302);
      expect(location(res)).toEqual("/auth/forward-auth");
      expect(res.headers.get("set-cookie")).toContain("forwardAuthAttempt=1");
    });

    it("should keep the requested page", async () => {
      const res = await page("/doc/abc?x=1");

      expect(res.status).toEqual(302);
      expect(location(res)).toEqual(
        "/auth/forward-auth?path=%2Fdoc%2Fabc%3Fx%3D1"
      );
    });

    it("should show the page after a failed sign-in", async () => {
      const res = await page("/?notice=auth-error");

      expect(res.status).not.toEqual(302);
    });

    it("should show the page after logging out", async () => {
      const res = await page("/?logout=true");

      expect(res.status).not.toEqual(302);
    });

    it("should not sign in again while an attempt is in progress", async () => {
      const res = await page("/", { cookie: "forwardAuthAttempt=1" });

      expect(res.status).not.toEqual(302);
    });

    it("should not sign in a visitor that already has a session", async () => {
      const user = await buildUser();
      const res = await page("/", {
        cookie: `accessToken=${user.getSessionToken()}`,
      });

      expect(res.status).not.toEqual(302);
    });

    it("should not sign in without the proxy header", async () => {
      const { host } = await buildForwardAuthTeam();
      const res = await server.get("/", {
        redirect: "manual",
        headers: { host },
      });

      expect(res.status).not.toEqual(302);
    });
  });

  it("should redirect logout to the proxy", async () => {
    const res = await server.get("/auth/forward-auth.logout", {
      redirect: "manual",
    });

    expect(res.status).toEqual(302);
    expect(res.headers.get("location")).toContain("/oauth2/sign_out?rd=");
  });
});
