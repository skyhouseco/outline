import { generateKeyPairSync, type KeyObject } from "node:crypto";
import JWT from "jsonwebtoken";
import {
  entraIssuer,
  entraKeysUrl,
  entraSigningKeys,
  isMicrosoftToken,
  type SigningKeys,
  verifyEntraToken,
} from "./entraToken";

const tenantId = "aa08167d-feb6-4390-9e0a-d8744267dcb4";
const clientId = "e10e22d5-dc15-43a8-afba-1e044eb2a72e";
const claudeClient = "967d3a14-9da0-43d4-8031-8d1185a9bda7";
const config = {
  tenantId,
  clientId,
  scope: "wiki.mcp.access",
  clientAppIds: [claudeClient],
};
const now = Date.UTC(2026, 10, 17, 12);
const nowSeconds = now / 1000;

const signing = generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = generateKeyPairSync("rsa", { modulusLength: 2048 });

/**
 * A key source that knows one key.
 *
 * @param kid the key id.
 * @param key the public key.
 * @returns the key lookup.
 */
function keysWith(kid: string, key: KeyObject): SigningKeys {
  return async (_tenantId, requested) =>
    requested === kid ? { key } : { missing: "unknown key" };
}

const keys = keysWith("k1", signing.publicKey);

/**
 * Signs an access token like Entra would, with overrides.
 *
 * @param claims claims to add or replace, undefined removes one.
 * @param options the signing key and key id.
 * @returns the token.
 */
function sign(
  claims: Record<string, unknown> = {},
  options: { key?: KeyObject; kid?: string } = {}
) {
  const payload: Record<string, unknown> = {
    iss: entraIssuer(tenantId),
    aud: clientId,
    tid: tenantId,
    azp: claudeClient,
    scp: "hub.mcp.access wiki.mcp.access video.mcp.access",
    email: "Person@SkyHouse.ai",
    ver: "2.0",
    nbf: nowSeconds - 60,
    exp: nowSeconds + 3600,
  };
  for (const [name, value] of Object.entries(claims)) {
    if (value === undefined) {
      delete payload[name];
    } else {
      payload[name] = value;
    }
  }
  const key = options.key ?? signing.privateKey;
  return JWT.sign(payload, key.export({ type: "pkcs8", format: "pem" }), {
    algorithm: "RS256",
    keyid: options.kid ?? "k1",
    noTimestamp: true,
  });
}

describe("verifyEntraToken", () => {
  it("should accept a good token and lower-case the email", async () => {
    expect(await verifyEntraToken(sign(), config, keys, now)).toEqual({
      ok: true,
      email: "person@skyhouse.ai",
    });
  });

  it("should not take the email from preferred_username", async () => {
    const token = sign({
      email: undefined,
      preferred_username: "Other@SkyHouse.ai",
    });
    expect(await verifyEntraToken(token, config, keys, now)).toEqual({
      ok: false,
      reason: "no email in the Microsoft token",
      detail: "no email claim",
    });
  });

  it("should refuse a token without an email", async () => {
    const token = sign({ email: undefined });
    expect(await verifyEntraToken(token, config, keys, now)).toMatchObject({
      ok: false,
      reason: "no email in the Microsoft token",
    });
  });

  it.each([
    ["wrong audience", { aud: "00000003-0000-0000-c000-000000000000" }],
    ["wrong issuer", { iss: "https://login.microsoftonline.com/other/v2.0" }],
    ["v1 token", { iss: `https://sts.windows.net/${tenantId}/` }],
    ["wrong tenant", { tid: "11111111-1111-1111-1111-111111111111" }],
    ["token from another app", { azp: "22222222-2222-2222-2222-222222222222" }],
    ["token from another app", { azp: undefined }],
    ["missing scope", { scp: "hub.mcp.access video.mcp.access" }],
    ["missing scope", { scp: undefined }],
    ["expired", { exp: nowSeconds }],
    ["expired", { exp: undefined }],
    ["not valid yet", { nbf: nowSeconds + 6 * 60 }],
  ])("should refuse a token: %s", async (reason, claims) => {
    const result = await verifyEntraToken(sign(claims), config, keys, now);
    expect(result).toMatchObject({ ok: false, reason });
  });

  it("should allow 5 minutes of clock skew on nbf", async () => {
    const token = sign({ nbf: nowSeconds + 4 * 60 });
    expect(await verifyEntraToken(token, config, keys, now)).toMatchObject({
      ok: true,
    });
  });

  it("should accept the audience in a list", async () => {
    const token = sign({ aud: ["api://other", clientId] });
    expect(await verifyEntraToken(token, config, keys, now)).toMatchObject({
      ok: true,
    });
  });

  it("should name the person on a refused token with a good signature", async () => {
    const result = await verifyEntraToken(
      sign({ scp: "hub.mcp.access" }),
      config,
      keys,
      now
    );
    expect(result).toMatchObject({ ok: false, email: "person@skyhouse.ai" });
  });

  it("should refuse a token signed with another key", async () => {
    const token = sign({}, { key: other.privateKey });
    expect(await verifyEntraToken(token, config, keys, now)).toEqual({
      ok: false,
      reason: "bad signature",
    });
  });

  it("should refuse a token with an unknown key id", async () => {
    const token = sign({}, { kid: "unknown" });
    expect(await verifyEntraToken(token, config, keys, now)).toEqual({
      ok: false,
      reason: "bad signature",
      detail: "unknown key",
    });
  });

  it("should refuse a token that is not RS256", async () => {
    const token = JWT.sign({ email: "person@skyhouse.ai" }, "secret", {
      algorithm: "HS256",
      keyid: "k1",
    });
    expect(await verifyEntraToken(token, config, keys, now)).toMatchObject({
      ok: false,
      reason: "bad signature",
      detail: "not RS256",
    });
  });

  it("should refuse a malformed token", async () => {
    expect(
      await verifyEntraToken("not.a-token", config, keys, now)
    ).toMatchObject({ ok: false, reason: "unreadable token" });
  });

  it("should report keys that could not be loaded", async () => {
    const unavailable: SigningKeys = async () => ({
      missing: "keys unavailable",
      detail: "keys request answered 500",
    });
    expect(await verifyEntraToken(sign(), config, unavailable, now)).toEqual({
      ok: false,
      reason: "Microsoft's keys could not be loaded",
      detail: "keys request answered 500",
      unavailable: true,
    });
  });

  it("should treat a key source that throws as unavailable", async () => {
    const throwing: SigningKeys = async () => {
      throw new Error("socket hang up");
    };
    expect(await verifyEntraToken(sign(), config, throwing, now)).toMatchObject(
      { ok: false, unavailable: true }
    );
  });

  it("should refuse when not set up", async () => {
    expect(
      await verifyEntraToken(sign(), { ...config, tenantId: "" }, keys, now)
    ).toMatchObject({ ok: false, reason: "Microsoft sign-in is not set up" });
  });

  it("should never return the token", async () => {
    const token = sign({ aud: "api://other" });
    const result = await verifyEntraToken(token, config, keys, now);
    expect(JSON.stringify(result)).not.toContain(token.split(".")[2]);
  });
});

describe("entraSigningKeys", () => {
  const jwks = (kid: string, key: KeyObject) => ({
    keys: [{ ...key.export({ format: "jwk" }), kid, use: "sig" }],
  });

  it("should fetch the tenant's keys once and cache them", async () => {
    const fetchJson = vi.fn(async () => jwks("k1", signing.publicKey));
    const source = entraSigningKeys(fetchJson);

    expect(await verifyEntraToken(sign(), config, source, now)).toMatchObject({
      ok: true,
    });
    expect(
      await verifyEntraToken(sign(), config, source, now + 1000)
    ).toMatchObject({ ok: true });
    expect(fetchJson).toHaveBeenCalledTimes(1);
    expect(fetchJson).toHaveBeenCalledWith(entraKeysUrl(tenantId));
  });

  it("should refetch an unknown key id at most once a minute", async () => {
    const fetchJson = vi.fn(async () => jwks("k1", signing.publicKey));
    const source = entraSigningKeys(fetchJson);
    await source(tenantId, "k1", now);

    expect(await source(tenantId, "k2", now + 1000)).toEqual({
      missing: "unknown key",
    });
    expect(fetchJson).toHaveBeenCalledTimes(1);

    fetchJson.mockResolvedValueOnce(jwks("k2", other.publicKey));
    expect(await source(tenantId, "k2", now + 61_000)).toHaveProperty("key");
    expect(fetchJson).toHaveBeenCalledTimes(2);
  });

  it("should keep the old keys when a refresh fails", async () => {
    const fetchJson = vi.fn(async () => jwks("k1", signing.publicKey));
    const source = entraSigningKeys(fetchJson);
    await source(tenantId, "k1", now);

    fetchJson.mockRejectedValueOnce(new Error("keys request answered 503"));
    const later = now + 25 * 60 * 60 * 1000;
    expect(await source(tenantId, "k1", later)).toHaveProperty("key");
    await new Promise((resolve) => setImmediate(resolve));
    expect(fetchJson).toHaveBeenCalledTimes(2);
    expect(await source(tenantId, "k1", later + 1000)).toHaveProperty("key");
  });

  it("should report keys unavailable when the first fetch fails", async () => {
    const fetchJson = vi.fn(async () => {
      throw new Error("keys request answered 500");
    });
    const source = entraSigningKeys(fetchJson);

    expect(await verifyEntraToken(sign(), config, source, now)).toMatchObject({
      ok: false,
      unavailable: true,
      detail: "keys request answered 500",
    });
  });

  it("should skip keys that are not RSA signing keys", async () => {
    const source = entraSigningKeys(async () => ({
      keys: [
        { kid: "k1", kty: "EC" },
        {
          ...signing.publicKey.export({ format: "jwk" }),
          kid: "k1",
          use: "enc",
        },
      ],
    }));
    expect(await source(tenantId, "k1", now)).toMatchObject({
      missing: "keys unavailable",
      detail: "no usable keys in the response",
    });
  });
});

describe("isMicrosoftToken", () => {
  it("should recognize Microsoft's issuers", () => {
    expect(isMicrosoftToken(sign())).toBe(true);
    expect(
      isMicrosoftToken(sign({ iss: `https://sts.windows.net/${tenantId}/` }))
    ).toBe(true);
  });

  it("should not claim Outline's own tokens", () => {
    expect(isMicrosoftToken(JWT.sign({ id: "user" }, "secret"))).toBe(false);
    expect(isMicrosoftToken("ol_at_abcdefghijklmnopqrstuvwxyz")).toBe(false);
    expect(isMicrosoftToken("ol_api_abcdefghijklmnopqrstuvwxyz")).toBe(false);
    expect(
      isMicrosoftToken(sign({ iss: "https://login.example.com/v2.0" }))
    ).toBe(false);
  });
});
