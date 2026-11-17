import { createPublicKey, type KeyObject, verify } from "node:crypto";
import fetch from "@server/utils/fetch";

/**
 * Checks the person's own Microsoft Entra access token on /mcp, ported from
 * the SkyHouse MCP hub's src/gateway/access-token.ts. A token is accepted only
 * when it is:
 *
 * - signed RS256 by one of the tenant's published keys, kept in memory for a
 *   day. An unknown key id refetches them at most once a minute, so made up
 *   tokens cannot hammer Microsoft, and a failed refresh keeps the old keys;
 * - a v2 token from the tenant (`iss`, `tid`) for the SSO app (`aud`);
 * - issued to one of the allowed client apps (`azp`), so a token another app
 *   got for the same scope is refused;
 * - carrying the wiki's scope in `scp`, which keeps out ID tokens and tokens
 *   for the other apps' scopes only. Other scopes alongside it are fine;
 * - not expired (`exp`, no grace) and already valid (`nbf`, 5 minutes skew);
 * - naming the person in its `email` claim, lower-cased. Never
 *   `preferred_username`: that is the UPN, which can differ from the email
 *   the person signs in to the wiki with.
 *
 * The token itself is never logged, stored or returned: `detail` names the
 * claim that failed, for the server log.
 */

/** The settings a Microsoft access token is checked against. */
export interface EntraTokenConfig {
  /** The Entra tenant id. */
  tenantId: string;
  /** The SSO app's client id, the token's audience. */
  clientId: string;
  /** The delegated scope the token must carry. */
  scope: string;
  /** The client apps the token may be issued to. */
  clientAppIds: string[];
}

/** The outcome of checking a Microsoft access token. */
export type EntraTokenResult =
  | { ok: true; email: string }
  | {
      ok: false;
      /** Why the token was refused, in plain words. */
      reason: string;
      /** The claim that failed, for the server log. */
      detail?: string;
      /** The person, only when the signature was good. */
      email?: string;
      /** Microsoft's keys could not be loaded, the token was never judged. */
      unavailable?: boolean;
    };

/** The tenant's signing key for a key id, or why there is none. */
export type SigningKeyLookup =
  | { key: KeyObject }
  | { missing: "unknown key" | "keys unavailable"; detail?: string };

/** Finds the tenant's signing key for a key id. */
export type SigningKeys = (
  tenantId: string,
  kid: string,
  now: number
) => Promise<SigningKeyLookup>;

/** Fetches a URL and returns its JSON body, or throws. */
export type FetchJson = (url: string) => Promise<unknown>;

/** Clock skew allowed on `nbf`, in seconds. */
const NotBeforeSkewSeconds = 5 * 60;

/** Entra's keys rotate every few weeks with overlap, a day-old copy is fine. */
const KeysTtlMs = 24 * 60 * 60 * 1000;

/** At most one keys request a minute, for an unknown key id or a retry. */
const KeysRetryMs = 60 * 1000;

/** How long to wait for Microsoft's keys. */
const KeysTimeoutMs = 5000;

/** Longer than any real Entra access token, bigger ones are refused unread. */
const MaxTokenLength = 16_384;

/** The longest detail kept for the server log. */
const MaxDetailLength = 200;

const Base64UrlPattern = /^[A-Za-z0-9_-]+$/;

/**
 * The issuer of the tenant's v2 access tokens.
 *
 * @param tenantId the Entra tenant id.
 * @returns the issuer URL.
 */
export function entraIssuer(tenantId: string) {
  return `https://login.microsoftonline.com/${tenantId}/v2.0`;
}

/**
 * The address of the tenant's published signing keys.
 *
 * @param tenantId the Entra tenant id.
 * @returns the JWKS URL.
 */
export function entraKeysUrl(tenantId: string) {
  return `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
}

/**
 * Whether a bearer token claims to be issued by Microsoft. Its signature is
 * not checked, this only decides which check applies to it.
 *
 * @param token the bearer token.
 * @returns true for a JWT whose issuer is Microsoft's.
 */
export function isMicrosoftToken(token: string): boolean {
  if (token.length > MaxTokenLength) {
    return false;
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    return false;
  }
  const iss = jsonPart(parts[1])?.iss;
  return (
    typeof iss === "string" &&
    (iss.startsWith("https://login.microsoftonline.com/") ||
      iss.startsWith("https://sts.windows.net/"))
  );
}

/**
 * Builds a source of the tenant's signing keys, cached in memory.
 *
 * @param fetchJson fetches the keys document.
 * @returns the key lookup.
 */
export function entraSigningKeys(
  fetchJson: FetchJson = fetchKeysDocument
): SigningKeys {
  let keys = new Map<string, KeyObject>();
  let keysTenant = "";
  let keysAt = 0;
  let lastAttempt = 0;
  let lastError: string | undefined;
  let inflight: Promise<void> | undefined;

  const refresh = (tenantId: string, now: number) => {
    if (inflight) {
      return inflight;
    }
    lastAttempt = now;
    inflight = (async () => {
      try {
        const next = parseKeys(await fetchJson(entraKeysUrl(tenantId)));
        if (!next.size) {
          throw new Error("no usable keys in the response");
        }
        keys = next;
        keysTenant = tenantId;
        keysAt = now;
        lastError = undefined;
      } catch (err) {
        // Keep the keys we had, Microsoft being briefly unreachable must not
        // sign everyone out.
        lastError =
          err instanceof Error
            ? err.message.slice(0, MaxDetailLength)
            : "keys request failed";
      } finally {
        inflight = undefined;
      }
    })();
    return inflight;
  };

  return async (tenantId, kid, now) => {
    const have = keysTenant === tenantId && keys.size > 0;
    const mayFetch = lastAttempt === 0 || now - lastAttempt >= KeysRetryMs;
    let fetched = false;

    if (!have || !keys.has(kid)) {
      // First use, a key Microsoft rolled in, or a made up key id.
      if (mayFetch || inflight) {
        await refresh(tenantId, now);
        fetched = true;
      }
    } else if (now - keysAt > KeysTtlMs && mayFetch) {
      // Stale but usable, refresh in the background.
      void refresh(tenantId, now);
    }

    const key = keysTenant === tenantId ? keys.get(kid) : undefined;
    if (key) {
      return { key };
    }

    // Unavailable only when the token could not be judged: this lookup's own
    // fetch failed, or there are no keys at all.
    const haveNow = keysTenant === tenantId && keys.size > 0;
    if (lastError && (fetched || !haveNow)) {
      return { missing: "keys unavailable", detail: lastError };
    }
    return { missing: "unknown key" };
  };
}

/**
 * Checks a Microsoft access token for the wiki's MCP server.
 *
 * @param token the bearer token.
 * @param config the tenant, app and scope to check against.
 * @param keys the source of the tenant's signing keys.
 * @param now the current time in milliseconds.
 * @returns the person's email, or why the token was refused.
 */
export async function verifyEntraToken(
  token: string,
  config: EntraTokenConfig,
  keys: SigningKeys = defaultSigningKeys(),
  now = Date.now()
): Promise<EntraTokenResult> {
  if (!config.tenantId || !config.clientId || !config.scope) {
    return refusal("Microsoft sign-in is not set up");
  }

  const signed = await verifySignature(token, config.tenantId, keys, now);
  if (!signed.ok) {
    return signed;
  }

  const claims = signed.claims;
  const email = emailOf(claims);
  const no = (reason: string, detail?: string) =>
    refusal(reason, detail, email);

  if (claims.ver === "1.0" || claims.iss === v1Issuer(config.tenantId)) {
    return no("v1 token", `iss ${String(claims.iss)}`);
  }
  if (claims.iss !== entraIssuer(config.tenantId)) {
    return no("wrong issuer", `iss ${String(claims.iss)}`);
  }

  const aud = claims.aud;
  if (
    !(
      aud === config.clientId ||
      (Array.isArray(aud) && aud.includes(config.clientId))
    )
  ) {
    return no("wrong audience", `aud ${JSON.stringify(aud)}`);
  }
  if (claims.tid !== config.tenantId) {
    return no("wrong tenant", `tid ${String(claims.tid)}`);
  }

  const clientApps = config.clientAppIds.map((id) => id.toLowerCase());
  if (
    typeof claims.azp !== "string" ||
    !clientApps.includes(claims.azp.toLowerCase())
  ) {
    return no("token from another app", `azp ${String(claims.azp)}`);
  }

  if (!("scp" in claims)) {
    return no("missing scope", "no scp claim");
  }
  if (!scopesOf(claims.scp).includes(config.scope)) {
    return no("missing scope", `scp ${String(claims.scp)}`);
  }

  const nowSeconds = now / 1000;
  if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp)) {
    return no("expired", "no exp claim");
  }
  if (nowSeconds >= claims.exp) {
    return no("expired");
  }
  if (
    typeof claims.nbf === "number" &&
    nowSeconds < claims.nbf - NotBeforeSkewSeconds
  ) {
    return no("not valid yet");
  }

  if (!email) {
    return no("no email in the Microsoft token", "no email claim");
  }
  return { ok: true, email };
}

/**
 * The scopes in a `scp` claim, which is space separated.
 *
 * @param scp the claim value.
 * @returns the scopes.
 */
export function scopesOf(scp: unknown): string[] {
  return typeof scp === "string" ? scp.split(" ").filter(Boolean) : [];
}

let sharedSigningKeys: SigningKeys | undefined;

/**
 * The signing keys shared by every request in this process.
 *
 * @returns the key lookup.
 */
function defaultSigningKeys() {
  sharedSigningKeys ??= entraSigningKeys();
  return sharedSigningKeys;
}

/**
 * Fetches Microsoft's keys document.
 *
 * @param url the JWKS URL.
 * @returns the parsed body.
 */
async function fetchKeysDocument(url: string): Promise<unknown> {
  const res = await fetch(url, { timeout: KeysTimeoutMs });
  if (!res.ok) {
    throw new Error(`keys request answered ${res.status}`);
  }
  const body: unknown = await res.json();
  return body;
}

/**
 * Reads the RSA signing keys from a JWKS document, skipping any other key.
 *
 * @param body the JWKS document.
 * @returns the keys by key id.
 */
function parseKeys(body: unknown): Map<string, KeyObject> {
  const keys = new Map<string, KeyObject>();
  const list = isRecord(body) && Array.isArray(body.keys) ? body.keys : [];

  for (const item of list) {
    if (!isRecord(item)) {
      continue;
    }
    const { kid, kty, use, n, e } = item;
    if (typeof kid !== "string" || kty !== "RSA") {
      continue;
    }
    if (use !== undefined && use !== "sig") {
      continue;
    }
    if (typeof n !== "string" || typeof e !== "string") {
      continue;
    }
    try {
      keys.set(
        kid,
        createPublicKey({ key: { kty: "RSA", n, e }, format: "jwk" })
      );
    } catch {
      // Skip a key Node cannot read.
    }
  }
  return keys;
}

/**
 * Returns the token's claims when it is a JWT signed RS256 by one of the
 * tenant's keys. The claims themselves are not checked.
 *
 * @param token the bearer token.
 * @param tenantId the Entra tenant id.
 * @param keys the source of the tenant's signing keys.
 * @param now the current time in milliseconds.
 * @returns the claims, or why the token was refused.
 */
async function verifySignature(
  token: string,
  tenantId: string,
  keys: SigningKeys,
  now: number
): Promise<
  | { ok: true; claims: Record<string, unknown> }
  | Extract<EntraTokenResult, { ok: false }>
> {
  if (token.length > MaxTokenLength) {
    return refusal("unreadable token", "too long");
  }
  const parts = token.split(".");
  if (
    parts.length !== 3 ||
    !parts.every((part) => Base64UrlPattern.test(part))
  ) {
    return refusal("unreadable token", "malformed");
  }
  const header = jsonPart(parts[0]);
  const claims = jsonPart(parts[1]);
  if (!header || !claims) {
    return refusal("unreadable token", "unreadable");
  }
  if (header.alg !== "RS256") {
    return refusal("bad signature", "not RS256");
  }
  if (
    typeof header.kid !== "string" ||
    !header.kid ||
    header.kid.length > 200
  ) {
    return refusal("bad signature", "no key id");
  }

  let found: SigningKeyLookup;
  try {
    found = await keys(tenantId, header.kid, now);
  } catch (err) {
    // A key source that throws is treated like Microsoft being unreachable,
    // it is only ever given the tenant and the key id.
    found = {
      missing: "keys unavailable",
      detail: err instanceof Error ? err.message : "keys lookup failed",
    };
  }
  if ("missing" in found) {
    return found.missing === "keys unavailable"
      ? {
          ...refusal("Microsoft's keys could not be loaded", found.detail),
          unavailable: true,
        }
      : refusal("bad signature", "unknown key");
  }

  let valid = false;
  try {
    valid = verify(
      "RSA-SHA256",
      Buffer.from(`${parts[0]}.${parts[1]}`),
      found.key,
      Buffer.from(parts[2], "base64url")
    );
  } catch {
    valid = false;
  }
  return valid ? { ok: true, claims } : refusal("bad signature");
}

/**
 * The person named by the token, from its `email` claim only.
 *
 * @param claims the token's claims.
 * @returns the email, trimmed and lower-cased, or undefined.
 */
function emailOf(claims: Record<string, unknown>): string | undefined {
  if (typeof claims.email !== "string") {
    return undefined;
  }
  const email = claims.email.trim().toLowerCase();
  return email.includes("@") ? email : undefined;
}

/**
 * Builds a refusal.
 *
 * @param reason why the token was refused.
 * @param detail the claim that failed, for the server log.
 * @param email the person, when the signature was good.
 * @returns the refusal.
 */
function refusal(
  reason: string,
  detail?: string,
  email?: string
): Extract<EntraTokenResult, { ok: false }> {
  return {
    ok: false,
    reason,
    ...(email ? { email } : {}),
    ...(detail ? { detail: detail.slice(0, MaxDetailLength) } : {}),
  };
}

/**
 * The issuer of the tenant's v1 tokens, which are refused.
 *
 * @param tenantId the Entra tenant id.
 * @returns the issuer URL.
 */
function v1Issuer(tenantId: string) {
  return `https://sts.windows.net/${tenantId}/`;
}

/**
 * Decodes one base64url JSON part of a JWT.
 *
 * @param part the encoded part.
 * @returns the decoded object, or undefined.
 */
function jsonPart(part: string): Record<string, unknown> | undefined {
  try {
    const value: unknown = JSON.parse(
      Buffer.from(part, "base64url").toString("utf8")
    );
    return isRecord(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Whether a value is a plain object.
 *
 * @param value the value.
 * @returns true for a non-array object.
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}
