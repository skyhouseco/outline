import { QueryTypes } from "sequelize";
import { AuthenticationType } from "@shared/types";
import { createContext } from "@server/context";
import { ApiKey, User } from "@server/models";
import { sequelize } from "@server/storage/database";
import type { McpToolCall } from "@server/utils/PluginManager";

/** How a person reached the MCP, in the hub's words. */
export type Via = "claude" | "key";

/** One row of daily usage, in the shape of the hub contract. */
export interface UsageRow {
  day: string;
  email: string;
  tool: string;
  via: Via;
  calls: number;
  failures: number;
  ms_p95: number | null;
  cost: null;
}

/** A person blocked from the MCP. */
export interface BlockedRow {
  email: string;
  blocked_at: string;
  blocked_by: string | null;
}

/** An API key, in the shape of the hub contract. */
export interface KeyConnection {
  via: "key";
  email: string;
  key_id: string;
  key_prefix: string;
  name: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

/** A person who called the MCP with a connector token. */
export interface ClaudeConnection {
  via: "claude";
  email: string;
  last_seen_at: string;
}

/**
 * Normalizes an email the way people are keyed: trimmed and lower-cased.
 *
 * @param value the raw value.
 * @returns the email, or undefined when it is not one.
 */
export function normalizeEmail(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const email = value.trim().toLowerCase();
  return email.length >= 3 && email.length <= 320 && email.includes("@")
    ? email
    : undefined;
}

/**
 * Records a completed MCP tool call.
 *
 * @param call the call reported by the MCP route.
 */
export async function recordCall(call: McpToolCall) {
  await sequelize.query(
    `INSERT INTO mcp_tool_calls ("userId", email, tool, via, ok, "durationMs", "createdAt")
     VALUES ($userId, $email, $tool, $via, $ok, $durationMs, now())`,
    {
      bind: {
        userId: call.user.id,
        email: call.user.email?.trim().toLowerCase() ?? "",
        tool: call.tool,
        via: call.authType === AuthenticationType.API ? "key" : "claude",
        ok: call.ok,
        durationMs: Math.max(0, Math.round(call.durationMs)),
      },
      type: QueryTypes.INSERT,
    }
  );
}

/**
 * Daily totals per person, tool and connection type, for whole UTC days.
 *
 * @param from the first day, YYYY-MM-DD.
 * @param to the last day, YYYY-MM-DD.
 * @returns the rows, only days with calls.
 */
export async function usage(from: string, to: string): Promise<UsageRow[]> {
  const rows = await sequelize.query<{
    day: string;
    email: string;
    tool: string;
    via: Via;
    calls: number;
    failures: number;
    ms_p95: number | null;
  }>(
    `SELECT to_char(("createdAt" AT TIME ZONE 'UTC')::date, 'YYYY-MM-DD') AS day,
            email, tool, via,
            COUNT(*)::int AS calls,
            (COUNT(*) FILTER (WHERE NOT ok))::int AS failures,
            round(percentile_cont(0.95) WITHIN GROUP (ORDER BY "durationMs"))::int AS ms_p95
       FROM mcp_tool_calls
      WHERE "createdAt" >= ($from::date)::timestamp AT TIME ZONE 'UTC'
        AND "createdAt" < ($to::date + 1)::timestamp AT TIME ZONE 'UTC'
      GROUP BY 1, 2, 3, 4
      ORDER BY 1, 2, 3, 4`,
    { bind: { from, to }, type: QueryTypes.SELECT }
  );
  return rows.map((row) => ({ ...row, cost: null }));
}

/**
 * Every API key, revoked ones included. API keys open the whole API, so a
 * revoked key stops working everywhere, not only on the MCP.
 *
 * @returns the keys, newest first.
 */
export async function keyConnections(): Promise<KeyConnection[]> {
  const keys = await ApiKey.findAll({
    paranoid: false,
    include: [{ model: User, as: "user", paranoid: false, required: true }],
    order: [["createdAt", "DESC"]],
  });

  return keys.map((key) => ({
    via: "key",
    email: key.user.email?.trim().toLowerCase() ?? "",
    key_id: key.id,
    key_prefix: `${ApiKey.prefix}…${key.last4}`,
    name: key.name || null,
    created_at: key.createdAt.toISOString(),
    last_used_at: key.lastActiveAt?.toISOString() ?? null,
    revoked_at: key.deletedAt?.toISOString() ?? null,
  }));
}

/**
 * People who called a tool with a connector token, with their last call.
 * Tokens are listed nowhere else, blocking the person is the cutoff.
 *
 * @returns one row per person.
 */
export async function claudeConnections(): Promise<ClaudeConnection[]> {
  const rows = await sequelize.query<{ email: string; last_seen_at: Date }>(
    `SELECT email, MAX("createdAt") AS last_seen_at
       FROM mcp_tool_calls
      WHERE via = 'claude'
      GROUP BY email
      ORDER BY 2 DESC`,
    { type: QueryTypes.SELECT }
  );
  return rows.map((row) => ({
    via: "claude",
    email: row.email,
    last_seen_at: new Date(row.last_seen_at).toISOString(),
  }));
}

/**
 * Revokes an API key. Idempotent.
 *
 * @param id the key id.
 * @param admin the email of the admin who asked.
 * @returns undefined for an unknown key, otherwise whether it was revoked before.
 */
export async function revokeKey(
  id: string,
  admin: string
): Promise<{ already: boolean } | undefined> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) {
    return undefined;
  }

  return sequelize.transaction(async (transaction) => {
    const key = await ApiKey.findByPk(id, {
      paranoid: false,
      lock: transaction.LOCK.UPDATE,
      transaction,
    });
    if (!key) {
      return undefined;
    }
    if (key.deletedAt) {
      return { already: true };
    }

    // Recorded as the admin's own action when they have an account here.
    const actor = await User.findOne({
      where: { email: admin },
      transaction,
    });
    if (actor) {
      await key.destroyWithCtx(createContext({ user: actor, transaction }));
    } else {
      await key.destroy({ transaction });
    }
    return { already: false };
  });
}

/**
 * Whether the person is blocked from the MCP.
 *
 * @param email the person's email.
 * @returns true when blocked.
 */
export async function isBlocked(email: string): Promise<boolean> {
  const rows = await sequelize.query(
    "SELECT 1 FROM mcp_blocked_emails WHERE email = $email LIMIT 1",
    { bind: { email }, type: QueryTypes.SELECT }
  );
  return rows.length > 0;
}

/**
 * Everyone blocked from the MCP.
 *
 * @returns the blocked people, most recent first.
 */
export async function blockedPeople(): Promise<BlockedRow[]> {
  const rows = await sequelize.query<{
    email: string;
    createdAt: Date;
    blockedBy: string | null;
  }>(
    `SELECT email, "createdAt", "blockedBy"
       FROM mcp_blocked_emails ORDER BY "createdAt" DESC`,
    { type: QueryTypes.SELECT }
  );
  return rows.map((row) => ({
    email: row.email,
    blocked_at: new Date(row.createdAt).toISOString(),
    blocked_by: row.blockedBy,
  }));
}

/**
 * Blocks a person from the MCP. Idempotent.
 *
 * @param email the person's email.
 * @param admin the email of the admin who asked.
 * @returns true when the person was not blocked before.
 */
export async function block(email: string, admin: string): Promise<boolean> {
  const rows = await sequelize.query(
    `INSERT INTO mcp_blocked_emails (email, "blockedBy", "createdAt")
     VALUES ($email, $admin, now())
     ON CONFLICT (email) DO NOTHING
     RETURNING email`,
    { bind: { email, admin }, type: QueryTypes.SELECT }
  );
  return rows.length > 0;
}

/**
 * Unblocks a person. Idempotent.
 *
 * @param email the person's email.
 * @returns true when the person was blocked before.
 */
export async function unblock(email: string): Promise<boolean> {
  const rows = await sequelize.query(
    "DELETE FROM mcp_blocked_emails WHERE email = $email RETURNING email",
    { bind: { email }, type: QueryTypes.SELECT }
  );
  return rows.length > 0;
}
