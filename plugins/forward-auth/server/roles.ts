import { UserRole } from "@shared/types";

/** Maps proxy roles to workspace roles. */
export interface RoleMapping {
  /** Proxy roles that grant the admin role. */
  admin?: string[];
  /** Proxy roles that grant the member role. */
  member?: string[];
  /** Proxy roles that grant the viewer role. */
  viewer?: string[];
}

/**
 * Resolves the workspace role for a user from the roles reported by the proxy.
 * The highest matching role wins. When no member roles are configured, users
 * without a matching role keep their current role.
 *
 * @param proxyRoles the roles reported by the proxy for the user.
 * @param mapping the configured mapping of proxy roles to workspace roles.
 * @returns the workspace role, `null` when the user must be refused, or
 * `undefined` when the role must not be changed.
 */
export function resolveRole(
  proxyRoles: string[],
  mapping: RoleMapping
): UserRole | null | undefined {
  const admin = mapping.admin ?? [];
  const member = mapping.member ?? [];
  const viewer = mapping.viewer ?? [];

  if (!admin.length && !member.length && !viewer.length) {
    return undefined;
  }

  const has = (roles: string[]) =>
    roles.some((role) => proxyRoles.includes(role));

  if (has(admin)) {
    return UserRole.Admin;
  }
  if (has(member)) {
    return UserRole.Member;
  }
  if (has(viewer)) {
    return UserRole.Viewer;
  }
  return member.length ? null : undefined;
}

/**
 * Parses a comma separated roles header value.
 *
 * @param value the header value.
 * @returns the list of roles.
 */
export function parseRoles(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((role) => role.trim())
    .filter(Boolean);
}
