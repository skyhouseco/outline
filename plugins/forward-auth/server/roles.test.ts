import { UserRole } from "@shared/types";
import { parseRoles, resolveRole } from "./roles";

describe("resolveRole", () => {
  const mapping = {
    admin: ["outline-admins"],
    member: ["outline-users"],
    viewer: ["outline-viewers"],
  };

  it("should return undefined when no mapping is configured", () => {
    expect(resolveRole(["outline-admins"], {})).toBeUndefined();
  });

  it("should prefer the highest matching role", () => {
    expect(
      resolveRole(
        ["outline-viewers", "outline-users", "outline-admins"],
        mapping
      )
    ).toEqual(UserRole.Admin);
    expect(resolveRole(["outline-viewers", "outline-users"], mapping)).toEqual(
      UserRole.Member
    );
    expect(resolveRole(["outline-viewers"], mapping)).toEqual(UserRole.Viewer);
  });

  it("should refuse users without a role when member roles are set", () => {
    expect(resolveRole([], mapping)).toBeNull();
    expect(resolveRole(["scraper-admins"], mapping)).toBeNull();
  });

  it("should demote an admin without an admin role when member roles are not set", () => {
    const adminOnly = { admin: ["outline-admins", "admin"] };
    expect(resolveRole(["admin"], adminOnly, UserRole.Member)).toEqual(
      UserRole.Admin
    );
    expect(resolveRole([], adminOnly, UserRole.Admin)).toEqual(UserRole.Member);
    expect(resolveRole([], adminOnly, UserRole.Viewer)).toBeUndefined();
    expect(resolveRole([], adminOnly)).toBeUndefined();
  });

  it("should leave the role unchanged when member roles are not set", () => {
    const withoutMember = { admin: ["outline-admins"], viewer: ["guests"] };
    expect(resolveRole([], withoutMember)).toBeUndefined();
    expect(resolveRole(["guests"], withoutMember)).toEqual(UserRole.Viewer);
    expect(resolveRole(["outline-admins"], withoutMember)).toEqual(
      UserRole.Admin
    );
  });
});

describe("parseRoles", () => {
  it("should split and trim a comma separated header", () => {
    expect(parseRoles(" a, b ,,c ")).toEqual(["a", "b", "c"]);
  });

  it("should return an empty list for a missing header", () => {
    expect(parseRoles(undefined)).toEqual([]);
    expect(parseRoles("")).toEqual([]);
  });
});
