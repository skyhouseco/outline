import {
  buildCollection,
  buildComment,
  buildDocument,
  buildResolvedComment,
  buildShare,
  buildTemplate,
  buildUser,
} from "@server/test/factories";
import { getTestServer } from "@server/test/support";
import { buildOAuthUser, callMcpTool } from "@server/test/McpHelper";

const server = getTestServer();

describe("fetch", () => {
  it("returns collection details", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "collection",
      id: collection.id,
    });

    expect(res?.result?.content).toBeDefined();
    expect(res!.result!.content!.length).toBeGreaterThanOrEqual(1);

    const data = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(data.id).toEqual(collection.id);
    expect(data.url).toMatch(/^https?:\/\//);
  });

  it("does not return the document tree of a private collection to a non-member admin", async () => {
    const { user, accessToken } = await buildOAuthUser({ role: "admin" });
    const author = await buildUser({ teamId: user.teamId });
    const collection = await buildCollection({
      teamId: author.teamId,
      userId: author.id,
      permission: null,
    });
    const document = await buildDocument({
      teamId: author.teamId,
      userId: author.id,
      collectionId: collection.id,
      title: "Secret plans",
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "collection",
      id: collection.id,
    });

    const content = res?.result?.content ?? [];
    expect(content.length).toEqual(1);
    expect(JSON.parse(content[0].text ?? "{}").id).toEqual(collection.id);
    expect(JSON.stringify(content)).not.toContain(document.id);
  });

  it("returns the document tree of a private collection to a member", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
      permission: null,
    });
    const document = await buildDocument({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "collection",
      id: collection.id,
    });

    const content = res?.result?.content ?? [];
    expect(content.length).toEqual(2);
    expect(content[1].text).toContain(document.id);
  });

  it("returns document metadata and markdown", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const document = await buildDocument({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
      text: "# Hello\n\nWorld",
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "document",
      id: document.id,
    });

    expect(res?.result?.content).toBeDefined();
    expect(res!.result!.content!.length).toEqual(2);

    // First content is JSON metadata
    const metadata = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(metadata.document.id).toEqual(document.id);
    expect(metadata.document.title).toEqual(document.title);
    expect(metadata.document.url).toMatch(/^https?:\/\//);

    // Second content is markdown text
    expect(res!.result!.content![1].text).toContain("Hello");
  });

  it("bounds long document text and reads the rest with offset", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const document = await buildDocument({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
      text: "a".repeat(60_000),
    });

    const first = await callMcpTool(server, accessToken, "fetch", {
      resource: "document",
      id: document.id,
    });
    const firstContent = first?.result?.content ?? [];
    expect(firstContent.length).toEqual(3);
    expect(firstContent[1].text?.length).toEqual(50_000);
    expect(firstContent[2].text).toContain("offset 50000");

    const firstRange = JSON.parse(firstContent[0].text ?? "{}").textRange;
    expect(firstRange.offset).toEqual(0);
    expect(firstRange.end).toEqual(50_000);

    const rest = await callMcpTool(server, accessToken, "fetch", {
      resource: "document",
      id: document.id,
      offset: 50_000,
    });
    const restContent = rest?.result?.content ?? [];
    expect(restContent.length).toEqual(2);
    expect(restContent[1].text?.length).toEqual(
      firstRange.totalLength - 50_000
    );
    expect(JSON.parse(restContent[0].text ?? "{}").textRange.offset).toEqual(
      50_000
    );
  });

  it("returns the public share url for a shared document", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const document = await buildDocument({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
    });
    const share = await buildShare({
      teamId: user.teamId,
      userId: user.id,
      documentId: document.id,
      published: true,
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "document",
      id: document.id,
    });

    const metadata = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(metadata.shareUrl).toMatch(/^https?:\/\//);
    expect(metadata.shareUrl).toContain(`/s/${share.id}`);
  });

  it("omits shareUrl when the share is revoked", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const document = await buildDocument({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
    });
    await buildShare({
      teamId: user.teamId,
      userId: user.id,
      documentId: document.id,
      published: true,
      revokedAt: new Date(),
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "document",
      id: document.id,
    });

    const metadata = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(metadata.shareUrl).toBeUndefined();
  });

  it("returns the public share url for a shared collection", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const share = await buildShare({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
      published: true,
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "collection",
      id: collection.id,
    });

    const data = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(data.shareUrl).toMatch(/^https?:\/\//);
    expect(data.shareUrl).toContain(`/s/${share.id}`);
  });

  it("returns unresolved commentCount on documents", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const document = await buildDocument({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
    });
    const thread = await buildComment({
      documentId: document.id,
      userId: user.id,
    });
    await buildComment({
      documentId: document.id,
      userId: user.id,
      parentCommentId: thread.id,
    });
    await buildResolvedComment(user, {
      documentId: document.id,
      userId: user.id,
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "document",
      id: document.id,
    });

    const metadata = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(metadata.document.commentCount).toEqual(2);
  });

  it("returns template metadata and markdown", async () => {
    const { user, accessToken } = await buildOAuthUser();
    const collection = await buildCollection({
      teamId: user.teamId,
      userId: user.id,
    });
    const template = await buildTemplate({
      teamId: user.teamId,
      userId: user.id,
      collectionId: collection.id,
      text: "Body of the template",
    });

    const res = await callMcpTool(server, accessToken, "fetch", {
      resource: "template",
      id: template.id,
    });

    expect(res?.result?.isError).not.toBe(true);
    expect(res!.result!.content!.length).toEqual(2);

    const metadata = JSON.parse(res!.result!.content![0].text ?? "{}");
    expect(metadata.id).toEqual(template.id);
    expect(metadata.url).toMatch(/^https?:\/\//);

    expect(res!.result!.content![1].text).toContain("Body of the template");
  });
});
