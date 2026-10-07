import { createHash, randomUUID } from "node:crypto";
import { eq } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vite-plus/test";
import db, { schema } from "../../apps/api/src/database";
import { createApp } from "../../apps/api/src/index";
import { resetTestDatabase } from "./helpers/database";

const protocolVersions = ["2026-07-28", "2025-06-18"];

async function signUp(app: ReturnType<typeof createApp>["app"]) {
  const response = await app.request("/api/auth/sign-up/email", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "http://localhost:5173",
    },
    body: JSON.stringify({
      name: "MCP user",
      email: `${randomUUID()}@example.com`,
      password: "mcp-banned-user-password",
    }),
  });
  expect(response.status).toBe(200);
  const body = (await response.json()) as {
    token: string;
    user: { id: string };
  };
  return { token: body.token, userId: body.user.id };
}

function mcpRequest(
  app: ReturnType<typeof createApp>["app"],
  token: string,
  protocolVersion: string,
  header = "authorization",
) {
  const isModern = protocolVersion === "2026-07-28";
  const method = isModern ? "tools/list" : "initialize";
  const params = isModern
    ? {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": protocolVersion,
          "io.modelcontextprotocol/clientInfo": {
            name: "kaneo-banned-user-test",
            version: "1.0.0",
          },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      }
    : {
        protocolVersion,
        capabilities: {},
        clientInfo: { name: "kaneo-banned-user-test", version: "1.0.0" },
      };
  return app.request("/api/mcp", {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      [header]: header === "authorization" ? `Bearer ${token}` : token,
      "content-type": "application/json",
      "mcp-method": method,
      "mcp-protocol-version": protocolVersion,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

describe("API integration: MCP access for banned users", () => {
  beforeEach(async () => {
    await resetTestDatabase();
  });

  it.each(protocolVersions)(
    "stops serving a %s session token once its owner is banned",
    async (protocolVersion) => {
      const { app } = createApp();
      const { token, userId } = await signUp(app);

      expect((await mcpRequest(app, token, protocolVersion)).status).not.toBe(
        401,
      );

      await db
        .update(schema.userTable)
        .set({ banned: true })
        .where(eq(schema.userTable.id, userId));

      expect((await mcpRequest(app, token, protocolVersion)).status).toBe(401);
    },
  );

  it("accepts active API keys and rejects invalid explicit API-key credentials", async () => {
    const protocolVersion = "2025-06-18";
    const { app } = createApp();
    const email = `${randomUUID()}@example.com`;
    const createdUser = await app.request("/api/auth/sign-up/email", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:5173",
      },
      body: JSON.stringify({
        name: "MCP API key user",
        email,
        password: "mcp-api-key-password",
      }),
    });
    const user = (await createdUser.json()) as {
      user: { id: string };
    };
    const hashed = createHash("sha256")
      .update("valid-mcp-api-key")
      .digest()
      .toString("base64url");
    await db.insert(schema.apikeyTable).values({
      id: randomUUID(),
      key: hashed,
      userId: user.user.id,
      referenceId: user.user.id,
      name: "mcp",
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    });

    const apiKeyMcpResponse = await mcpRequest(
      app,
      "valid-mcp-api-key",
      protocolVersion,
      "x-api-key",
    );
    expect(
      apiKeyMcpResponse.status,
      await apiKeyMcpResponse.clone().text(),
    ).toBe(200);
    expect(
      (await mcpRequest(app, "valid-mcp-api-key", protocolVersion)).status,
    ).toBe(200);
    expect(
      (await mcpRequest(app, "invalid-key", protocolVersion, "x-api-key"))
        .status,
    ).toBe(401);
    await db
      .update(schema.userTable)
      .set({ banned: true })
      .where(eq(schema.userTable.id, user.user.id));
    expect(
      (await mcpRequest(app, "valid-mcp-api-key", protocolVersion, "x-api-key"))
        .status,
    ).toBe(401);
    await db
      .update(schema.userTable)
      .set({ banned: false })
      .where(eq(schema.userTable.id, user.user.id));
    await db
      .update(schema.apikeyTable)
      .set({ enabled: false })
      .where(eq(schema.apikeyTable.key, hashed));
    expect(
      (await mcpRequest(app, "valid-mcp-api-key", protocolVersion, "x-api-key"))
        .status,
    ).toBe(401);
    await db
      .update(schema.apikeyTable)
      .set({ enabled: true, expiresAt: new Date(Date.now() - 1000) })
      .where(eq(schema.apikeyTable.key, hashed));
    expect(
      (await mcpRequest(app, "valid-mcp-api-key", protocolVersion, "x-api-key"))
        .status,
    ).toBe(401);
    const signedIn = await app.request("/api/auth/sign-in/email", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        origin: "http://localhost:5173",
      },
      body: JSON.stringify({ email, password: "mcp-api-key-password" }),
    });
    expect(signedIn.status).toBe(200);
    const cookie = signedIn.headers.get("set-cookie") ?? "";
    const keyWithCookie = await app.request("/api/mcp", {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        authorization: "Bearer invalid-key",
        cookie,
        "content-type": "application/json",
        "mcp-method": "initialize",
        "mcp-protocol-version": protocolVersion,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion,
          capabilities: {},
          clientInfo: { name: "test", version: "1" },
        },
      }),
    });
    expect(keyWithCookie.status).toBe(401);
  });
});
