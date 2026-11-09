import { createHash } from "node:crypto";
import { eq } from "drizzle-orm";
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vite-plus/test";
import { auth } from "../../apps/api/src/auth";
import db, { schema } from "../../apps/api/src/database";
import { createApp } from "../../apps/api/src/index";
import {
  createAuthorizationRequest,
  registerClient,
} from "../../apps/api/src/mcp/oauth";
import { signUpWithSession } from "./helpers/auth-session";
import { resetTestDatabase } from "./helpers/database";
import { createWorkspaceMember } from "./helpers/fixtures";

const MODERN_VERSION = "2026-07-28";
const LEGACY_VERSION = "2025-06-18";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("API integration: MCP API-key authentication", () => {
  beforeEach(resetTestDatabase);

  async function createKey() {
    const { app } = createApp();
    const { user, workspace } = await createWorkspaceMember();
    const key = await auth.api.createApiKey({
      body: {
        userId: user.id,
        name: "MCP integration key",
        permissions: { project: ["read"], workspace: ["read"] },
      },
    });
    const originalFetch = globalThis.fetch;
    vi.stubGlobal(
      "fetch",
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = new URL(String(input));
        if (url.origin === "http://127.0.0.1:1337") {
          return app.request(`${url.pathname}${url.search}`, init);
        }
        return originalFetch(input, init);
      },
    );
    return { app, user, workspace, key: key.key, keyId: key.id };
  }

  function rpcRequest(
    version: string,
    method: string,
    id: number,
    params: Record<string, unknown>,
  ) {
    const modern = version === MODERN_VERSION;
    return new Request("http://localhost/api/mcp", {
      method: "POST",
      headers: {
        accept: "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-method": method,
        "mcp-protocol-version": version,
        ...(method === "tools/call" ? { "mcp-name": String(params.name) } : {}),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id,
        method,
        params: modern
          ? {
              ...params,
              _meta: {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientInfo": {
                  name: "integration",
                  version: "1",
                },
                "io.modelcontextprotocol/clientCapabilities": {},
              },
            }
          : params,
      }),
    });
  }

  async function callTool(
    app: ReturnType<typeof createApp>["app"],
    version: string,
    credential: { name: string; value: string },
    name: string,
    args = {},
  ) {
    const request = rpcRequest(version, "tools/call", 1, {
      name,
      arguments: args,
    });
    request.headers.set(credential.name, credential.value);
    const response = await app.request(request);
    const text = await response.text();
    const data = text
      .split("\n")
      .find((line) => line.startsWith("data: "))
      ?.slice(6);
    return {
      response,
      body: JSON.parse(data ?? text) as {
        result?: { isError?: boolean; content?: Array<{ text: string }> };
        error?: unknown;
      },
    };
  }

  for (const version of [LEGACY_VERSION, MODERN_VERSION]) {
    it.each(["expired", "disabled", "banned"] as const)(
      `rejects %s keys without a cookie escape for ${version}`,
      async (state) => {
        const { app, user, key, keyId } = await createKey();
        const { cookies } = await signUpWithSession(app, {
          email: "unrelated@example.com",
          name: "Unrelated session",
        });
        if (state === "banned") {
          await db
            .update(schema.userTable)
            .set({ banned: true })
            .where(eq(schema.userTable.id, user.id));
        } else {
          await db
            .update(schema.apikeyTable)
            .set(
              state === "expired"
                ? { expiresAt: new Date(Date.now() - 1000) }
                : { enabled: false },
            )
            .where(eq(schema.apikeyTable.id, keyId));
        }
        for (const headers of [
          { "x-api-key": key },
          { authorization: `Bearer ${key}` },
        ]) {
          const request = rpcRequest(version, "tools/call", 1, {
            name: "whoami",
            arguments: {},
          });
          for (const [name, value] of Object.entries(headers))
            request.headers.set(name, value);
          request.headers.set("cookie", cookies);
          expect((await app.request(request)).status).toBe(401);
        }
      },
    );

    it(`does not consume preflight quota and accounts once per REST call for ${version}`, async () => {
      const { app, key, keyId } = await createKey();
      await db
        .update(schema.apikeyTable)
        .set({
          remaining: 2,
          rateLimitEnabled: true,
          rateLimitMax: 10,
          rateLimitTimeWindow: 60_000,
          requestCount: 0,
        })
        .where(eq(schema.apikeyTable.id, keyId));
      const list = rpcRequest(version, "tools/list", 1, {});
      list.headers.set("x-api-key", key);
      expect((await app.request(list)).status).toBe(200);
      const readKey = async () =>
        (
          await db
            .select()
            .from(schema.apikeyTable)
            .where(eq(schema.apikeyTable.id, keyId))
        )[0];
      expect(await readKey()).toMatchObject({ remaining: 2, requestCount: 0 });
      const result = await callTool(
        app,
        version,
        { name: "x-api-key", value: key },
        "whoami",
      );
      expect(result.body.result?.isError).not.toBe(true);
      expect(await readKey()).toMatchObject({ remaining: 1, requestCount: 1 });
    });

    it.each(["quota", "rate"] as const)(
      `returns 429 with retry metadata for %s exhaustion for ${version}`,
      async (kind) => {
        const { app, key, keyId } = await createKey();
        await db
          .update(schema.apikeyTable)
          .set(
            kind === "quota"
              ? {
                  remaining: 0,
                  refillInterval: 60_000,
                  refillAmount: 10,
                  lastRefillAt: new Date(),
                }
              : {
                  rateLimitEnabled: true,
                  rateLimitMax: 1,
                  rateLimitTimeWindow: 60_000,
                  requestCount: 1,
                  lastRequest: new Date(),
                },
          )
          .where(eq(schema.apikeyTable.id, keyId));
        for (const credential of [
          { name: "x-api-key", value: key },
          { name: "authorization", value: `Bearer ${key}` },
        ]) {
          const request = rpcRequest(version, "tools/list", 1, {});
          request.headers.set(credential.name, credential.value);
          const response = await app.request(request);
          expect(response.status).toBe(429);
          expect(Number(response.headers.get("retry-after"))).toBeGreaterThan(
            0,
          );
          if (kind === "rate") {
            expect(response.headers.get("x-ratelimit-limit")).toBe("1");
            expect(response.headers.get("x-ratelimit-remaining")).toBe("0");
            expect(
              Number(response.headers.get("x-ratelimit-reset")),
            ).toBeGreaterThan(0);
          }
        }
      },
    );

    it(`rechecks revocation between MCP preflight and internal REST for ${version}`, async () => {
      const { app, key, keyId } = await createKey();
      vi.stubGlobal(
        "fetch",
        async (input: RequestInfo | URL, init?: RequestInit) => {
          const url = new URL(String(input));
          await db
            .update(schema.apikeyTable)
            .set({ enabled: false })
            .where(eq(schema.apikeyTable.id, keyId));
          expect(new Headers(init?.headers).get("x-api-key")).toBe(key);
          expect(new Headers(init?.headers).has("authorization")).toBe(false);
          return app.request(`${url.pathname}${url.search}`, init);
        },
      );
      const result = await callTool(
        app,
        version,
        { name: "x-api-key", value: key },
        "whoami",
      );
      expect(result.response.status).toBe(200);
      expect(result.body.result?.isError).toBe(true);
    });

    it(`denies cross-workspace writes even with create scope for ${version}`, async () => {
      const { app, key, keyId } = await createKey();
      const outsider = await createWorkspaceMember();
      await db
        .update(schema.apikeyTable)
        .set({ permissions: JSON.stringify({ project: ["create"] }) })
        .where(eq(schema.apikeyTable.id, keyId));
      const result = await callTool(
        app,
        version,
        { name: "x-api-key", value: key },
        "create_project",
        {
          workspaceId: outsider.workspace.id,
          name: "Forbidden",
          icon: "Folder",
          slug: "forbidden",
        },
      );
      expect(result.body.result?.isError).toBe(true);
      expect(
        await db
          .select()
          .from(schema.projectTable)
          .where(eq(schema.projectTable.workspaceId, outsider.workspace.id)),
      ).toEqual([]);
    });

    it(`executes session and consent-issued OAuth bearer tools for ${version}`, async () => {
      const { app } = await createKey();
      const { userId, cookies } = await signUpWithSession(app, {
        email: "oauth@example.com",
        name: "OAuth User",
      });
      const session = await auth.api.getSession({
        headers: new Headers({ cookie: cookies }),
      });
      expect(session?.user.id).toBe(userId);
      const redirectUri = "https://client.example/callback";
      const verifier = "mcp-api-key-integration-pkce-verifier";
      const client = await registerClient({ redirectUris: [redirectUri] });
      const requestId = await createAuthorizationRequest({
        clientId: client.clientId,
        redirectUri,
        codeChallenge: createHash("sha256")
          .update(verifier)
          .digest("base64url"),
      });
      const decision = await app.request(
        `/api/mcp/authorize/request/${requestId}`,
        {
          method: "POST",
          headers: {
            cookie: cookies,
            origin: "http://localhost:5173",
            "content-type": "application/json",
          },
          body: JSON.stringify({ approved: true }),
        },
      );
      expect(decision.status).toBe(200);
      const { redirect } = (await decision.json()) as { redirect: string };
      const code = new URL(redirect).searchParams.get("code");
      expect(code).toBeTruthy();
      const redemption = await app.request("/api/mcp/token", {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code ?? "",
          client_id: client.clientId,
          redirect_uri: redirectUri,
          code_verifier: verifier,
        }),
      });
      expect(redemption.status).toBe(200);
      const { access_token } = (await redemption.json()) as {
        access_token: string;
      };
      for (const token of [session?.session.token, access_token]) {
        const result = await callTool(
          app,
          version,
          { name: "authorization", value: `Bearer ${token}` },
          "whoami",
        );
        expect(result.response.status).toBe(200);
        expect(result.body.result?.isError).not.toBe(true);
        expect(
          JSON.parse(result.body.result?.content?.[0]?.text ?? "null"),
        ).toMatchObject({
          id: userId,
          name: "OAuth User",
          email: "oauth@example.com",
        });
      }
    });

    for (const scheme of ["Bearer", "x-api-key"] as const) {
      it(`routes real ${version} ${scheme} tool calls through the API and enforces scope`, async () => {
        const { app, user, workspace, key } = await createKey();
        const credential =
          scheme === "Bearer"
            ? { name: "authorization", value: `Bearer ${key}` }
            : { name: "x-api-key", value: key };
        const whoami = await callTool(app, version, credential, "whoami");
        expect(whoami.response.status).toBe(200);
        expect(whoami.body.result?.isError).not.toBe(true);
        expect(
          JSON.parse(whoami.body.result?.content?.[0]?.text ?? "null"),
        ).toMatchObject({ id: user.id });

        const workspaces = await callTool(
          app,
          version,
          credential,
          "list_workspaces",
        );
        expect(workspaces.response.status).toBe(200);
        expect(workspaces.body.result?.isError).not.toBe(true);
        expect(
          JSON.parse(workspaces.body.result?.content?.[0]?.text ?? "null"),
        ).toEqual([expect.objectContaining({ id: workspace.id })]);

        const denied = await callTool(
          app,
          version,
          credential,
          "create_project",
          {
            workspaceId: workspace.id,
            name: "Must not be created",
            icon: "Folder",
            slug: "must-not-be-created",
          },
        );
        expect(denied.body.result?.isError).toBe(true);
        expect(denied.body.result?.content?.[0]?.text ?? "").toMatch(
          /insufficient.*scope/i,
        );
        expect(
          await db
            .select({ id: schema.projectTable.id })
            .from(schema.projectTable)
            .where(eq(schema.projectTable.workspaceId, workspace.id)),
        ).toEqual([]);
      });
    }
  }

  it.each([
    { "x-api-key": "" },
    { "x-api-key": "   " },
    { authorization: "" },
    { authorization: "Basic invalid" },
    { authorization: "Bearer" },
    { authorization: "Bearer unknown-token" },
  ])(
    "rejects empty or malformed credentials even with a valid cookie: %j",
    async (headers) => {
      const { app } = await createKey();
      const { cookies } = await signUpWithSession(app, {
        email: "cookie-escape@example.com",
        name: "Cookie escape",
      });
      for (const version of [LEGACY_VERSION, MODERN_VERSION]) {
        const request = rpcRequest(version, "tools/call", 1, {
          name: "whoami",
          arguments: {},
        });
        for (const [name, value] of Object.entries(headers))
          request.headers.set(name, value);
        request.headers.set("cookie", cookies);
        expect((await app.request(request)).status).toBe(401);
      }
    },
  );

  it("rejects both credentials when an explicitly supplied credential is empty", async () => {
    const { app, key } = await createKey();
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: LEGACY_VERSION,
        capabilities: {},
        clientInfo: { name: "test", version: "1" },
      },
    });
    const headers = {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-method": "initialize",
      "mcp-protocol-version": LEGACY_VERSION,
    };

    const emptyApiKey = await app.request("/api/mcp", {
      method: "POST",
      headers: {
        ...headers,
        authorization: `Bearer ${key}`,
        "x-api-key": "",
      },
      body,
    });
    expect(emptyApiKey.status).toBe(401);

    const emptyAuthorization = await app.request("/api/mcp", {
      method: "POST",
      headers: { ...headers, authorization: "", "x-api-key": key },
      body,
    });
    expect(emptyAuthorization.status).toBe(401);
  });

  for (const version of [LEGACY_VERSION, MODERN_VERSION]) {
    it(`rejects both valid credentials for ${version}`, async () => {
      const { app, key } = await createKey();
      const request = rpcRequest(version, "tools/call", 1, {
        name: "whoami",
        arguments: {},
      });
      request.headers.set("authorization", `Bearer ${key}`);
      request.headers.set("x-api-key", key);
      expect((await app.request(request)).status).toBe(401);
    });

    it(`rejects cookie-only authentication for ${version}`, async () => {
      const { app } = createApp();
      const { userId, cookies } = await signUpWithSession(app, {
        email: "mcp-cookie@example.com",
        name: "MCP cookie user",
      });
      const session = await app.request("/api/auth/get-session", {
        headers: { cookie: cookies },
      });
      expect(session.status).toBe(200);
      expect(await session.json()).toMatchObject({ user: { id: userId } });
      const request = rpcRequest(version, "tools/call", 1, {
        name: "whoami",
        arguments: {},
      });
      request.headers.set("cookie", cookies);
      expect((await app.request(request)).status).toBe(401);
    });
  }
});
