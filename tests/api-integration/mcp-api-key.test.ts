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
    return { app, user, workspace, key: key.key };
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
