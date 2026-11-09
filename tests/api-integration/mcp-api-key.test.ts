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

const versions = ["2025-06-18", "2026-07-28"];

async function fixture() {
  const { app } = createApp();
  const { user, workspace } = await createWorkspaceMember();
  const key = await auth.api.createApiKey({
    body: { userId: user.id, permissions: { project: ["read"] } },
  });
  const originalFetch = globalThis.fetch;
  const forwarded: Headers[] = [];
  vi.stubGlobal("fetch", (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    if (url.origin !== "http://127.0.0.1:1337")
      return originalFetch(input, init);
    forwarded.push(new Headers(init?.headers));
    return app.request(`${url.pathname}${url.search}`, init);
  });
  return { app, user, workspace, key, forwarded };
}

function request(
  version: string,
  headers: Record<string, string>,
  name = "whoami",
  args = {},
) {
  return new Request("http://localhost/api/mcp", {
    method: "POST",
    headers: {
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-method": "tools/call",
      "mcp-name": name,
      "mcp-protocol-version": version,
      ...headers,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: args,
        ...(version === "2026-07-28"
          ? {
              _meta: {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientInfo": {
                  name: "integration",
                  version: "1",
                },
                "io.modelcontextprotocol/clientCapabilities": {},
              },
            }
          : {}),
      },
    }),
  });
}

async function result(response: Response) {
  expect(response.status).toBe(200);
  const text = await response.text();
  const data = text
    .split("\n")
    .find((line) => line.startsWith("data: "))
    ?.slice(6);
  return (
    JSON.parse(data ?? text) as {
      result: { isError?: boolean; content: Array<{ text: string }> };
    }
  ).result;
}

beforeEach(resetTestDatabase);
afterEach(() => vi.unstubAllGlobals());

describe.each(versions)("MCP API-key transport %s", (version) => {
  it.each(["x-api-key", "authorization"])(
    "forwards %s unchanged, charges once and enforces scope",
    async (header) => {
      const { app, user, workspace, key, forwarded } = await fixture();
      await db
        .update(schema.apikeyTable)
        .set({ remaining: 2 })
        .where(eq(schema.apikeyTable.id, key.id));
      const headers = {
        [header]: header === "authorization" ? `Bearer ${key.key}` : key.key,
      };
      const whoami = await result(await app.request(request(version, headers)));
      expect(whoami.isError).not.toBe(true);
      expect(JSON.parse(whoami.content[0].text)).toMatchObject({
        id: user.id,
        name: user.name,
        email: user.email,
      });
      expect(forwarded).toHaveLength(1);
      expect(forwarded[0].get("x-api-key")).toBe(key.key);
      expect(forwarded[0].has("authorization")).toBe(false);
      const [saved] = await db
        .select()
        .from(schema.apikeyTable)
        .where(eq(schema.apikeyTable.id, key.id));
      expect(saved.remaining).toBe(1);
      const denied = await result(
        await app.request(
          request(version, headers, "create_project", {
            workspaceId: workspace.id,
            name: "Forbidden",
            icon: "Folder",
            slug: "forbidden",
          }),
        ),
      );
      expect(denied.isError).toBe(true);
      expect(denied.content[0].text).toMatch(/insufficient.*scope/i);
      expect(
        await db
          .select()
          .from(schema.projectTable)
          .where(eq(schema.projectTable.workspaceId, workspace.id)),
      ).toEqual([]);
    },
  );

  it.each(["invalid", "expired", "disabled", "banned", "quota", "rate"])(
    "rejects %s keys at preflight",
    async (state) => {
      const { app, user, key, forwarded } = await fixture();
      if (state === "banned") {
        await db
          .update(schema.userTable)
          .set({ banned: true })
          .where(eq(schema.userTable.id, user.id));
      } else {
        const updates: Partial<typeof schema.apikeyTable.$inferInsert> = {};
        if (state === "expired")
          updates.expiresAt = new Date(Date.now() - 1000);
        if (state === "disabled") updates.enabled = false;
        if (state === "quota")
          Object.assign(updates, {
            remaining: 0,
            refillAmount: 10,
            refillInterval: 60_000,
            lastRefillAt: new Date(),
          });
        if (state === "rate")
          Object.assign(updates, {
            rateLimitEnabled: true,
            rateLimitMax: 1,
            requestCount: 1,
            lastRequest: new Date(),
            rateLimitTimeWindow: 60_000,
          });
        if (state !== "invalid")
          await db
            .update(schema.apikeyTable)
            .set(updates)
            .where(eq(schema.apikeyTable.id, key.id));
      }
      for (const headers of [
        { "x-api-key": state === "invalid" ? "unknown" : key.key },
        {
          authorization: `Bearer ${state === "invalid" ? "unknown" : key.key}`,
        },
      ]) {
        const response = await app.request(request(version, headers));
        expect(response.status).toBe(
          state === "quota" || state === "rate" ? 429 : 401,
        );
        if (response.status === 429)
          expect(Number(response.headers.get("retry-after"))).toBeGreaterThan(
            0,
          );
        if (state === "rate") {
          expect(response.headers.get("x-ratelimit-limit")).toBe("1");
          expect(response.headers.get("x-ratelimit-remaining")).toBe("0");
        }
      }
      expect(forwarded).toHaveLength(0);
    },
  );

  it("accepts a session bearer but never lets a cookie rescue absent, empty or mixed credentials", async () => {
    const { app } = await fixture();
    const { cookies, userId } = await signUpWithSession(app, {
      email: "mcp@example.com",
      name: "MCP user",
    });
    const session = await auth.api.getSession({
      headers: new Headers({ cookie: cookies }),
    });
    if (!session) throw new Error("Expected test session");
    const authorization = `Bearer ${session.session.token}`;
    const whoami = await result(
      await app.request(request(version, { authorization })),
    );
    expect(whoami.isError).not.toBe(true);
    expect(JSON.parse(whoami.content[0].text)).toMatchObject({ id: userId });
    const rejected: Record<string, string>[] = [
      {},
      { "x-api-key": "" },
      { authorization: "" },
      { authorization: "Bearer unknown" },
      { authorization, "x-api-key": "" },
      { authorization: "", "x-api-key": "unknown" },
      { authorization, "x-api-key": "unknown" },
    ];
    for (const headers of rejected) {
      expect(
        (await app.request(request(version, { cookie: cookies, ...headers })))
          .status,
      ).toBe(401);
    }
  });
});
