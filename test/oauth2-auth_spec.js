"use strict";

const assert = require("assert");
const helper = require("node-red-node-test-helper");
const oauth2AuthModule = require("../oauth2-auth.js");
const { version } = require("../package.json");
const { createMockTokenServer } = require("./helpers/mock-token-server");

helper.init(require.resolve("node-red"));

// The test helper's RED._ returns only the message key. Append the
// substitutions so that tests can check what ends up in the responses.
function oauth2AuthNode(RED) {
  RED._ = (key, subs) => subs ? key + " " + Object.values(subs).join(" ") : key;
  return oauth2AuthModule(RED);
}

const NODE_ID = "n1";
const flow = [
  { id: NODE_ID, type: "oauth2-auth", name: "oauth2", wires: [["h1"]] },
  { id: "h1", type: "helper" }
];

const CLOUDFLARE_PAGE = "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head></html>";

function nowSeconds() {
  return Math.floor(Date.now() / 1000);
}

function waitFor(node, event) {
  return new Promise((resolve) => node.once(event, resolve));
}

describe("oauth2-auth node", function () {
  const tokenServer = createMockTokenServer();

  function storedCredentials(overrides) {
    return {
      [NODE_ID]: {
        client_id: "client",
        client_secret: "secret",
        access_token_url: tokenServer.url,
        access_token: "OLD_ACCESS",
        refresh_token: "OLD_REFRESH",
        expires_in: 3600,
        expire_time: nowSeconds() + 3600,
        auth_time: nowSeconds(),
        ...overrides
      }
    };
  }

  function getCredentials() {
    return helper.credentials.get(NODE_ID);
  }

  // Runs /oauth2-auth/auth and returns the state for the callback.
  async function startAuthorization() {
    const res = await helper.request()
      .get("/oauth2-auth/auth")
      .query({
        id: NODE_ID,
        client_id: "client",
        client_secret: "secret",
        authentication_url: "https://provider.invalid/authorize",
        redirect_url: "http://localhost:1880/oauth2-auth/callback",
        access_token_url: tokenServer.url,
        scope: "public",
        force_login: "false"
      })
      .expect(302);

    return new URL(res.headers.location).searchParams.get("state");
  }

  before(async function () {
    await tokenServer.start();
    await new Promise((resolve) => helper.startServer(resolve));
  });

  after(async function () {
    await new Promise((resolve) => helper.stopServer(resolve));
    await tokenServer.stop();
  });

  beforeEach(function () {
    tokenServer.reset();
  });

  afterEach(async function () {
    await helper.unload();
  });

  it("should be loaded", async function () {
    await helper.load(oauth2AuthNode, flow, storedCredentials());
    assert.strictEqual(helper.getNode(NODE_ID).name, "oauth2");
  });

  describe("input", function () {
    it("sets the bearer header without a refresh while the token is valid", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());
      const received = waitFor(helper.getNode("h1"), "input");

      helper.getNode(NODE_ID).receive({ payload: "x" });

      const msg = await received;
      assert.strictEqual(msg.headers.Authorization, "Bearer OLD_ACCESS");
      assert.strictEqual(tokenServer.requests.length, 0);
    });

    it("refreshes an expired token and stores the new one", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials({ expire_time: 1 }));
      tokenServer.respondWith(200, { access_token: "NEW_ACCESS", expires_in: 7200 });
      const received = waitFor(helper.getNode("h1"), "input");

      helper.getNode(NODE_ID).receive({ payload: "x" });

      const msg = await received;
      assert.strictEqual(msg.headers.Authorization, "Bearer NEW_ACCESS");

      const request = tokenServer.requests[0];
      assert.strictEqual(request.form.grant_type, "refresh_token");
      assert.strictEqual(request.form.refresh_token, "OLD_REFRESH");
      assert.strictEqual(request.headers["user-agent"], "Node-RED-OAuth2-Auth/" + version);

      const creds = getCredentials();
      assert.strictEqual(creds.access_token, "NEW_ACCESS");
      assert.strictEqual(creds.refresh_token, "OLD_REFRESH");
      assert.ok(creds.expire_time > nowSeconds());
    });

    for (const [title, status, body] of [
      ["an HTML error page", 403, CLOUDFLARE_PAGE],
      ["an OAuth2 error", 400, { error: "invalid_grant", error_description: "revoked" }],
      ["a success status without access_token", 200, {}]
    ]) {
      it("reports " + title + " on refresh and keeps the stored credentials", async function () {
        const initial = storedCredentials({ expire_time: 1 });
        await helper.load(oauth2AuthNode, flow, initial);
        tokenServer.respondWith(status, body);
        const node = helper.getNode(NODE_ID);
        const failed = waitFor(node, "call:error");
        let sent = false;
        helper.getNode("h1").on("input", () => sent = true);

        node.receive({ payload: "x" });

        const call = await failed;
        assert.match(String(call.args[0]), /something_broke/);
        assert.strictEqual(sent, false);
        assert.strictEqual(getCredentials().access_token, "OLD_ACCESS");
        assert.strictEqual(getCredentials().refresh_token, "OLD_REFRESH");
      });
    }
  });

  describe("authorization callback", function () {
    it("stores the tokens on success", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());
      const state = await startAuthorization();
      tokenServer.respondWith(200, { access_token: "AUTH_ACCESS", refresh_token: "AUTH_REFRESH", expires_in: 7200 });

      const res = await helper.request()
        .get("/oauth2-auth/callback")
        .query({ code: "abc", state })
        .expect(200);

      assert.match(res.text, /authorisation_successful/);

      const request = tokenServer.requests[0];
      assert.strictEqual(request.form.grant_type, "authorization_code");
      assert.strictEqual(request.form.code, "abc");
      assert.strictEqual(request.headers["user-agent"], "Node-RED-OAuth2-Auth/" + version);

      const creds = getCredentials();
      assert.strictEqual(creds.access_token, "AUTH_ACCESS");
      assert.strictEqual(creds.refresh_token, "AUTH_REFRESH");
      assert.strictEqual(creds.csrf_token, undefined);
    });

    it("rejects an HTML error page and stores no tokens", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());
      const state = await startAuthorization();
      tokenServer.respondWith(403, CLOUDFLARE_PAGE);

      const res = await helper.request()
        .get("/oauth2-auth/callback")
        .query({ code: "abc", state })
        .expect(502);

      assert.doesNotMatch(res.text, /authorisation_successful/);
      assert.match(res.text, /HTTP 403/);
      assert.doesNotMatch(res.text, /<!DOCTYPE/);
      assert.strictEqual(getCredentials().access_token, undefined);
      assert.strictEqual(getCredentials().refresh_token, undefined);
    });

    it("rejects a wrong CSRF token", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());
      await startAuthorization();

      await helper.request()
        .get("/oauth2-auth/callback")
        .query({ code: "abc", state: NODE_ID + ":wrong" })
        .expect(401);

      assert.strictEqual(tokenServer.requests.length, 0);
    });

    it("rejects a request without code or state", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());

      await helper.request().get("/oauth2-auth/callback").expect(400);
    });

    it("escapes error parameters from the provider", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());

      const res = await helper.request()
        .get("/oauth2-auth/callback")
        .query({ error: "<script>alert(1)</script>", error_description: "<b>x</b>" })
        .expect(200);

      assert.match(res.text, /&lt;script&gt;/);
      assert.doesNotMatch(res.text, /<script>|<b>/);
    });

    it("uses the new refresh token after a re-authorization", async function () {
      await helper.load(oauth2AuthNode, flow, storedCredentials());
      const state = await startAuthorization();
      // expires_in 0 forces a refresh on the next input
      tokenServer.respondWith(200, { access_token: "AUTH_ACCESS", refresh_token: "AUTH_REFRESH", expires_in: 0 });
      await helper.request().get("/oauth2-auth/callback").query({ code: "abc", state }).expect(200);

      tokenServer.reset();
      tokenServer.respondWith(200, { access_token: "REFRESHED", expires_in: 7200 });
      const received = waitFor(helper.getNode("h1"), "input");

      helper.getNode(NODE_ID).receive({ payload: "x" });

      const msg = await received;
      assert.strictEqual(tokenServer.requests[0].form.refresh_token, "AUTH_REFRESH");
      assert.strictEqual(msg.headers.Authorization, "Bearer REFRESHED");
    });
  });
});
