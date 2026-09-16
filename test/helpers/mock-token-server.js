"use strict";

const http = require("http");

// Minimal OAuth2 token endpoint for tests. The next response is set per test
// with respondWith(); every received request is recorded in `requests`.
function createMockTokenServer() {
  const server = http.createServer((req, res) => {
    let body = "";

    req.on("data", (chunk) => body += chunk);
    req.on("end", () => {
      mock.requests.push({
        method: req.method,
        headers: req.headers,
        form: Object.fromEntries(new URLSearchParams(body))
      });

      const { status, contentType, body: responseBody } = mock.response;
      res.writeHead(status, { "Content-Type": contentType });
      res.end(typeof responseBody === "string" ? responseBody : JSON.stringify(responseBody));
    });
  });

  const mock = {
    requests: [],
    response: null,

    get url() {
      return "http://127.0.0.1:" + server.address().port + "/token";
    },

    respondWith(status, body, contentType) {
      mock.response = {
        status,
        body,
        contentType: contentType || (typeof body === "string" ? "text/html; charset=UTF-8" : "application/json")
      };
    },

    reset() {
      mock.requests = [];
      mock.response = null;
    },

    start() {
      return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    },

    stop() {
      return new Promise((resolve) => server.close(resolve));
    }
  };

  return mock;
}

module.exports = { createMockTokenServer };
