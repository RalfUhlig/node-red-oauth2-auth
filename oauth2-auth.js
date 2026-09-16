module.exports = function (RED) {
  "use strict";

  const crypto = require("crypto");
  const request = require('request');

  // Some WAFs (e.g. Cloudflare in front of Trakt) reject requests without a User-Agent
  // or with a lower-case "node" in it, so keep this spelling.
  const USER_AGENT = "Node-RED-OAuth2-Auth/" + require("./package.json").version;

  function escapeHtml(text) {
    return String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  }

  // Returns null if the token endpoint response is usable, otherwise an error message.
  function validateTokenResponse(result, data) {
    const status = result && result.statusCode;
    const isObject = data !== null && typeof data === "object";

    if (!status || status < 200 || status >= 300 || !isObject || data.error) {
      let detail;

      if (isObject && data.error) {
        detail = data.error + (data.error_description ? ": " + data.error_description : "");
      } else if (data !== undefined && data !== null && data !== "") {
        detail = (typeof data === "string" ? data : JSON.stringify(data)).substring(0, 200);
      }

      return "HTTP " + status + (detail ? " - " + detail : "");
    }

    if (typeof data.access_token !== "string" || !data.access_token) {
      return "HTTP " + status + " - response contains no access_token";
    }

    return null;
  }

  function OAuth2AuthConfig(config) {
    RED.nodes.createNode(this, config);
  }

  RED.nodes.registerType("oauth2-auth-config", OAuth2AuthConfig);

  function OAuth2Auth(config) {
    RED.nodes.createNode(this, config);

    var node = this;
   
    node.on('input', function (msg) {
      node.status({ fill: "blue", shape: "dot", text: RED._("oauth2auth.status.refreshing") });

      node.refreshNodeCredentials((err) => {
        node.status({});

        if (err) {
          node.status({ fill: "red", shape: "dot", text: RED._("oauth2auth.status.failed") });
          return node.error(err);
        }

        const creds = RED.nodes.getCredentials(node.id);

        if (!creds || !creds.access_token) {
          return node.error(RED._("OAuth2Auth.error.no_access_token"));
        }

        msg.headers = {
          Authorization: 'Bearer ' + creds.access_token
        };

        node.send(msg);
      });
    });
  }

  RED.nodes.registerType("oauth2-auth", OAuth2Auth, {
    credentials: {
      client_id: { type: "text" },
      client_secret: { type: "password" },
      access_token_url: { type: "text" },
      access_token: { type: "password" },
      refresh_token: { type: "password" },
      expire_time: { type: "text" },
      expires_in: { type: "text" },
      auth_time: { type: "text" },
    }
  });

  OAuth2Auth.prototype.refreshNodeCredentials = function (callback) {
    const node = this;

    // Load current creadentials
    const creds = RED.nodes.getCredentials(node.id);

    if (!creds) {
      const err = "No credentials found for OAuth2 node.";
      node.error(RED._("oauth2auth.error.no_credentials", { error: err}));
      return callback(err);
    }

    // Ensure, that the credentials are complete.
    if (!creds.client_id || !creds.client_secret || !creds.refresh_token) {
      const err = "OAuth2 credentials incomplete (missing client_id, client_secret or refresh_token).";
      node.error(RED._("oauth2auth.error.invalid_credentials", { error: err}));
      return callback(err);
    }

    const now = Math.floor(Date.now() / 1000);

    // Is the access token still valid?
    if (creds.expire_time && Number(creds.expire_time) > now) {
        return callback(null);   // Access token is valid
    }

    // Access token is expiured - Perform refresh
    request.post({
      url: creds.access_token_url,
      json: true,
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json'
      },
      form: {
        grant_type: 'refresh_token',
        client_id: creds.client_id,
        client_secret: creds.client_secret,
        refresh_token: creds.refresh_token
      }
    }, 
    function (err, result, data) {
      if (err) {
        node.error(RED._("oauth2auth.error.get_access_token", { error: err }));
        return callback(err);
      }

      const responseError = validateTokenResponse(result, data);

      if (responseError) {
        node.error(RED._("oauth2auth.error.something_broke", { error: responseError }));
        return callback(responseError);
      }

      const expiresIn = Number(data.expires_in) || 0;

      const newCredentials = {
        ...creds,
        access_token:  data.access_token,
        refresh_token: data.refresh_token || creds.refresh_token,
        expires_in:    expiresIn,
        expire_time:   now + expiresIn,
        auth_time:     now
      };

      // Store new credentials.
      RED.nodes.addCredentials(node.id, newCredentials);

      return callback(null);
    });
  }

  RED.httpAdmin.get('/oauth2-auth/auth', function (req, res) {
    if (!req.query.id || !req.query.client_id || !req.query.client_secret || !req.query.authentication_url || !req.query.redirect_url || !req.query.access_token_url) {
      res.send(400);
      return;
    }

    var node_id = req.query.id;
    var client_id = req.query.client_id;
    var client_secret = req.query.client_secret;
    var scope = req.query.scope;
    var force_login = req.query.force_login;
    var authentication_url = req.query.authentication_url;
    var redirect_url = req.query.redirect_url;
    var access_token_url = req.query.access_token_url;
    var csrf_token = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
    var state = node_id + ":" + csrf_token;

    var credentials = {
      client_id: client_id,
      client_secret: client_secret,
      redirect_url: redirect_url,
      access_token_url: access_token_url,
      csrf_token: csrf_token
    };

    RED.nodes.addCredentials(node_id, credentials);

    var authentication_url_obj = new URL(authentication_url);
    authentication_url_obj.search = new URLSearchParams({
      client_id: credentials.client_id,
      redirect_uri: redirect_url,
      response_type: 'code',
      state: state,
      scope: scope,
      prompt: force_login.toLowerCase() === "true" ? "login" : "consent"
    });

    res.cookie('csrf', csrf_token);
    res.redirect(authentication_url_obj.href);
  });

  RED.httpAdmin.get('/oauth2-auth/callback', function (req, res) {
    if (req.query.error) {
      return res.send(RED._("oauth2auth.error.error", { error: req.query.error, description: req.query.error_description }));
    }

    if (!req.query.code || !req.query.state) {
      return res.status(400).send(RED._("oauth2auth.error.error", { error: "invalid_request", description: "Missing code or state." }));
    }

    var auth_code = req.query.code;
    var state = req.query.state.split(':');
    var node_id = state[0];
    var credentials = RED.nodes.getCredentials(node_id);

    if (!credentials || !credentials.client_id || !credentials.client_secret) {
      return res.send(RED._("oauth2auth.error.no_credentials"));
    }

    if (state[1] !== credentials.csrf_token) {
      return res.status(401).send(RED._("oauth2auth.error.csrf_token_mismatch"));
    }
   
    request.post({
      url: credentials.access_token_url,
      json: true,
      headers: {
        'User-Agent': USER_AGENT,
        'Accept': 'application/json'
      },
      form: {
        grant_type: 'authorization_code',
        code: auth_code,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        redirect_uri: credentials.redirect_url,
      }
    },
      function (err, result, data) {
        if (err) {
          return res.send(RED._("oauth2auth.error.get_access_token", { error: err }));
        }

        // Don't store anything if the token exchange failed.
        const responseError = validateTokenResponse(result, data);

        if (responseError) {
          return res.status(502).send(RED._("oauth2auth.error.something_broke", { error: escapeHtml(responseError) }));
        }

        const now = Math.floor(Date.now() / 1000);
        const expiresIn = Number(data.expires_in) || 0;

        credentials.access_token = data.access_token;
        if (data.refresh_token) {
          credentials.refresh_token = data.refresh_token;
        }
        credentials.expires_in = expiresIn;
        credentials.expire_time = now + expiresIn;
        credentials.auth_time = now;

        delete credentials.csrf_token;
        delete credentials.redirect_url;

        RED.nodes.addCredentials(node_id, credentials);

        res.send(RED._("oauth2auth.message.authorisation_successful"));
      });
  });
}
