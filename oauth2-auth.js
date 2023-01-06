module.exports = function (RED) {
  "use strict";

  const crypto = require("crypto");
  const fs = require('fs');
  const path = require('path');
  const request = require('request');

  function OAuth2Auth(config) {
    RED.nodes.createNode(this, config);

    var node = this;

    node.credentials = loadNodeCredentials(node.id, (err) => node.warn(err));

    node.on('input', function (msg) {
      refreshCredentials(node.id, node.credentials, (credentials, err) => 
      {
        if (err) {
          node.error(err);
        }

        node.credentials = credentials;
        msg.bearerToken = 'Bearer ' + node.credentials.access_token;
        node.send(msg);
      });
    });
  }

  RED.nodes.registerType("oauth2-auth", OAuth2Auth, {
    credentials: {
      client_id: { type: "text" },
      client_secret: { type: "password" },
      access_token_url: { type: "password" },
      access_token: { type: "password" },
      refresh_token: { type: "password" },
      expire_time: { type: "password" }
    }
  });

  function loadNodeCredentials(node_id, error_callback) {
    const filepath = path.join(RED.settings.userDir, 'node_' + node_id + '_cred.json')
    const encoding = 'utf8';

    try {
      if (!fs.existsSync(filepath)) {
        return {};
      }

      const content = fs.readFileSync(filepath, encoding);
      const credentials = JSON.parse(content);

      RED.nodes.addCredentials(node_id, credentials);

      return credentials;
    }
    catch (error) {
      if (error_callback) {
        error_callback(RED._("oauth2auth.error.load_node_credentials", { error: error }));
      }

      return {};
    }
  }
  function saveNodeCredentials(node_id, credentials, error_callback) {
    const filepath = path.join(RED.settings.userDir, 'node_' + node_id + '_cred.json');
    const content = JSON.stringify(credentials);
    const encoding = 'utf8';

    try {
      fs.writeFileSync(filepath, content, encoding);
    }
    catch (error) {
      if (error_callback) {
        error_callback(RED._("save_node_credentials", { error: error }));
      }
    }
  }

  function refreshCredentials(node_id, credentials, callback) {
    if (!credentials || !credentials.expire_time) {
      credentials = loadNodeCredentials(node_id);
    }

    if (credentials && credentials.expire_time && credentials.expire_time >= (new Date().getTime() / 1000)) {
      return callback(credentials, null);
    }

    request.post({
      url: credentials.access_token_url,
      json: true,
      form: {
        grant_type: 'refresh_token',
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        refresh_token: credentials.refresh_token
      }
    },
      function (err, result, data) {
        if (err) {
          return callback(credentials, RED._("oauth2auth.error.get_access_token", { error: err }));
        }

        if (data.error) {
          return callback(credentials, RED._("oauth2auth.error.something_broke", { error: data.error }));
        }

        credentials.access_token = data.access_token;
        credentials.refresh_token = data.refresh_token;
        credentials.expires_in = data.expires_in;
        credentials.expire_time = data.expires_in + (new Date().getTime() / 1000);

        RED.nodes.addCredentials(node_id, credentials);
        saveNodeCredentials(node_id, credentials);

        return callback(credentials, null);
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

    var authentication_url_obj = new URL(authentication_url);
    authentication_url_obj.search = new URLSearchParams({
      client_id: credentials.client_id,
      redirect_uri: redirect_url,
      response_type: 'code',
      state: state,
      scope: scope
    });

    res.cookie('csrf', csrf_token);
    res.redirect(authentication_url_obj.href);

    RED.nodes.addCredentials(node_id, credentials);
  });

  RED.httpAdmin.get('/oauth2-auth/callback', function (req, res) {
    if (req.query.error) {
      return res.send(RED._("oauth2auth.error.error", { error: req.query.error, description: req.query.error_description }));
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

        if (data.error) {
          return res.send(RED._("oauth2auth.error.something_broke", { error: data.error }));
        }

        credentials.access_token = data.access_token;
        credentials.refresh_token = data.refresh_token;
        credentials.expires_in = data.expires_in;
        credentials.expire_time = data.expires_in + (new Date().getTime() / 1000);

        delete credentials.csrf_token;
        delete credentials.redirect_url;

        RED.nodes.addCredentials(node_id, credentials);
        saveNodeCredentials(node_id, credentials);

        res.send(RED._("oauth2auth.message.authorisation_successful"));
      });
  });

  // function decryptCredentials(key, credentials) {
  //   var encryptionAlgorithm = "aes-256-ctr";
  //   var creds = credentials["$"];
  //   var initVector = Buffer.from(creds.substring(0, 32),'hex');
  //   creds = creds.substring(32);
  //   var decipher = crypto.createDecipheriv(encryptionAlgorithm, key, initVector);
  //   var decrypted = decipher.update(creds, 'base64', 'utf8') + decipher.final('utf8');
  //   return JSON.parse(decrypted);
  // }

  // function encryptCredentials(key, credentials) {
  //   var encryptionAlgorithm = "aes-256-ctr";
  //   var creds = credentials["$"];
  //   var initVector = Buffer.from(creds.substring(0, 32),'hex');
  //   creds = creds.substring(32);
  //   var decipher = crypto.createDecipheriv(encryptionAlgorithm, key, initVector);
  //   var decrypted = decipher.update(creds, 'base64', 'utf8') + decipher.final('utf8');
  //   return JSON.parse(decrypted);
  // }
}

