# node-red-oauth2-auth

OAuth2 client for getting oauth2 credentials by the authorization flow to use in other nodes. Credentials are automatically refreshed on expiration. After a successful authorization, the msg object has an element
*headers/Authorization* with the value **Bearer** *access token*. This element can directly be used for the authentication in the htmlRequest node.

The former new element *bearerToken* was removed with version 0.4.0. Sorry for the breaking change.

With version 0.4.0, node-red will now store valid tokens on shutdown and reload them on start. So there
is no need anymore to do the autorization procedure again after node-red was restarted.

With version 0.4.2, a failed token request (e.g. an HTTP error or a non-JSON answer from the token endpoint) is
reported as an error and no longer stored as a successful authorization. Token requests now send the User-Agent
*Node-RED-OAuth2-Auth/&lt;version&gt;*, because some providers behind a web application firewall (e.g. Trakt) reject
requests without one.

With version 0.5.0, the deprecated *request* library was replaced by the *fetch* function built into Node.js.
The node no longer has any runtime dependencies. Token requests now time out after 30 seconds.

I liked to have an indepentent implementation of the oauth2 authentication flow.
Inspired by <https://github.com/node-red/node-red-web-nodes/tree/master/google>, I implemented this node in a similar way.

Maybe it's useful for others. Up to now, there are no releases.
