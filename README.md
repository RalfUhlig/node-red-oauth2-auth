# node-red-oauth2-auth

OAuth2 client for getting oauth2 credentials by the authorization flow to use in other nodes. Credentials are automatically refreshed on expiration. After a successful authorization, the msg object has an element
*headers/Authorization* with the value **Bearer** *access token*. This element can directly be used for the authentication in the htmlRequest node.

The former new element *bearerToken* was removed with version 0.4.0. Sorry for the breaking change.

With version 0.4.0, node-red will now store valid tokens on shutdown and reload them on start. So there
is no need anymore to do the autorization procedure again after node-red was restarted.

I liked to have an indepentent implementation of the oauth2 authentication flow.
Inspired by <https://github.com/node-red/node-red-web-nodes/tree/master/google>, I implemented this node in a similar way.

Maybe it's useful for others. Up to now, there are no releases.
