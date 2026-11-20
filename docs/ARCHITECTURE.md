# Developersia AI architecture

```text
ChatGPT / Claude / Developersia Dashboard
                 |
          OAuth 2.1 + MCP
                 |
      Developersia AI Core (Node.js)
       |         |           |
     OAuth    PostgreSQL   MCP Tools
                              |
                      Encrypted Site Tokens
                              |
                 WordPress Connector Plugin
                              |
                  WordPress REST + Capabilities
```

## Product boundaries

The core owns identity, OAuth clients, tokens, subscriptions (future), site connections, audit events and tool routing. The WordPress plugin is a narrowly scoped adapter that executes explicitly authorized WordPress operations using the capabilities of the admin account that paired it.

The model is not the owner of credentials. Models receive tool schemas and structured results; the platform retains credentials and applies authorization.

## Extension strategy

New products should be added as independent modules with their own scopes, schemas, service adapters and tests. Avoid putting product-specific code into the OAuth or site-pairing core. The current WordPress module is the first vertical slice, not a product boundary for the entire Developersia brand.
