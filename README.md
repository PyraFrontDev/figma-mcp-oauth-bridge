# Figma MCP OAuth Bridge

A local gateway that connects Figma Desktop to an external AI client (Perplexity) over the Model Context Protocol. Instead of going through Figma's REST API (rate limits, access tokens, the usual friction), the gateway talks to a plugin running inside Figma Desktop and runs its own OAuth 2.0 authorization server, built from scratch.

## Background

I wanted to pull design context out of Figma (tokens, styles, components) straight into an AI client, without the Figma REST API or a Personal Access Token. The approach: the gateway acts as an MCP client itself. It connects over STDIO to a local plugin bridge, `figma-mcp-go`, which works against the running Figma Desktop app. The gateway then exposes a narrow, read-only slice of what that bridge can do.

## How it's wired together

```
Figma Desktop (plugin: figma-mcp-go)
        | STDIO
        v
Node.js gateway (Express)
        |  - custom OAuth 2.0 server (PKCE, JWT via `jose`)
        |  - read-only tool allowlist (21 tools)
        |  - MCP transport (StreamableHTTPServerTransport)
        v
HTTPS tunnel (ngrok)
        v
External MCP client (Perplexity connector)
```

The gateway connects to `figma-mcp-go` the way any AI client would: it calls `listTools()`, filters the result down to an allowlist, and re-registers only those tools on its own MCP server. Anything outside the list is never reachable from outside.

## What's in the code

- **OAuth 2.0 authorization server.** `/authorize` (login form and validation), `/token` (`authorization_code` and `refresh_token` grants), and the metadata endpoints `/.well-known/oauth-authorization-server` and `/.well-known/oauth-protected-resource`. PKCE (S256) is mandatory, with no fallback.
- **JWT access tokens.** Signed with HS256 via `jose`, with `issuer` and `audience` pinned to the gateway's own URL and a configurable lifetime.
- **Redirect URI allowlist.** Only known Perplexity callback URLs (prod, enterprise, staging) and the local MCP Inspector callback are accepted. Everything else is rejected before an authorization code is issued.
- **Read-only tool allowlist.** Of everything `figma-mcp-go` exposes, only 21 read tools (`get_design_context`, `export_tokens`, `get_variable_defs`, and so on) are registered on the gateway. Nothing that writes to the Figma file is reachable.
- **Session handling.** Streamable HTTP transport with per-session MCP servers and a bearer token check on every `/mcp` request.

## The 401 that turned out to be an SDK issue

The hardest part had little to do with OAuth itself. I was getting a 401 and then a failed handshake even though the token was issued correctly, the signature was valid, and `aud`/`iss` matched, so everything I would normally check first was fine.

I went layer by layer instead of guessing:

1. **Infrastructure.** The tunnel and port forwarding were healthy.
2. **Network and CORS.** Requests reached the server and were not blocked on a preflight mismatch.
3. **Auth.** The token was issued and validated correctly, checked independently of the AI client.
4. **Protocol.** The failure appeared only during the MCP handshake, at tool registration.
5. **SDK source.** `@modelcontextprotocol/sdk` validates tool `inputSchema` through Standard Schema (Zod), and I was passing plain JSON Schema objects straight from `figma-mcp-go`.

The fix is `jsonSchemaToZodShape()`, a small JSON Schema to Zod converter used at registration time, so tool definitions pass validation without pinning an older SDK. It is its own commit in the history (`Fix tool registration for Standard Schema compatibility`).

## Stack

| Layer | Technology |
|---|---|
| Server | Node.js, Express |
| Auth | OAuth 2.0 (PKCE), JWT (`jose`) |
| Protocol | Model Context Protocol (`@modelcontextprotocol/sdk`) |
| Figma access | `@vkhanhqui/figma-mcp-go` (plugin-based, no Figma PAT) |
| Validation | Zod / Standard Schema |
| Dev tooling | MCP Inspector, nodemon |

## Running it locally

```bash
npm install
cp .env.example .env   # fill in your own values
npm run dev
```

Required environment variables (see `.env.example`):

| Variable | Purpose |
|---|---|
| `PUBLIC_BASE_URL` | Public HTTPS URL the gateway is reachable at, used as `issuer` and `audience` |
| `JWT_SECRET` | Random secret for signing tokens. Generate one with `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"` |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | Login for the `/authorize` form |
| `TOKEN_TTL_SECONDS` | Access token lifetime (default 3600) |

The Figma Desktop app needs to be open with the `figma-mcp-go` plugin running. Expose the gateway through an HTTPS tunnel (for example `ngrok http 8787`) and set `PUBLIC_BASE_URL` to the tunnel address.

No real secrets live in this repository. `.env` is gitignored and the auth logic reads only from `process.env`.

## Known limitations

- Authorization codes and refresh tokens are stored in memory, so they are lost on restart.
- Single-user login (one admin account from `.env`), meant for personal use.
- HS256 with a shared secret; an asymmetric key pair would be the next step for multi-service setups.

## Status

Working end to end: an authenticated connection between Figma Desktop and an external AI client. I use it as the design-token source (colors, typography, spacing) for a newsletter template sent through Listmonk.
