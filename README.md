# mcpg-mcp-client

The MCP client mcpg dials with. Speaks MCP `2026-07-28`, the
stateless wire: `server/discover` at connect, the per-request `_meta`
identity on every request, SEP-2243 routing headers, MRTR retries and
`subscriptions/listen` for change notifications. Transports:
Streamable HTTP (per-request SSE, `subscriptions/listen` and
`events/stream` streams) and stdio child processes (newline-delimited
JSON-RPC), with SSRF-guarded dialing and `tunnel://` upstream
resolution. Frame types come from `mcpg-mcp-wire`; the mcpg gateway's
federation engine and the mcpg inspector both drive this client, so
what the inspector shows is what the gateway does.

This repository is read-only: development happens upstream, and each release
is published here as a tagged snapshot. Issues are welcome. Consume the crate
by git reference:

```toml
[dependencies]
mcpg-mcp-client = { git = "https://github.com/mcpg-dev/mcpg-mcp-client", tag = "<release-tag>" }
```

## Building and testing

```sh
cargo build
cargo test
```
