# mcpg-mcp-client

The MCP client mcpg dials with. Speaks both current protocol
revisions — the `2025-11-25` sessionful wire (initialize +
`Mcp-Session-Id`) and the `2026-07-28` stateless wire (per-request
`_meta` identity + SEP-2243 routing headers) — selected by a
SEP-2575 connect-time probe or pinned per upstream. Transports:
Streamable HTTP (per-request SSE, notification and
`subscriptions/listen` streams) and stdio child processes, with
SSRF-guarded dialing and `tunnel://` upstream resolution. Frame
types come from `mcpg-mcp-wire`; the mcpg gateway's federation
engine and the mcpg inspector both drive this client, so what the
inspector shows is what the gateway does.

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
