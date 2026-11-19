//! The MCP client mcpg dials with. It speaks protocol revision
//! `2026-07-28`, the stateless wire.
//!
//! The gateway and the inspector share this one outbound MCP
//! implementation:
//!
//! - [`upstream`] — the client itself: Streamable HTTP and stdio
//!   transports, `server/discover` at connect, the per-request `_meta`
//!   identity and SEP-2243 routing headers, `subscriptions/listen` and
//!   `events/stream` streams, MRTR retries, SSRF-guarded dialing,
//!   `tunnel://` upstream resolution.
//! - [`wire`] — the deliberately minimal client-side JSON-RPC codec
//!   and typed list results.
//! - [`transport`] — the `UpstreamTransport` config enum.
//! - [`auth`] — the client half of MCP authorization: `WWW-Authenticate`
//!   challenges and the RFC 9728 → RFC 8414 discovery chain.
//! - [`signer`] — the hook for authorization schemes whose credential is
//!   computed per request rather than held in a static header.
//! - [`tap`] — the raw-frame observation seam.
//!
//! Frame types come from `mcpg-mcp-wire`; the federation engine
//! (satellite pooling, capability overlay, downstream projection) stays
//! in the gateway.

pub mod auth;
pub mod signer;
pub mod tap;
pub mod transport;
pub mod upstream;
pub mod wire;
