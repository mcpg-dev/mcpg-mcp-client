//! The MCP client mcpg dials with.
//!
//! Extracted from the gateway's federation engine so the gateway and
//! the inspector share one outbound MCP implementation:
//!
//! - [`upstream`] — the client itself: Streamable HTTP and stdio
//!   transports, the SEP-2575 connect-time wire probe, session
//!   handling on the sessionful wire, per-request `_meta` + SEP-2243
//!   headers on the stateless wire, notification and
//!   `subscriptions/listen` streams, bridged server→client request
//!   walking, SSRF-guarded dialing, `tunnel://` upstream resolution.
//! - [`wire`] — the deliberately minimal client-side JSON-RPC codec
//!   and typed list results.
//! - [`transport`] — the `UpstreamTransport` config enum.
//! - [`auth`] — the client half of MCP authorization: `WWW-Authenticate`
//!   challenges and the RFC 9728 → RFC 8414 discovery chain.
//! - [`signer`] — the hook for authorization schemes whose credential is
//!   computed per request rather than held in a static header.
//!
//! Frame types come from `mcpg-mcp-wire`; the federation engine
//! (satellite pooling, capability overlay, downstream bridging) stays
//! in the gateway. Parts of the client surface are exercised only by
//! the gateway and its tests, so dead-code is silenced crate-wide,
//! matching the module's posture before extraction.
#![allow(dead_code)]

pub mod auth;
pub mod signer;
pub mod tap;
pub mod transport;
pub mod upstream;
pub mod wire;
