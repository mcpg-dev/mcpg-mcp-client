use serde::{Deserialize, Serialize};

/// Upstream wire transport.
#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamTransport {
    /// MCP Streamable HTTP (POST + SSE).
    #[default]
    StreamableHttp,
    /// Local stdio child process.
    Stdio,
}
