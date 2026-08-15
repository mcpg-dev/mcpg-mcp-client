//! MCP JSON-RPC *client* wire types for the federation upstream
//! client.
//!
//! These are the client side of MCP — MCPG sends requests and parses
//! responses — distinct from the gateway's server-side wire types
//! (`protocol/v_*`), which are direction-inverted. Kept lean: just
//! what the client needs (`initialize`, `tools/list`, `tools/call`).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `clientInfo.name` MCPG advertises to upstreams.
pub const CLIENT_NAME: &str = "mcpg-federation";

/// Outbound JSON-RPC message. A request when `id` is `Some`, a
/// notification when `None`.
#[derive(Debug, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    pub method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn call(id: u64, method: &'static str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id: Some(id),
            method,
            params,
        }
    }
    pub fn notification(method: &'static str, params: Option<Value>) -> Self {
        Self {
            jsonrpc: "2.0",
            id: None,
            method,
            params,
        }
    }
}

/// Inbound JSON-RPC response. `id` is intentionally not modelled: the
/// upstream client issues one request at a time per connection, so
/// correlation is implicit.
#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse {
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// An upstream tool descriptor (MCP wire shape). Maps onto the
/// gateway's `ToolDescriptor` at import time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamTool {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// `tools/list` result body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListToolsResult {
    #[serde(default)]
    pub tools: Vec<UpstreamTool>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// An upstream resource descriptor (MCP wire shape). Maps onto the
/// gateway's `ResourceDescriptor` at import time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamResource {
    pub uri: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// `resources/list` result body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResourcesResult {
    #[serde(default)]
    pub resources: Vec<UpstreamResource>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// An upstream resource *template* descriptor (MCP wire shape). Maps onto
/// the gateway's `ResourceTemplate` at import time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamResourceTemplate {
    pub uri_template: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// `resources/templates/list` result body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResourceTemplatesResult {
    #[serde(default)]
    pub resource_templates: Vec<UpstreamResourceTemplate>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// An upstream prompt descriptor (MCP wire shape). Maps onto the
/// gateway's `PromptDescriptor` at import time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpstreamPrompt {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub arguments: Vec<UpstreamPromptArgument>,
    #[serde(default, rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamPromptArgument {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
}

/// `prompts/list` result body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListPromptsResult {
    #[serde(default)]
    pub prompts: Vec<UpstreamPrompt>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Extract the JSON-RPC response from a Streamable-HTTP body, which is
/// either `application/json` (the object directly) or
/// `text/event-stream` (one or more `data:` frames — we take the last
/// frame carrying a `result` or `error`, i.e. the terminal response).
///
/// MCPG advertises no sampling/elicitation capability upstream here,
/// so a well-behaved upstream emits only the terminal response on the
/// call's stream.
pub fn parse_jsonrpc_body(is_sse: bool, body: &str) -> Result<JsonRpcResponse, String> {
    if !is_sse {
        return serde_json::from_str(body).map_err(|e| format!("invalid JSON-RPC body: {e}"));
    }
    let mut terminal: Option<JsonRpcResponse> = None;
    for raw in body.lines() {
        let line = raw.trim_start();
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() {
            continue;
        }
        if let Ok(resp) = serde_json::from_str::<JsonRpcResponse>(data)
            && (resp.result.is_some() || resp.error.is_some())
        {
            terminal = Some(resp);
        }
    }
    terminal.ok_or_else(|| "no JSON-RPC response frame in SSE stream".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serializes_call_and_notification() {
        let call = JsonRpcRequest::call(7, "tools/list", Some(json!({"cursor": "c"})));
        let v = serde_json::to_value(&call).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["method"], "tools/list");
        assert_eq!(v["params"]["cursor"], "c");

        let note = JsonRpcRequest::notification("notifications/initialized", None);
        let v = serde_json::to_value(&note).unwrap();
        assert!(v.get("id").is_none(), "notifications carry no id");
        assert!(v.get("params").is_none());
    }

    #[test]
    fn parse_plain_json_result() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let resp = parse_jsonrpc_body(false, body).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn parse_plain_json_error() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#;
        let resp = parse_jsonrpc_body(false, body).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "no such method");
    }

    #[test]
    fn parse_sse_takes_terminal_response_frame() {
        // A progress/notification frame, then the terminal result frame.
        let body = "event: message\n\
                    data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\
                    \n\
                    event: message\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[]}}\n\
                    \n";
        let resp = parse_jsonrpc_body(true, body).unwrap();
        assert!(resp.result.is_some());
    }

    #[test]
    fn parse_sse_without_response_frame_errors() {
        let body = "event: message\n\
                    data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n";
        assert!(parse_jsonrpc_body(true, body).is_err());
    }

    #[test]
    fn upstream_tool_deserializes_camel_case_schema() {
        let v = json!({
            "name": "search",
            "description": "Search things",
            "inputSchema": {"type": "object"},
            "_meta": {"x": 1}
        });
        let t: UpstreamTool = serde_json::from_value(v).unwrap();
        assert_eq!(t.name, "search");
        assert!(t.input_schema.is_some());
        assert!(t.meta.is_some());
        assert!(t.title.is_none());
    }
}
