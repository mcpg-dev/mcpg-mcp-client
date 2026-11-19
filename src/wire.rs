//! MCP JSON-RPC *client* wire types for the upstream client.
//!
//! These are the client side of MCP — MCPG sends requests and parses
//! responses — distinct from the server-side wire types in
//! `mcpg-mcp-wire`, which are direction-inverted. Kept lean: the
//! JSON-RPC envelope, the list results the client walks, and the
//! response-body reader.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// `clientInfo.name` MCPG advertises to upstreams.
pub const CLIENT_NAME: &str = "mcpg-federation";

/// Outbound JSON-RPC request.
#[derive(Debug, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub id: u64,
    pub method: &'static str,
    pub params: Value,
}

impl JsonRpcRequest {
    pub fn call(id: u64, method: &'static str, params: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
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
    /// The typed detail a code carries (e.g. `{kind}` on an Events
    /// `-32011`, `{limit, max}` on `-32013`). Kept so a caller can tell the
    /// conditions one code spans apart.
    #[serde(default)]
    pub data: Option<Value>,
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

/// The JSON-RPC response of an `application/json` Streamable-HTTP body.
pub fn parse_jsonrpc_body(body: &str) -> Result<JsonRpcResponse, String> {
    serde_json::from_str(body).map_err(|e| format!("invalid JSON-RPC body: {e}"))
}

/// The end (exclusive) of the first complete SSE event in `buf` whose
/// closing blank line ends at or after `from`. Events end with a blank
/// line, in LF or CRLF form.
pub fn sse_event_end(buf: &[u8], from: usize) -> Option<usize> {
    (from.max(1)..buf.len()).find_map(|i| {
        let blank_line = buf[i] == b'\n'
            && (buf[i - 1] == b'\n' || (i >= 2 && buf[i - 1] == b'\r' && buf[i - 2] == b'\n'));
        blank_line.then_some(i + 1)
    })
}

/// The response to request `id` an SSE event carries: `None` for a
/// notification, a server request, or a response to another id. The
/// event's `data:` lines join into one JSON document.
pub fn sse_response_frame(event: &[u8], id: u64) -> Option<JsonRpcResponse> {
    let text = std::str::from_utf8(event).ok()?;
    let mut data = String::new();
    for line in text.lines() {
        let Some(value) = line.strip_prefix("data:") else {
            continue;
        };
        if !data.is_empty() {
            data.push('\n');
        }
        data.push_str(value.strip_prefix(' ').unwrap_or(value));
    }
    let value: Value = serde_json::from_str(data.trim()).ok()?;
    if value.get("method").is_some() || value.get("id").and_then(Value::as_u64) != Some(id) {
        return None;
    }
    let response: JsonRpcResponse = serde_json::from_value(value).ok()?;
    (response.result.is_some() || response.error.is_some()).then_some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_serializes_a_call() {
        let call = JsonRpcRequest::call(7, "tools/list", json!({"cursor": "c"}));
        let v = serde_json::to_value(&call).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], 7);
        assert_eq!(v["method"], "tools/list");
        assert_eq!(v["params"]["cursor"], "c");
    }

    #[test]
    fn parse_plain_json_result() {
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}"#;
        let resp = parse_jsonrpc_body(body).unwrap();
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn parse_plain_json_error() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}"#;
        let resp = parse_jsonrpc_body(body).unwrap();
        let err = resp.error.unwrap();
        assert_eq!(err.code, -32601);
        assert_eq!(err.message, "no such method");
        assert_eq!(err.data, None);
    }

    #[test]
    fn parse_error_keeps_data() {
        let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32013,"message":"limit reached","data":{"limit":"subscriptions","max":100}}}"#;
        let err = parse_jsonrpc_body(body).unwrap().error.unwrap();
        assert_eq!(err.code, -32013);
        assert_eq!(
            err.data,
            Some(json!({ "limit": "subscriptions", "max": 100 }))
        );

        let sse = b"event: message\n\
                    data: {\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{\"code\":-32011,\"message\":\"x\",\"data\":{\"kind\":\"event\"}}}\n\n";
        let err = sse_response_frame(sse, 2).unwrap().error.unwrap();
        assert_eq!(err.data, Some(json!({ "kind": "event" })));
    }

    #[test]
    fn an_sse_response_frame_answers_its_own_id() {
        let progress = b"event: message\n\
                         data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n";
        assert!(sse_response_frame(progress, 3).is_none());
        let answer = b"event: message\n\
                       data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[]}}\n\n";
        assert!(sse_response_frame(answer, 3).unwrap().result.is_some());
        assert!(
            sse_response_frame(answer, 4).is_none(),
            "a response to another id"
        );
        let split = b"data: {\"jsonrpc\":\"2.0\",\"id\":3,\r\ndata: \"result\":{}}\r\n\r\n";
        assert!(sse_response_frame(split, 3).is_some(), "data lines join");
    }

    #[test]
    fn an_sse_event_ends_at_a_blank_line() {
        assert_eq!(sse_event_end(b"data: a\n\ndata: b\n\n", 0), Some(9));
        assert_eq!(sse_event_end(b"data: a\r\n\r\nrest", 0), Some(11));
        assert_eq!(sse_event_end(b"data: a\n", 0), None);
        assert_eq!(
            sse_event_end(b"data: a\n\ndata: b\n\n", 9),
            Some(18),
            "the search resumes past an event already taken"
        );
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
