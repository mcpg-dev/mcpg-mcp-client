//! Outbound MCP client for protocol revision `2026-07-28`.
//!
//! [`McpUpstream`] is the direction-clean client seam (kept behind a
//! trait so additional transports and a possible cdylib extraction
//! stay open).
//! [`StreamableHttpUpstream`] implements it over `reqwest` with the same
//! DNS-rebinding/SSRF guard the HTTP backend uses (`net-core`): resolve,
//! reject private addresses, pin the vetted IP to close the rebinding
//! TOCTOU window. [`StdioUpstream`] implements it over a child process's
//! stdin/stdout.
//!
//! The wire is stateless: there is no handshake and no session. Every
//! request carries the protocol version, the client identity and the
//! client capabilities in `params._meta` (SEP-2575); over HTTP every POST
//! also carries `Mcp-Protocol-Version` and the SEP-2243 routing headers.
//! Connect sends `server/discover` and keeps the capabilities the
//! upstream advertises.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use url::Url;

use crate::tap::{FrameChannel, FrameDirection, tap_frame};
use crate::wire::{
    self, JsonRpcRequest, ListPromptsResult, ListResourceTemplatesResult, ListResourcesResult,
    ListToolsResult, UpstreamPrompt, UpstreamResource, UpstreamResourceTemplate, UpstreamTool,
};
use mcpg_mcp_wire::v_2026_07_28::extensions::events::wire as events;
use mcpg_mcp_wire::v_2026_07_28::wire::lifecycle::METHOD_SERVER_DISCOVER;
use mcpg_mcp_wire::v_2026_07_28::wire::{PROTOCOL_VERSION_HEADER, SUPPORTED_PROTOCOL_VERSION};
use mcpg_plugin_backend_net_core::safe_dns;

/// The MCP protocol version MCPG speaks as a client.
const PROTOCOL_VERSION: &str = SUPPORTED_PROTOCOL_VERSION;
/// Loop-detection header. Set on every upstream request.
const VIA_HEADER: &str = "mcpg-upstream-via";
/// Defensive cap on imported tools from a single upstream.
const MAX_IMPORTED_TOOLS: usize = 10_000;
/// Defensive cap on the MCP Events types one `events/list` walk reads.
const MAX_LISTED_EVENT_TYPES: usize = 10_000;
/// Silence after which a long-lived stream is closed for the caller to
/// reopen: twice the heartbeat ceiling of an MCP Events push stream
/// ([`events::MAX_STREAM_HEARTBEAT_MS`]), and four times the 15 s keep-alive
/// mcpg's own SSE streams send.
pub const DEFAULT_STREAM_IDLE_TIMEOUT: Duration =
    Duration::from_millis(2 * events::MAX_STREAM_HEARTBEAT_MS);

/// The `capabilities` object of a `server/discover` result, when it has one.
fn capabilities_of(result: &Value) -> Option<Value> {
    result
        .get("capabilities")
        .filter(|capabilities| capabilities.is_object())
        .cloned()
}

/// The capabilities a `server/discover` result advertises. A result whose
/// `supportedVersions` leaves out the version this client speaks is
/// refused: every later request would be refused too.
fn discovered_capabilities(result: &Value) -> Result<Option<Value>, UpstreamError> {
    if let Some(versions) = result.get("supportedVersions").and_then(Value::as_array)
        && !versions
            .iter()
            .any(|version| version.as_str() == Some(PROTOCOL_VERSION))
    {
        return Err(UpstreamError::Protocol(format!(
            "the upstream does not list MCP {PROTOCOL_VERSION} among its supported versions"
        )));
    }
    Ok(capabilities_of(result))
}

/// The `clientInfo` MCPG presents to an upstream.
fn client_info() -> Value {
    json!({ "name": wire::CLIENT_NAME, "version": env!("CARGO_PKG_VERSION") })
}

/// The `server/discover` params: the version this client pins, its
/// identity and its capabilities.
fn discover_params(client_capabilities: &Value) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "clientInfo": client_info(),
        "capabilities": client_capabilities,
    })
}

/// Merge the per-request `_meta` identity triple (SEP-2575) into a
/// request's `params`, keeping any `_meta` entry the caller set (e.g. a
/// `progressToken`). Params that are not an object get none.
fn inject_request_meta(params: &mut Value, client_capabilities: &Value) {
    use mcpg_mcp_wire::v_2026_07_28::wire::meta::{
        META_KEY_CLIENT_CAPABILITIES, META_KEY_CLIENT_INFO, META_KEY_PROTOCOL_VERSION,
    };
    let Some(obj) = params.as_object_mut() else {
        return;
    };
    let meta = obj.entry("_meta").or_insert_with(|| json!({}));
    if let Some(meta) = meta.as_object_mut() {
        meta.entry(META_KEY_PROTOCOL_VERSION)
            .or_insert_with(|| json!(PROTOCOL_VERSION));
        meta.entry(META_KEY_CLIENT_INFO).or_insert_with(client_info);
        meta.entry(META_KEY_CLIENT_CAPABILITIES)
            .or_insert_with(|| client_capabilities.clone());
    }
}

/// SEP-2243 routing headers for an id-bearing request: `Mcp-Method` (the
/// JSON-RPC method, always), `Mcp-Name` (the tool name / resource uri /
/// prompt name for `tools/call` / `resources/read` / `prompts/get`), and
/// the `Mcp-Param-{Name}` param promotions for `tools/call` when an
/// `inputSchema` is known. Non-ASCII `Mcp-Name` values use the
/// `=?base64?…?=` sentinel.
fn routing_headers(
    method: &str,
    params: &Value,
    input_schema: Option<&Value>,
) -> Vec<(String, String)> {
    use mcpg_mcp_wire::v_2026_07_28::wire::{METHOD_HEADER, NAME_HEADER, encode_header_value};
    let mut headers = vec![(METHOD_HEADER.to_owned(), method.to_owned())];
    let name = match method {
        "tools/call" | "prompts/get" => params.get("name").and_then(Value::as_str),
        "resources/read" => params.get("uri").and_then(Value::as_str),
        _ => None,
    };
    if let Some(name) = name {
        headers.push((NAME_HEADER.to_owned(), encode_header_value(name)));
    }
    // The server-side promoter, so the constraint + encoding rules are
    // identical in both directions.
    if method == "tools/call"
        && let (Some(schema), Some(args)) = (input_schema, params.get("arguments"))
    {
        headers.extend(mcpg_mcp_wire::v_2026_07_28::wire::promote_param_headers(
            schema, args,
        ));
    }
    headers
}

/// Failure modes of an upstream MCP call.
#[derive(Debug)]
pub enum UpstreamError {
    /// Connection setup failed (bad URL, DNS, client build).
    Connect(String),
    /// Transport-level failure (network, body read).
    Transport(String),
    /// Non-2xx HTTP response on a POST. Carries the status and, when the
    /// body held one, the JSON-RPC error: the server answers an error with
    /// the status its code maps to, so the error is the answer and the
    /// status only how it travelled.
    Http {
        status: u16,
        error: Option<wire::JsonRpcError>,
    },
    /// Malformed / unexpected protocol payload.
    Protocol(String),
    /// Upstream resolved to a private address and the guard rejected it.
    Rebinding(String),
    /// Upstream response exceeded the configured byte cap.
    ResponseTooLarge { limit: u64 },
    /// Upstream returned a JSON-RPC error. `data` is the error's `data`
    /// member, kept verbatim; it is the upstream's text, so it is not part
    /// of the `Display` form.
    JsonRpc {
        code: i64,
        message: String,
        data: Option<Value>,
    },
    /// The upstream credential is minted from a sign-in the caller has not
    /// stored, so no request was sent. `message` says how to store one, in
    /// words written for the caller: it names no upstream detail.
    NotLinked { message: String },
    /// The method is not served on this transport, so no request was sent:
    /// MCP Events, for example, is served over HTTP only.
    Unsupported(&'static str),
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "upstream connect error: {m}"),
            Self::Transport(m) => write!(f, "upstream transport error: {m}"),
            Self::Http {
                status,
                error: Some(error),
            } => write!(
                f,
                "upstream returned HTTP {status} (JSON-RPC error {}: {})",
                error.code, error.message
            ),
            Self::Http {
                status,
                error: None,
            } => write!(f, "upstream returned HTTP {status}"),
            Self::Protocol(m) => write!(f, "upstream protocol error: {m}"),
            Self::Rebinding(m) => write!(f, "upstream blocked by DNS-rebinding guard: {m}"),
            Self::ResponseTooLarge { limit } => {
                write!(f, "upstream response exceeded {limit} bytes")
            }
            Self::JsonRpc { code, message, .. } => {
                write!(f, "upstream JSON-RPC error {code}: {message}")
            }
            Self::NotLinked { message } => write!(f, "no stored sign-in: {message}"),
            Self::Unsupported(method) => {
                write!(f, "{method} is not served on this upstream's transport")
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

impl From<wire::JsonRpcError> for UpstreamError {
    fn from(err: wire::JsonRpcError) -> Self {
        Self::JsonRpc {
            code: err.code,
            message: err.message,
            data: err.data,
        }
    }
}

impl UpstreamError {
    /// A JSON-RPC `error` member read off a raw frame. A malformed member
    /// still yields an error (`-32603`), never a success.
    fn from_error_value(err: &Value) -> Self {
        Self::JsonRpc {
            code: err.get("code").and_then(Value::as_i64).unwrap_or(-32603),
            message: err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream error")
                .to_owned(),
            data: err.get("data").cloned(),
        }
    }

    /// The code of the JSON-RPC error the upstream answered with, in a
    /// success body or with an error status.
    pub fn jsonrpc_code(&self) -> Option<i64> {
        match self {
            Self::JsonRpc { code, .. } => Some(*code),
            Self::Http {
                error: Some(error), ..
            } => Some(error.code),
            _ => None,
        }
    }

    /// The `data` of that JSON-RPC error, when it carried any.
    pub fn jsonrpc_data(&self) -> Option<&Value> {
        match self {
            Self::JsonRpc { data, .. } => data.as_ref(),
            Self::Http {
                error: Some(error), ..
            } => error.data.as_ref(),
            _ => None,
        }
    }
}

/// Connection parameters for a single upstream.
#[derive(Clone)]
pub struct UpstreamConnectOptions {
    /// Upstream `/mcp` endpoint.
    pub url: String,
    /// Raw bearer credential (resolved `service_token`, or the
    /// inbound token for `pass_through`). `None` for `auth.mode: none`.
    pub bearer_token: Option<String>,
    /// Org token for a `tunnel://` upstream, sent to the relay's federation
    /// ingress in `X-MCPG-Tunnel-Token` on every request. Distinct from
    /// `bearer_token` (which the relay forwards to the tunnelled gateway as the
    /// end-user identity); the relay consumes this header and never forwards it.
    /// `None` for a direct http(s)/stdio upstream.
    pub tunnel_token: Option<String>,
    /// Permit private/loopback upstream addresses.
    pub allow_private: bool,
    /// Per-call response byte cap, enforced gateway-side.
    pub max_response_bytes: u64,
    /// Per-call timeout.
    pub timeout: Duration,
    /// This gateway instance's loop-detection id (`Mcpg-Upstream-Via`).
    pub gateway_via: String,
    /// Client capabilities advertised to the upstream: the `capabilities`
    /// of `server/discover` and the
    /// `_meta.io.modelcontextprotocol/clientCapabilities` of every request.
    /// `{}` advertises none.
    pub client_capabilities: Value,
    /// Send `server/discover` on connect and keep the capabilities the
    /// upstream advertises; an upstream that does not serve this revision
    /// fails the connect. A connection that reads no capabilities skips the
    /// round trip, and its first request fails instead.
    pub discover: bool,
    /// Wire transport: `StreamableHttp` uses `url`; `Stdio` spawns
    /// `command`/`args`/`env`.
    pub transport: crate::transport::UpstreamTransport,
    /// Static request headers sent on every upstream call (API-key
    /// style upstreams). Reserved protocol headers are rejected at
    /// config validation.
    pub headers: std::collections::BTreeMap<String, String>,
    /// stdio command + args + env (only the `Stdio` transport reads these).
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
    /// Observer for raw frames in both directions ([`crate::tap`]).
    /// `None` records nothing and costs nothing.
    pub tap: Option<crate::tap::SharedTap>,
    /// Pipe the stdio child's stderr and feed each line to the tap
    /// (`StdioStderr` channel). `false` discards stderr, the only useful
    /// choice without a tap.
    pub capture_stdio_stderr: bool,
    /// Computes request-scoped authorization headers ([`crate::signer`]).
    /// `None` (default) sends only the static header map. Only the
    /// `StreamableHttp` transport honors this — stdio has no request headers.
    pub signer: Option<crate::signer::SharedSigner>,
}

/// What to subscribe to: the targets of one `subscriptions/listen`
/// (SEP-2575).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionSpec {
    /// Resource URIs to watch for content changes
    /// (`notifications/resources/updated`).
    pub resource_uris: Vec<String>,
    pub tools_list_changed: bool,
    pub prompts_list_changed: bool,
    pub resources_list_changed: bool,
    /// MCP Events type changes (`notifications/events/list_changed`). An
    /// extension: ask only an upstream that advertises events.
    pub events_list_changed: bool,
}

impl SubscriptionSpec {
    /// Every core catalog change, no per-resource watches. What a UI wants
    /// when it is showing lists and nothing more specific.
    pub fn all_list_changed() -> Self {
        Self {
            resource_uris: Vec::new(),
            tools_list_changed: true,
            prompts_list_changed: true,
            resources_list_changed: true,
            events_list_changed: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.resource_uris.is_empty()
            && !self.tools_list_changed
            && !self.prompts_list_changed
            && !self.resources_list_changed
            && !self.events_list_changed
    }

    /// The typed-array form `subscriptions/listen` carries.
    fn targets(&self) -> Vec<mcpg_mcp_wire::v_2026_07_28::wire::subscriptions::SubscriptionTarget> {
        use mcpg_mcp_wire::v_2026_07_28::wire::subscriptions::SubscriptionTarget;
        let mut out = Vec::new();
        for uri in &self.resource_uris {
            out.push(SubscriptionTarget::ResourcesUpdated { uri: uri.clone() });
        }
        if self.tools_list_changed {
            out.push(SubscriptionTarget::ToolsListChanged);
        }
        if self.prompts_list_changed {
            out.push(SubscriptionTarget::PromptsListChanged);
        }
        if self.resources_list_changed {
            out.push(SubscriptionTarget::ResourcesListChanged);
        }
        if self.events_list_changed {
            out.push(SubscriptionTarget::EventsListChanged);
        }
        out
    }
}

/// What a `tools/call` carries beyond the tool's name and arguments.
#[derive(Debug, Clone, Copy, Default)]
pub struct ToolCallOptions<'a> {
    /// The tool's declared `inputSchema`. Over HTTP it drives the SEP-2243
    /// `Mcp-Param-{Name}` promotion of the arguments it marks.
    pub input_schema: Option<&'a Value>,
    /// Sent as `_meta.progressToken`, so the upstream reports progress
    /// under the caller's token.
    pub progress_token: Option<&'a Value>,
    /// Request-scoped `params._meta` entries. `_meta` belongs on the
    /// params beside `name` and `arguments`: inside `arguments` the
    /// server would treat it as a tool input.
    pub meta: Option<&'a Value>,
    /// The `requestState` of the `InputRequiredResult` this call answers
    /// (SEP-2322), echoed verbatim.
    pub request_state: Option<&'a str>,
    /// The answers to that result's `inputRequests`, keyed by its
    /// correlation tokens.
    pub input_responses: Option<&'a Value>,
}

impl ToolCallOptions<'_> {
    /// The `tools/call` params for `name` and `arguments`.
    fn params(&self, name: &str, arguments: Option<&Value>) -> Value {
        let mut params = serde_json::Map::new();
        params.insert("name".to_owned(), json!(name));
        params.insert(
            "arguments".to_owned(),
            arguments.cloned().unwrap_or_else(|| json!({})),
        );
        if let Some(meta) = self.meta {
            params.insert("_meta".to_owned(), meta.clone());
        }
        if let Some(token) = self.progress_token {
            let meta = params
                .entry("_meta".to_owned())
                .or_insert_with(|| json!({}));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert("progressToken".to_owned(), token.clone());
            }
        }
        if let Some(request_state) = self.request_state {
            params.insert("requestState".to_owned(), json!(request_state));
        }
        if let Some(input_responses) = self.input_responses {
            params.insert("inputResponses".to_owned(), input_responses.clone());
        }
        Value::Object(params)
    }
}

/// A connected upstream MCP server.
#[async_trait]
pub trait McpUpstream: Send + Sync {
    async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError>;
    async fn list_resources(&self) -> Result<Vec<UpstreamResource>, UpstreamError>;
    async fn list_resource_templates(&self)
    -> Result<Vec<UpstreamResourceTemplate>, UpstreamError>;
    async fn read_resource(&self, uri: &str) -> Result<Value, UpstreamError>;
    async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError>;
    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError>;

    /// `tools/call` with nothing beyond the name and arguments.
    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.call_tool_with(name, arguments, &ToolCallOptions::default())
            .await
    }

    /// `tools/call` carrying request-scoped `params._meta`.
    async fn call_tool_with_meta(
        &self,
        name: &str,
        arguments: Option<&Value>,
        meta: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let options = ToolCallOptions {
            meta,
            ..ToolCallOptions::default()
        };
        self.call_tool_with(name, arguments, &options).await
    }

    /// The retry of a `tools/call` that answered `InputRequiredResult`
    /// (SEP-2322): `request_state` and `input_responses` travel as
    /// top-level params beside `name` and `arguments`.
    async fn call_tool_resuming(
        &self,
        name: &str,
        arguments: Option<&Value>,
        request_state: &str,
        input_responses: &Value,
    ) -> Result<Value, UpstreamError> {
        let options = ToolCallOptions {
            request_state: Some(request_state),
            input_responses: Some(input_responses),
            ..ToolCallOptions::default()
        };
        self.call_tool_with(name, arguments, &options).await
    }

    /// `tools/call` with everything [`ToolCallOptions`] adds to it. The
    /// result is returned as the upstream sent it, an
    /// `InputRequiredResult` included; notifications the upstream sends
    /// before it are skipped.
    async fn call_tool_with(
        &self,
        name: &str,
        arguments: Option<&Value>,
        options: &ToolCallOptions<'_>,
    ) -> Result<Value, UpstreamError>;

    /// Ask for argument completions (`completion/complete`).
    ///
    /// `reference` names what is being completed — a prompt or a resource
    /// template — and `argument` carries the name plus the prefix typed so
    /// far.
    async fn complete(
        &self,
        reference: &Value,
        argument: &Value,
        context: Option<&Value>,
    ) -> Result<Value, UpstreamError>;

    /// Subscribe to the changes `spec` names over `subscriptions/listen`
    /// and stream the notifications as they arrive. An empty spec opens
    /// nothing and never yields.
    async fn open_subscriptions(
        &self,
        spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError>;

    /// `events/list`, every page. MCP Events is served over HTTP only;
    /// elsewhere [`UpstreamError::Unsupported`].
    async fn list_events(&self) -> Result<Vec<events::EventDescriptor>, UpstreamError> {
        Err(UpstreamError::Unsupported(events::METHOD_LIST_EVENTS))
    }

    /// `events/poll`.
    async fn poll_events(
        &self,
        _params: &events::PollEventsParams,
    ) -> Result<events::PollEventsResult, UpstreamError> {
        Err(UpstreamError::Unsupported(events::METHOD_POLL_EVENTS))
    }

    /// `events/stream`: the stream's notifications as they arrive. The
    /// stream ends when the upstream closes it, or after the stream idle
    /// timeout without a byte (a live stream heartbeats well inside it).
    async fn open_event_stream(
        &self,
        _params: &events::StreamEventsParams,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        Err(UpstreamError::Unsupported(events::METHOD_STREAM_EVENTS))
    }

    /// `events/subscribe`: create or refresh a webhook subscription.
    async fn subscribe_events(
        &self,
        _params: &events::SubscribeEventsParams,
    ) -> Result<events::SubscribeEventsResult, UpstreamError> {
        Err(UpstreamError::Unsupported(events::METHOD_SUBSCRIBE_EVENTS))
    }

    /// `events/unsubscribe`.
    async fn unsubscribe_events(
        &self,
        _params: &events::UnsubscribeEventsParams,
    ) -> Result<events::UnsubscribeEventsResult, UpstreamError> {
        Err(UpstreamError::Unsupported(
            events::METHOD_UNSUBSCRIBE_EVENTS,
        ))
    }

    /// The `capabilities` object of the upstream's `server/discover`
    /// result. `None` when the result carried none. Kept verbatim, so an
    /// extension's entry reaches whoever reads it by type (MCP Events:
    /// `EventsCapability::advertised_in`).
    fn server_capabilities(&self) -> Option<&Value> {
        None
    }

    async fn close(&self);
}

/// MCP client over Streamable HTTP.
pub struct StreamableHttpUpstream {
    client: reqwest::Client,
    opts: UpstreamConnectOptions,
    /// The `server/discover` result's advertised `capabilities`.
    server_capabilities: Option<Value>,
    next_id: AtomicU64,
    /// How long a long-lived stream may stay silent before it is closed
    /// and the caller reconnects.
    stream_idle_timeout: Duration,
    /// The client for long-lived streams: same pinned address and
    /// redirect policy as `client`, but no total-request timeout, which
    /// would cut every stream at `opts.timeout`.
    stream_client: reqwest::Client,
}

impl StreamableHttpUpstream {
    /// Connect: build the guarded clients, then, with `opts.discover`, send
    /// `server/discover` and keep the capabilities the upstream advertises.
    /// An upstream that does not serve this revision fails there.
    pub async fn connect(opts: UpstreamConnectOptions) -> Result<Self, UpstreamError> {
        let (client, stream_client) = build_guarded_clients(&opts).await?;
        let mut upstream = Self {
            client,
            opts,
            server_capabilities: None,
            next_id: AtomicU64::new(1),
            stream_idle_timeout: DEFAULT_STREAM_IDLE_TIMEOUT,
            stream_client,
        };
        if !upstream.opts.discover {
            return Ok(upstream);
        }
        let params = discover_params(&upstream.opts.client_capabilities);
        let result = upstream
            .request(METHOD_SERVER_DISCOVER, Some(params), None)
            .await?;
        upstream.server_capabilities = discovered_capabilities(&result)?;
        Ok(upstream)
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Close a long-lived stream after `idle` without a byte from the
    /// upstream, in place of [`DEFAULT_STREAM_IDLE_TIMEOUT`].
    #[cfg(test)]
    fn with_stream_idle_timeout(mut self, idle: Duration) -> Self {
        self.stream_idle_timeout = idle;
        self
    }

    /// One finite request and its `result`. The params get the `_meta`
    /// identity triple, and the POST the SEP-2243 routing headers derived
    /// from them (`input_schema` enables `tools/call` param promotion). A
    /// response that streams (`text/event-stream`) is read event by event
    /// until the one that answers this request ([`read_sse_response`]).
    async fn request(
        &self,
        method: &'static str,
        params: Option<Value>,
        input_schema: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let mut params = params.unwrap_or_else(|| json!({}));
        inject_request_meta(&mut params, &self.opts.client_capabilities);
        let headers = routing_headers(method, &params, input_schema);
        let id = self.next_id();
        let body = JsonRpcRequest::call(id, method, params);
        let resp = self.send_post(&self.client, &body, &headers).await?;
        let parsed = if is_event_stream(&resp) {
            read_sse_response(resp, id, self.opts.max_response_bytes, &self.opts.tap).await?
        } else {
            if let Some(len) = resp.content_length()
                && len > self.opts.max_response_bytes
            {
                return Err(UpstreamError::ResponseTooLarge {
                    limit: self.opts.max_response_bytes,
                });
            }
            let text = read_capped(resp, self.opts.max_response_bytes).await?;
            tap_frame(
                &self.opts.tap,
                FrameDirection::Received,
                FrameChannel::HttpResponse,
                text.as_bytes(),
            );
            wire::parse_jsonrpc_body(&text).map_err(UpstreamError::Protocol)?
        };
        if let Some(err) = parsed.error {
            return Err(err.into());
        }
        parsed
            .result
            .ok_or_else(|| UpstreamError::Protocol(format!("{method} returned no result")))
    }

    /// One finite request and its typed result.
    async fn typed_request<P, R>(
        &self,
        method: &'static str,
        params: &P,
    ) -> Result<R, UpstreamError>
    where
        P: serde::Serialize + ?Sized,
        R: serde::de::DeserializeOwned,
    {
        let params = serde_json::to_value(params)
            .map_err(|e| UpstreamError::Protocol(format!("{method} params serialize: {e}")))?;
        let result = self.request(method, Some(params), None).await?;
        serde_json::from_value(result)
            .map_err(|e| UpstreamError::Protocol(format!("{method} result: {e}")))
    }

    /// Build + send a POST on `client`, returning the validated response
    /// (status checked, body not yet read). Every POST carries
    /// `Mcp-Protocol-Version`; `routing_headers` are the SEP-2243 headers
    /// of an id-bearing request.
    async fn send_post<B: serde::Serialize + ?Sized>(
        &self,
        client: &reqwest::Client,
        body: &B,
        routing_headers: &[(String, String)],
    ) -> Result<reqwest::Response, UpstreamError> {
        let mut req = client
            .post(&self.opts.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header(VIA_HEADER, &self.opts.gateway_via);
        for (name, value) in &self.opts.headers {
            req = req.header(name.as_str(), value.as_str());
        }
        if let Some(token) = &self.opts.bearer_token {
            req = req.bearer_auth(token);
        }
        req = req.header(PROTOCOL_VERSION_HEADER, PROTOCOL_VERSION);
        for (name, value) in routing_headers {
            req = req.header(name.as_str(), value.as_str());
        }
        // Serialized explicitly (identically to reqwest's `json()`) so the
        // tap sees the exact bytes that go on the wire.
        let raw = serde_json::to_vec(body)
            .map_err(|e| UpstreamError::Protocol(format!("request serialize: {e}")))?;
        // A signature covers header values, so signing needs them as data
        // rather than as builder calls. Gathering them costs a handful of
        // allocations per request, which every federated call the gateway
        // makes would otherwise pay for a feature only the inspector uses —
        // so it happens only when a signer is actually configured.
        if self.opts.signer.is_some() {
            let mut headers: Vec<(String, String)> = vec![
                ("content-type".into(), "application/json".into()),
                (
                    "accept".into(),
                    "application/json, text/event-stream".into(),
                ),
                (VIA_HEADER.into(), self.opts.gateway_via.clone()),
            ];
            headers.extend(
                self.opts
                    .headers
                    .iter()
                    .map(|(n, v)| (n.clone(), v.clone())),
            );
            if let Some(token) = &self.opts.bearer_token {
                headers.push(("authorization".into(), format!("Bearer {token}")));
            }
            headers.push((PROTOCOL_VERSION_HEADER.into(), PROTOCOL_VERSION.into()));
            headers.extend(routing_headers.iter().cloned());
            for (name, value) in self.sign_headers("POST", Some(&raw), &headers)? {
                req = req.header(name, value);
            }
        }
        tap_frame(
            &self.opts.tap,
            FrameDirection::Sent,
            FrameChannel::HttpRequest,
            &raw,
        );
        let resp = req.body(raw).send().await.map_err(|e| {
            UpstreamError::Transport(format!("request to {} failed: {e}", self.opts.url))
        })?;
        let status = resp.status();
        if !status.is_success() {
            // The JSON-RPC error the body carries, whole: its `data` is what
            // a caller tells one condition of a code from another by.
            let error = match read_capped(resp, self.opts.max_response_bytes).await {
                Ok(text) => {
                    tap_frame(
                        &self.opts.tap,
                        FrameDirection::Received,
                        FrameChannel::HttpResponse,
                        text.as_bytes(),
                    );
                    serde_json::from_str::<Value>(&text)
                        .ok()
                        .and_then(|mut v| v.get_mut("error").map(Value::take))
                        .and_then(|e| serde_json::from_value::<wire::JsonRpcError>(e).ok())
                }
                Err(_) => None,
            };
            return Err(UpstreamError::Http {
                status: status.as_u16(),
                error,
            });
        }
        Ok(resp)
    }

    /// Run the configured [`crate::signer::RequestSigner`] and return the
    /// headers it produced, for the caller to apply.
    ///
    /// `headers` must be the request's full decided header set: a signature
    /// covers header *values*, so anything added afterwards is outside it.
    /// Returns nothing when no signer is configured.
    fn sign_headers(
        &self,
        method: &str,
        body: Option<&[u8]>,
        headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>, UpstreamError> {
        let Some(signer) = &self.opts.signer else {
            return Ok(Vec::new());
        };
        signer
            .sign(&crate::signer::SigningRequest {
                method,
                url: &self.opts.url,
                headers,
                body,
            })
            .map_err(|e| UpstreamError::Protocol(format!("request signing failed: {e}")))
    }

    /// A long-lived request (`subscriptions/listen`, `events/stream`): its
    /// notifications as they arrive. A JSON answer instead of a stream is
    /// the server refusing the request. Only the response head is bounded
    /// by `opts.timeout`; the stream itself ends on the idle timeout.
    async fn open_stream_request(
        &self,
        method: &'static str,
        mut params: Value,
    ) -> Result<impl futures::Stream<Item = Value> + Send + use<>, UpstreamError> {
        inject_request_meta(&mut params, &self.opts.client_capabilities);
        let headers = routing_headers(method, &params, None);
        let body = JsonRpcRequest::call(self.next_id(), method, params);
        let resp = tokio::time::timeout(
            self.opts.timeout,
            self.send_post(&self.stream_client, &body, &headers),
        )
        .await
        .map_err(|_| {
            UpstreamError::Transport(format!(
                "{method} to {} timed out waiting for a response",
                self.opts.url
            ))
        })??;
        if !is_event_stream(&resp) {
            // The stream client has no body deadline, so this read gets one.
            let text = tokio::time::timeout(
                self.opts.timeout,
                read_capped(resp, self.opts.max_response_bytes),
            )
            .await
            .map_err(|_| UpstreamError::Transport(format!("{method} refusal body timed out")))??;
            let parsed = wire::parse_jsonrpc_body(&text).map_err(UpstreamError::Protocol)?;
            return Err(match parsed.error {
                Some(err) => err.into(),
                None => UpstreamError::Protocol(format!("{method} did not open a stream")),
            });
        }
        Ok(notification_stream(
            resp,
            self.opts.max_response_bytes,
            self.stream_idle_timeout,
            self.opts.tap.clone(),
        ))
    }
}

/// Read a `text/event-stream` answer to request `id` event by event and
/// return the response that carries `id`. Every event goes to the tap; the
/// notifications and server requests before the answer are dropped, so only
/// the event being read counts against `max_event_bytes`. The client's
/// request timeout bounds the stream as a whole, and the stream is dropped
/// as soon as the answer arrives.
async fn read_sse_response(
    mut resp: reqwest::Response,
    id: u64,
    max_event_bytes: u64,
    tap: &Option<crate::tap::SharedTap>,
) -> Result<wire::JsonRpcResponse, UpstreamError> {
    let mut buf: Vec<u8> = Vec::new();
    // Where the search for the next blank line resumes: a blank line can
    // start in the two bytes before the end of what was searched.
    let mut scanned = 0usize;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| UpstreamError::Transport(format!("reading body: {e}")))?
    {
        buf.extend_from_slice(&chunk);
        while let Some(end) = wire::sse_event_end(&buf, scanned) {
            if end as u64 > max_event_bytes {
                return Err(UpstreamError::ResponseTooLarge {
                    limit: max_event_bytes,
                });
            }
            let event: Vec<u8> = buf.drain(..end).collect();
            scanned = 0;
            tap_frame(tap, FrameDirection::Received, FrameChannel::HttpSse, &event);
            if let Some(response) = wire::sse_response_frame(&event, id) {
                return Ok(response);
            }
        }
        if buf.len() as u64 > max_event_bytes {
            return Err(UpstreamError::ResponseTooLarge {
                limit: max_event_bytes,
            });
        }
        scanned = buf.len().saturating_sub(2);
    }
    // A last event the upstream closed without a blank line.
    if !buf.is_empty() {
        tap_frame(tap, FrameDirection::Received, FrameChannel::HttpSse, &buf);
        if let Some(response) = wire::sse_response_frame(&buf, id) {
            return Ok(response);
        }
    }
    Err(UpstreamError::Protocol(
        "no JSON-RPC response frame in SSE stream".to_owned(),
    ))
}

/// Incrementally parse an SSE byte stream into JSON-RPC notification values.
/// SSE events are separated by a blank line; we accumulate bytes (so a chunk
/// split across a UTF-8 boundary or mid-frame is handled), drain whole
/// frames on `\n\n`, and surface only notifications (object with `method`,
/// no `id`). A frame buffer that grows past 4× the response cap without a
/// boundary aborts the stream (defensive against a non-framing upstream).
///
/// The stream also ends when `idle` passes without a byte. Heartbeats and
/// SSE comment keep-alives count as bytes, so a live stream never trips
/// it, while a silently dead connection ends instead of hanging; either
/// way the caller reconnects.
fn notification_stream(
    mut resp: reqwest::Response,
    max_response_bytes: u64,
    idle: Duration,
    tap: Option<crate::tap::SharedTap>,
) -> impl futures::Stream<Item = Value> + Send + use<> {
    let cap = max_response_bytes.saturating_mul(4);
    async_stream::stream! {
        // `Response::chunk` streams the body without needing reqwest's
        // `stream` feature.
        let mut buf: Vec<u8> = Vec::new();
        // Bytes already searched. Only the trailing `needle.len() - 1` bytes
        // can start a delimiter that completes in the next chunk.
        let mut scanned = 0usize;
        while let Ok(Ok(Some(chunk))) = tokio::time::timeout(idle, resp.chunk()).await {
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > cap {
                break;
            }
            while let Some(idx) = find_subslice_from(&buf, b"\n\n", scanned) {
                let frame: Vec<u8> = buf.drain(..idx + 2).collect();
                // The searched prefix left with the frame.
                scanned = 0;
                // The raw event block — `event:` / `id:` field lines
                // included — goes to the tap even when the filter below
                // drops the frame.
                tap_frame(&tap, FrameDirection::Received, FrameChannel::HttpSse, &frame);
                let Ok(text) = std::str::from_utf8(&frame) else {
                    continue;
                };
                for line in text.lines() {
                    let Some(data) = line.strip_prefix("data:") else {
                        continue;
                    };
                    if let Ok(val) = serde_json::from_str::<Value>(data.trim())
                        && val.get("method").is_some()
                        && val.get("id").is_none()
                    {
                        yield val;
                    }
                }
            }
            // Nothing further in what has been seen; the next chunk only needs
            // to re-examine the one-byte delimiter overlap.
            scanned = buf.len().saturating_sub(1);
        }
    }
}

/// Index of the first occurrence of `needle` in `haystack`, starting the
/// search at `from`.
///
/// The offset is what keeps SSE framing linear. Re-searching the whole
/// accumulated buffer on every chunk is quadratic in the stream length, and
/// the stream is produced by the upstream — so a federated server could spend
/// the gateway's CPU simply by sending many small chunks before a delimiter.
fn find_subslice_from(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|idx| idx + from)
}

/// True if the response is an SSE stream (`text/event-stream`).
fn is_event_stream(resp: &reqwest::Response) -> bool {
    resp.headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.contains("text/event-stream"))
}

#[async_trait]
impl McpUpstream for StreamableHttpUpstream {
    async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let result = self.request("tools/list", params, None).await?;
            let page: ListToolsResult = serde_json::from_value(result)
                .map_err(|e| UpstreamError::Protocol(format!("invalid tools/list result: {e}")))?;
            all.extend(page.tools);
            if all.len() > MAX_IMPORTED_TOOLS {
                return Err(UpstreamError::Protocol(format!(
                    "upstream advertised more than {MAX_IMPORTED_TOOLS} tools"
                )));
            }
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(all)
    }

    async fn list_resources(&self) -> Result<Vec<UpstreamResource>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let result = self.request("resources/list", params, None).await?;
            let page: ListResourcesResult = serde_json::from_value(result).map_err(|e| {
                UpstreamError::Protocol(format!("invalid resources/list result: {e}"))
            })?;
            all.extend(page.resources);
            if all.len() > MAX_IMPORTED_TOOLS {
                return Err(UpstreamError::Protocol(format!(
                    "upstream advertised more than {MAX_IMPORTED_TOOLS} resources"
                )));
            }
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(all)
    }

    async fn list_resource_templates(
        &self,
    ) -> Result<Vec<UpstreamResourceTemplate>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let result = self
                .request("resources/templates/list", params, None)
                .await?;
            let page: ListResourceTemplatesResult =
                serde_json::from_value(result).map_err(|e| {
                    UpstreamError::Protocol(format!("invalid resources/templates/list result: {e}"))
                })?;
            all.extend(page.resource_templates);
            if all.len() > MAX_IMPORTED_TOOLS {
                return Err(UpstreamError::Protocol(format!(
                    "upstream advertised more than {MAX_IMPORTED_TOOLS} resource templates"
                )));
            }
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(all)
    }

    async fn read_resource(&self, uri: &str) -> Result<Value, UpstreamError> {
        self.request("resources/read", Some(json!({ "uri": uri })), None)
            .await
    }

    async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let result = self.request("prompts/list", params, None).await?;
            let page: ListPromptsResult = serde_json::from_value(result).map_err(|e| {
                UpstreamError::Protocol(format!("invalid prompts/list result: {e}"))
            })?;
            all.extend(page.prompts);
            if all.len() > MAX_IMPORTED_TOOLS {
                return Err(UpstreamError::Protocol(format!(
                    "upstream advertised more than {MAX_IMPORTED_TOOLS} prompts"
                )));
            }
            match page.next_cursor {
                Some(c) if !c.is_empty() => cursor = Some(c),
                _ => break,
            }
        }
        Ok(all)
    }

    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let params = json!({
            "name": name,
            "arguments": arguments.cloned().unwrap_or_else(|| json!({})),
        });
        self.request("prompts/get", Some(params), None).await
    }

    async fn call_tool_with(
        &self,
        name: &str,
        arguments: Option<&Value>,
        options: &ToolCallOptions<'_>,
    ) -> Result<Value, UpstreamError> {
        self.request(
            "tools/call",
            Some(options.params(name, arguments)),
            options.input_schema,
        )
        .await
    }

    async fn complete(
        &self,
        reference: &Value,
        argument: &Value,
        context: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let mut params = json!({ "ref": reference, "argument": argument });
        if let Some(context) = context {
            params["context"] = context.clone();
        }
        self.request(
            mcpg_mcp_wire::v_2026_07_28::wire::completion::METHOD_COMPLETION_COMPLETE,
            Some(params),
            None,
        )
        .await
    }

    async fn open_subscriptions(
        &self,
        spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        use mcpg_mcp_wire::v_2026_07_28::wire::subscriptions::{
            METHOD_SUBSCRIPTIONS_LISTEN, SubscriptionsListenParams,
        };
        if spec.is_empty() {
            return Ok(Box::pin(futures::stream::pending()));
        }
        let params = SubscriptionsListenParams {
            subscriptions: spec.targets(),
            meta: None,
        };
        let params = serde_json::to_value(&params)
            .map_err(|e| UpstreamError::Protocol(format!("listen params serialize: {e}")))?;
        Ok(Box::pin(
            self.open_stream_request(METHOD_SUBSCRIPTIONS_LISTEN, params)
                .await?,
        ))
    }

    async fn list_events(&self) -> Result<Vec<events::EventDescriptor>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let params = events::ListEventsParams {
                cursor: cursor.clone(),
                meta: None,
            };
            let page: events::ListEventsResult = self
                .typed_request(events::METHOD_LIST_EVENTS, &params)
                .await?;
            all.extend(page.events);
            if all.len() > MAX_LISTED_EVENT_TYPES {
                return Err(UpstreamError::Protocol(format!(
                    "upstream listed more than {MAX_LISTED_EVENT_TYPES} event types"
                )));
            }
            // A server that hands back the cursor it was given ends the walk
            // rather than looping.
            match page.next_cursor {
                Some(next) if !next.is_empty() && cursor.as_deref() != Some(next.as_str()) => {
                    cursor = Some(next);
                }
                _ => return Ok(all),
            }
        }
    }

    async fn poll_events(
        &self,
        params: &events::PollEventsParams,
    ) -> Result<events::PollEventsResult, UpstreamError> {
        self.typed_request(events::METHOD_POLL_EVENTS, params).await
    }

    async fn open_event_stream(
        &self,
        params: &events::StreamEventsParams,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        let params = serde_json::to_value(params)
            .map_err(|e| UpstreamError::Protocol(format!("events/stream params serialize: {e}")))?;
        Ok(Box::pin(
            self.open_stream_request(events::METHOD_STREAM_EVENTS, params)
                .await?,
        ))
    }

    async fn subscribe_events(
        &self,
        params: &events::SubscribeEventsParams,
    ) -> Result<events::SubscribeEventsResult, UpstreamError> {
        self.typed_request(events::METHOD_SUBSCRIBE_EVENTS, params)
            .await
    }

    async fn unsubscribe_events(
        &self,
        params: &events::UnsubscribeEventsParams,
    ) -> Result<events::UnsubscribeEventsResult, UpstreamError> {
        self.typed_request(events::METHOD_UNSUBSCRIBE_EVENTS, params)
            .await
    }

    fn server_capabilities(&self) -> Option<&Value> {
        self.server_capabilities.as_ref()
    }

    /// Stateless: there is nothing to tear down.
    async fn close(&self) {}
}

/// MCP client over a stdio child process: newline-delimited JSON-RPC on the
/// child's stdin/stdout. One `io` Mutex serializes each request/response
/// cycle: the active call owns the pipe and reads it until *its* response.
/// There is no separate stream channel, so [`McpUpstream::open_subscriptions`]
/// opens nothing.
pub struct StdioUpstream {
    opts: UpstreamConnectOptions,
    next_id: AtomicU64,
    io: tokio::sync::Mutex<StdioIo>,
    /// The `server/discover` result's advertised `capabilities`.
    server_capabilities: std::sync::OnceLock<Value>,
}

struct StdioIo {
    /// Kept so the child is reaped on drop (`kill_on_drop`) + explicit close.
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::BufReader<tokio::process::ChildStdout>,
}

impl StdioUpstream {
    /// Spawn the child, then, with `opts.discover`, send `server/discover`
    /// and keep the capabilities it advertises.
    pub async fn connect(opts: UpstreamConnectOptions) -> Result<Self, UpstreamError> {
        let command = opts
            .command
            .clone()
            .ok_or_else(|| UpstreamError::Connect("stdio transport requires `command`".into()))?;
        let capture_stderr = opts.capture_stdio_stderr && opts.tap.is_some();
        let mut cmd = tokio::process::Command::new(&command);
        cmd.args(&opts.args)
            .envs(&opts.env)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(if capture_stderr {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .kill_on_drop(true);
        let mut child = cmd.spawn().map_err(|e| {
            UpstreamError::Connect(format!("failed to spawn stdio upstream '{command}': {e}"))
        })?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| UpstreamError::Connect("stdio child has no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| UpstreamError::Connect("stdio child has no stdout".into()))?;
        // Forward stderr lines to the tap; the task ends when the child
        // closes its stderr.
        if capture_stderr && let (Some(stderr), Some(tap)) = (child.stderr.take(), opts.tap.clone())
        {
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut lines = tokio::io::BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tap.on_frame(
                        FrameDirection::Received,
                        FrameChannel::StdioStderr,
                        line.as_bytes(),
                    );
                }
            });
        }
        let upstream = Self {
            opts,
            next_id: AtomicU64::new(1),
            io: tokio::sync::Mutex::new(StdioIo {
                child,
                stdin,
                stdout: tokio::io::BufReader::new(stdout),
            }),
            server_capabilities: std::sync::OnceLock::new(),
        };
        if !upstream.opts.discover {
            return Ok(upstream);
        }
        let params = discover_params(&upstream.opts.client_capabilities);
        let result = upstream.call(METHOD_SERVER_DISCOVER, params).await?;
        if let Some(capabilities) = discovered_capabilities(&result)? {
            let _ = upstream.server_capabilities.set(capabilities);
        }
        Ok(upstream)
    }

    /// One request over the serialized pipe: write it with the `_meta`
    /// identity triple, then read frames until the response that carries
    /// its id. Notifications in between are skipped. A request the child
    /// sends meanwhile is declined with `-32601`, so the child never waits
    /// on an answer.
    async fn call(&self, method: &'static str, mut params: Value) -> Result<Value, UpstreamError> {
        inject_request_meta(&mut params, &self.opts.client_capabilities);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });

        let mut io = self.io.lock().await;
        write_line(&mut io.stdin, &request, &self.opts.tap).await?;
        loop {
            let Some(line) = read_line(&mut io.stdout, self.opts.max_response_bytes).await? else {
                return Err(UpstreamError::Transport(format!(
                    "stdio upstream closed before responding to {method}"
                )));
            };
            tap_frame(
                &self.opts.tap,
                FrameDirection::Received,
                FrameChannel::Stdio,
                line.as_bytes(),
            );
            let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                continue; // ignore non-JSON stdout noise
            };
            let frame_method = msg.get("method").and_then(Value::as_str);
            match (frame_method, msg.get("id")) {
                (Some(frame_method), Some(req_id)) => {
                    let decline = json!({
                        "jsonrpc": "2.0", "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": format!("{frame_method} is not served by this client"),
                        }
                    });
                    write_line(&mut io.stdin, &decline, &self.opts.tap).await?;
                }
                (None, Some(resp_id)) if resp_id == &json!(id) => {
                    if let Some(err) = msg.get("error") {
                        return Err(UpstreamError::from_error_value(err));
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
                _ => {} // a notification, or a stray response for another id
            }
        }
    }
}

#[async_trait]
impl McpUpstream for StdioUpstream {
    async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        let r = self.call("tools/list", json!({})).await?;
        Ok(serde_json::from_value::<ListToolsResult>(r)
            .map_err(|e| UpstreamError::Protocol(format!("invalid tools/list result: {e}")))?
            .tools)
    }

    async fn list_resources(&self) -> Result<Vec<UpstreamResource>, UpstreamError> {
        let r = self.call("resources/list", json!({})).await?;
        Ok(serde_json::from_value::<ListResourcesResult>(r)
            .map_err(|e| UpstreamError::Protocol(format!("invalid resources/list result: {e}")))?
            .resources)
    }

    async fn list_resource_templates(
        &self,
    ) -> Result<Vec<UpstreamResourceTemplate>, UpstreamError> {
        let r = self.call("resources/templates/list", json!({})).await?;
        Ok(serde_json::from_value::<ListResourceTemplatesResult>(r)
            .map_err(|e| {
                UpstreamError::Protocol(format!("invalid resources/templates/list result: {e}"))
            })?
            .resource_templates)
    }

    async fn read_resource(&self, uri: &str) -> Result<Value, UpstreamError> {
        self.call("resources/read", json!({ "uri": uri })).await
    }

    async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError> {
        let r = self.call("prompts/list", json!({})).await?;
        Ok(serde_json::from_value::<ListPromptsResult>(r)
            .map_err(|e| UpstreamError::Protocol(format!("invalid prompts/list result: {e}")))?
            .prompts)
    }

    async fn get_prompt(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let params =
            json!({ "name": name, "arguments": arguments.cloned().unwrap_or_else(|| json!({})) });
        self.call("prompts/get", params).await
    }

    async fn call_tool_with(
        &self,
        name: &str,
        arguments: Option<&Value>,
        options: &ToolCallOptions<'_>,
    ) -> Result<Value, UpstreamError> {
        // A pipe carries no routing headers, so `input_schema` has no use.
        self.call("tools/call", options.params(name, arguments))
            .await
    }

    async fn complete(
        &self,
        reference: &Value,
        argument: &Value,
        context: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let mut params = json!({ "ref": reference, "argument": argument });
        if let Some(context) = context {
            params["context"] = context.clone();
        }
        self.call(
            mcpg_mcp_wire::v_2026_07_28::wire::completion::METHOD_COMPLETION_COMPLETE,
            params,
        )
        .await
    }

    async fn open_subscriptions(
        &self,
        _spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        // A listen stream would hold the one pipe every call needs, so a
        // stdio upstream is polled instead: the stream parks and never yields.
        Ok(Box::pin(futures::stream::pending()))
    }

    fn server_capabilities(&self) -> Option<&Value> {
        self.server_capabilities.get()
    }

    async fn close(&self) {
        let mut io = self.io.lock().await;
        let _ = io.child.start_kill();
    }
}

/// Write a JSON value as one newline-delimited frame to the child's stdin.
async fn write_line<T: serde::Serialize>(
    stdin: &mut tokio::process::ChildStdin,
    msg: &T,
    tap: &Option<crate::tap::SharedTap>,
) -> Result<(), UpstreamError> {
    use tokio::io::AsyncWriteExt;
    let mut line = serde_json::to_vec(msg)
        .map_err(|e| UpstreamError::Protocol(format!("encode stdio message: {e}")))?;
    line.push(b'\n');
    tap_frame(tap, FrameDirection::Sent, FrameChannel::Stdio, &line);
    stdin
        .write_all(&line)
        .await
        .map_err(|e| UpstreamError::Transport(format!("stdio write failed: {e}")))?;
    stdin
        .flush()
        .await
        .map_err(|e| UpstreamError::Transport(format!("stdio flush failed: {e}")))
}

/// Read one newline-delimited frame from the child's stdout. `Ok(None)` on EOF.
async fn read_line(
    stdout: &mut tokio::io::BufReader<tokio::process::ChildStdout>,
    cap: u64,
) -> Result<Option<String>, UpstreamError> {
    use tokio::io::AsyncBufReadExt;
    let mut line = String::new();
    let n = stdout
        .read_line(&mut line)
        .await
        .map_err(|e| UpstreamError::Transport(format!("stdio read failed: {e}")))?;
    if n == 0 {
        return Ok(None);
    }
    if line.len() as u64 > cap {
        return Err(UpstreamError::ResponseTooLarge { limit: cap });
    }
    Ok(Some(line))
}

/// Connect to an upstream over its configured transport, returning a
/// transport-agnostic handle.
pub async fn connect_upstream(
    opts: UpstreamConnectOptions,
) -> Result<std::sync::Arc<dyn McpUpstream>, UpstreamError> {
    match opts.transport {
        crate::transport::UpstreamTransport::StreamableHttp => Ok(std::sync::Arc::new(
            StreamableHttpUpstream::connect(opts).await?,
        )),
        crate::transport::UpstreamTransport::Stdio => {
            Ok(std::sync::Arc::new(StdioUpstream::connect(opts).await?))
        }
    }
}

/// Build the `reqwest::Client`s for one upstream, their DNS pinned to a
/// validated, non-private address — the same rebinding guard `net-core`
/// applies to HTTP bindings. Pinning closes the TOCTOU window where an
/// attacker-controlled record could flip to a private IP after the
/// check.
///
/// The first client bounds every request by `opts.timeout` end to end.
/// The second serves long-lived streams: `opts.timeout` bounds only the
/// connect, and the stream readers watch for silence instead.
async fn build_guarded_clients(
    opts: &UpstreamConnectOptions,
) -> Result<(reqwest::Client, reqwest::Client), UpstreamError> {
    let url = Url::parse(&opts.url)
        .map_err(|e| UpstreamError::Connect(format!("invalid url '{}': {e}", opts.url)))?;
    let host = url
        .host_str()
        .ok_or_else(|| UpstreamError::Connect("url has no host".to_owned()))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| UpstreamError::Connect("url has no port and no known default".to_owned()))?;

    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| UpstreamError::Connect(format!("DNS resolution failed for {host}: {e}")))?;
    let mut chosen = None;
    for addr in addrs {
        if opts.allow_private || !safe_dns::is_private_address(&addr.ip()) {
            chosen = Some(addr);
            break;
        }
    }
    let resolved = chosen.ok_or_else(|| {
        UpstreamError::Rebinding(format!(
            "host '{host}' resolved only to private/loopback addresses; \
             set upstream_safety.allow_private_backends: true to permit it"
        ))
    })?;

    // A `tunnel://` upstream authenticates its org to the relay's federation
    // ingress with this header on every request, so it is a client default.
    // The relay consumes it and does not forward it, so it never reaches the
    // tunnelled gateway.
    let mut default_headers = reqwest::header::HeaderMap::new();
    if let Some(token) = &opts.tunnel_token {
        let value = reqwest::header::HeaderValue::from_str(token).map_err(|_| {
            UpstreamError::Connect("tunnel token is not a valid HTTP header value".to_owned())
        })?;
        default_headers.insert(TUNNEL_TOKEN_HEADER, value);
    }
    let pinned = || {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .resolve(&host, resolved)
            .default_headers(default_headers.clone())
    };
    let build = |builder: reqwest::ClientBuilder| {
        builder
            .build()
            .map_err(|e| UpstreamError::Connect(format!("client build failed: {e}")))
    };
    let client = build(pinned().timeout(opts.timeout))?;
    let stream_client = build(pinned().connect_timeout(opts.timeout))?;
    Ok((client, stream_client))
}

/// Relay-consumed org-authentication header for `tunnel://` federation
/// upstreams. Must match the relay's `TUNNEL_TOKEN_HEADER`.
const TUNNEL_TOKEN_HEADER: reqwest::header::HeaderName =
    reqwest::header::HeaderName::from_static("x-mcpg-tunnel-token");

/// Read a response body with a hard byte cap, streaming chunks so a
/// malicious upstream can't force an unbounded allocation.
async fn read_capped(mut resp: reqwest::Response, max: u64) -> Result<String, UpstreamError> {
    let mut buf = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| UpstreamError::Transport(format!("reading body: {e}")))?
    {
        if buf.len() as u64 + chunk.len() as u64 > max {
            return Err(UpstreamError::ResponseTooLarge { limit: max });
        }
        buf.extend_from_slice(&chunk);
    }
    String::from_utf8(buf).map_err(|e| UpstreamError::Protocol(format!("non-utf8 body: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Router, http::StatusCode};
    use std::sync::{Arc, Mutex};

    /// A missing stored sign-in reads as what the caller must do, not as
    /// a failure to reach the upstream.
    #[test]
    fn a_missing_sign_in_says_how_to_store_one() {
        let error = UpstreamError::NotLinked {
            message: "open https://gw.example/oauth/connect once, then retry".to_owned(),
        };
        assert_eq!(
            error.to_string(),
            "no stored sign-in: open https://gw.example/oauth/connect once, then retry"
        );
    }

    /// The typed-array form is what goes on the wire, and its order is
    /// what the server echoes back — per-resource watches first, so a
    /// caller can line the acknowledgement up with what it asked for.
    #[test]
    fn a_spec_becomes_the_typed_targets_it_names() {
        use mcpg_mcp_wire::v_2026_07_28::wire::subscriptions::SubscriptionTarget;
        let spec = SubscriptionSpec {
            resource_uris: vec!["docs://a".into(), "docs://b".into()],
            tools_list_changed: true,
            prompts_list_changed: false,
            resources_list_changed: true,
            events_list_changed: true,
        };
        let targets = spec.targets();
        assert_eq!(
            targets,
            vec![
                SubscriptionTarget::ResourcesUpdated {
                    uri: "docs://a".into()
                },
                SubscriptionTarget::ResourcesUpdated {
                    uri: "docs://b".into()
                },
                SubscriptionTarget::ToolsListChanged,
                SubscriptionTarget::ResourcesListChanged,
                SubscriptionTarget::EventsListChanged,
            ]
        );
    }

    /// An empty spec asks for nothing, and the client must not open a
    /// stream for it — a subscription nobody requested is a connection
    /// nobody closes.
    #[test]
    fn an_empty_spec_is_recognised_as_empty() {
        assert!(SubscriptionSpec::default().is_empty());
        assert!(SubscriptionSpec::default().targets().is_empty());
        assert!(!SubscriptionSpec::all_list_changed().is_empty());
        assert!(
            !SubscriptionSpec {
                resource_uris: vec!["docs://a".into()],
                ..Default::default()
            }
            .is_empty()
        );
    }

    /// The convenience constructor asks for every catalog change and no
    /// per-resource watch — what a UI showing lists wants.
    #[test]
    fn all_list_changed_watches_catalogs_only() {
        let spec = SubscriptionSpec::all_list_changed();
        assert!(spec.resource_uris.is_empty());
        assert_eq!(spec.targets().len(), 3);
    }

    /// The options land where the spec puts them: `_meta` and the progress
    /// token under `_meta`, the MRTR answers as top-level params.
    #[test]
    fn tool_call_options_place_every_field() {
        let meta = json!({ "com.example/trace": "t" });
        let token = json!("tok-1");
        let answers = json!({ "elic-1": { "action": "accept" } });
        let options = ToolCallOptions {
            input_schema: None,
            progress_token: Some(&token),
            meta: Some(&meta),
            request_state: Some("state-1"),
            input_responses: Some(&answers),
        };
        let params = options.params("echo", Some(&json!({ "q": 1 })));
        assert_eq!(
            params,
            json!({
                "name": "echo",
                "arguments": { "q": 1 },
                "_meta": { "com.example/trace": "t", "progressToken": "tok-1" },
                "requestState": "state-1",
                "inputResponses": { "elic-1": { "action": "accept" } }
            })
        );

        let bare = ToolCallOptions::default().params("echo", None);
        assert_eq!(bare, json!({ "name": "echo", "arguments": {} }));
    }

    /// The identity triple joins whatever `_meta` the caller set, without
    /// overwriting it.
    #[test]
    fn request_meta_keeps_the_callers_entries() {
        let mut params = json!({ "_meta": { "progressToken": 3 } });
        inject_request_meta(&mut params, &json!({ "sampling": {} }));
        let meta = &params["_meta"];
        assert_eq!(meta["progressToken"], 3);
        assert_eq!(
            meta["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientInfo"]["name"],
            wire::CLIENT_NAME
        );
        assert_eq!(
            meta["io.modelcontextprotocol/clientCapabilities"],
            json!({ "sampling": {} })
        );
    }

    /// The `server/discover` result of a mock upstream.
    fn discover_result(capabilities: Value) -> Value {
        json!({
            "resultType": "complete",
            "supportedVersions": ["2026-07-28"],
            "serverInfo": { "name": "mock", "version": "1" },
            "capabilities": capabilities,
            "ttlMs": 60_000,
            "cacheScope": "public"
        })
    }

    async fn serve(app: Router) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/mcp")
    }

    async fn mock_handler(Json(body): Json<Value>) -> Response {
        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let id = body.get("id").cloned();
        match method {
            "server/discover" => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": discover_result(json!({
                    "tools": {},
                    "events": {},
                    "extensions": { "io.modelcontextprotocol/events": {} }
                }))
            }))
            .into_response(),
            "tools/list" => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "tools": [
                    { "name": "search", "description": "Search", "inputSchema": {"type": "object"} },
                    { "name": "create_page", "description": "Create", "inputSchema": {"type": "object"} }
                ] }
            }))
            .into_response(),
            "tools/call" => {
                let name = body
                    .get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "content": [{ "type": "text", "text": format!("called {name}") }],
                        "isError": false
                    }
                }))
                .into_response()
            }
            _ => Json(json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": "method not found" }
            }))
            .into_response(),
        }
    }

    async fn spawn_mock() -> String {
        serve(Router::new().route("/mcp", post(mock_handler))).await
    }

    fn opts(url: String, allow_private: bool) -> UpstreamConnectOptions {
        UpstreamConnectOptions {
            url,
            bearer_token: None,
            tunnel_token: None,
            allow_private,
            max_response_bytes: 1024 * 1024,
            timeout: Duration::from_secs(5),
            gateway_via: "mcpg-test".to_owned(),
            client_capabilities: serde_json::json!({}),
            discover: true,
            transport: crate::transport::UpstreamTransport::StreamableHttp,
            headers: std::collections::BTreeMap::new(),
            command: None,
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            tap: None,
            capture_stdio_stderr: false,
            signer: None,
        }
    }

    #[tokio::test]
    async fn connect_list_and_call_against_mock() {
        let url = spawn_mock().await;
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect");

        let tools = upstream.list_tools().await.expect("list_tools");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, "search");
        assert_eq!(tools[1].name, "create_page");

        let result = upstream
            .call_tool("search", Some(&json!({ "q": "x" })))
            .await
            .expect("call_tool");
        assert_eq!(result["content"][0]["text"], "called search");
        assert_eq!(result["isError"], false);

        upstream.close().await;
    }

    /// The discover result is kept verbatim, keys this build has no type
    /// for included, so a caller can see what the upstream offers.
    #[tokio::test]
    async fn discover_capabilities_are_kept_verbatim() {
        let url = spawn_mock().await;
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect");
        let capabilities = upstream
            .server_capabilities()
            .expect("discover capabilities");
        assert_eq!(capabilities["events"], json!({}));
        assert_eq!(
            capabilities["extensions"]["io.modelcontextprotocol/events"],
            json!({})
        );
        assert_eq!(capabilities["tools"], json!({}));
    }

    /// An upstream that answers `server/discover` with `-32022` serves
    /// another revision: connect fails with that answer, whole.
    #[tokio::test]
    async fn connect_fails_when_the_upstream_refuses_the_version() {
        async fn handler(Json(body): Json<Value>) -> Response {
            let id = body.get("id").cloned();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {
                        "code": -32022,
                        "message": "unsupported protocol version",
                        "data": { "supported": ["2030-01-01"] }
                    }
                })),
            )
                .into_response()
        }
        let url = serve(Router::new().route("/mcp", post(handler))).await;
        let Err(error) = StreamableHttpUpstream::connect(opts(url, true)).await else {
            panic!("connect must fail");
        };
        assert!(
            matches!(error, UpstreamError::Http { status: 400, .. }),
            "{error:?}"
        );
        assert_eq!(error.jsonrpc_code(), Some(-32022));
    }

    /// A discover result that does not list this client's version is
    /// refused at connect rather than at the first call.
    #[tokio::test]
    async fn connect_refuses_a_discover_result_without_this_version() {
        async fn handler(Json(body): Json<Value>) -> Response {
            let id = body.get("id").cloned();
            let mut result = discover_result(json!({}));
            result["supportedVersions"] = json!(["2030-01-01"]);
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
        }
        let url = serve(Router::new().route("/mcp", post(handler))).await;
        let Err(error) = StreamableHttpUpstream::connect(opts(url, true)).await else {
            panic!("connect must fail");
        };
        assert!(
            matches!(&error, UpstreamError::Protocol(message) if message.contains("2026-07-28")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn private_address_blocked_without_optin() {
        // Loopback is a private address; with allow_private=false the
        // rebinding guard must reject at client-build time (no server
        // needed — resolution happens before any request).
        let result =
            StreamableHttpUpstream::connect(opts("http://127.0.0.1:1/mcp".to_owned(), false)).await;
        assert!(
            matches!(result, Err(UpstreamError::Rebinding(_))),
            "loopback must be blocked by the rebinding guard"
        );
    }

    /// Write an executable `/bin/sh` script that logs every line it reads
    /// to `requests.log` beside it. Returns the script and the log path.
    #[cfg(unix)]
    fn stdio_script(dir: &std::path::Path, body: &str) -> (String, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let script = dir.join("mock-mcp.sh");
        let log = dir.join("requests.log");
        let text = format!(
            "#!/bin/sh\nLOG='{}'\nnext() {{ IFS= read -r line; printf '%s\\n' \"$line\" >> \"$LOG\"; }}\n{body}",
            log.display()
        );
        std::fs::write(&script, text).expect("write script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        (script.to_string_lossy().into_owned(), log)
    }

    #[cfg(unix)]
    fn stdio_opts(command: String) -> UpstreamConnectOptions {
        let mut o = opts(String::new(), true);
        o.transport = crate::transport::UpstreamTransport::Stdio;
        o.command = Some(command);
        o
    }

    #[cfg(unix)]
    const STDIO_DISCOVER_REPLY: &str = "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"supportedVersions\":[\"2026-07-28\"],\"serverInfo\":{\"name\":\"m\",\"version\":\"1\"},\"capabilities\":{\"tools\":{}},\"ttlMs\":1,\"cacheScope\":\"public\"}}'\n";

    /// A canned stdio MCP server replies to each request line in order:
    /// `server/discover` (id 1), `tools/list` (id 2), `tools/call` (id 3).
    /// Every request carries the `_meta` identity triple; nothing else is
    /// sent. Unix-only (the release target is linux-gnu).
    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_transport_discovers_lists_and_calls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (script, log) = stdio_script(
            dir.path(),
            &format!(
                "next\n{STDIO_DISCOVER_REPLY}\
                 next\n\
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"tools\":[{{\"name\":\"echo\",\"description\":\"e\",\"inputSchema\":{{\"type\":\"object\"}}}}]}}}}'\n\
                 next\n\
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"stdio-ok\"}}],\"isError\":false}}}}'\n"
            ),
        );
        let upstream = StdioUpstream::connect(stdio_opts(script))
            .await
            .expect("spawn + discover stdio upstream");
        assert_eq!(
            upstream.server_capabilities(),
            Some(&json!({ "tools": {} }))
        );
        let tools = upstream.list_tools().await.expect("list_tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let result = upstream.call_tool("echo", None).await.expect("call_tool");
        assert_eq!(result["content"][0]["text"], "stdio-ok");
        upstream.close().await;

        let sent: Vec<Value> = std::fs::read_to_string(log)
            .expect("request log")
            .lines()
            .map(|line| serde_json::from_str(line).expect("a JSON-RPC line"))
            .collect();
        let methods: Vec<&str> = sent.iter().filter_map(|m| m["method"].as_str()).collect();
        assert_eq!(methods, ["server/discover", "tools/list", "tools/call"]);
        assert_eq!(sent[0]["params"]["protocolVersion"], "2026-07-28");
        for request in &sent {
            let meta = &request["params"]["_meta"];
            assert_eq!(
                meta["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            assert_eq!(
                meta["io.modelcontextprotocol/clientInfo"]["name"],
                wire::CLIENT_NAME
            );
            assert_eq!(
                meta["io.modelcontextprotocol/clientCapabilities"],
                json!({})
            );
        }
    }

    /// A JSON-RPC error's `data` survives the stdio transport too.
    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_errors_keep_their_data() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (script, _) = stdio_script(
            dir.path(),
            &format!(
                "next\n{STDIO_DISCOVER_REPLY}\
                 next\n\
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"error\":{{\"code\":-32011,\"message\":\"not found\",\"data\":{{\"kind\":\"event\"}}}}}}'\n"
            ),
        );
        let upstream = StdioUpstream::connect(stdio_opts(script))
            .await
            .expect("spawn stdio upstream");
        let error = upstream.call_tool("x", None).await.unwrap_err();
        assert_eq!(error.jsonrpc_data(), Some(&json!({ "kind": "event" })));
        upstream.close().await;
    }

    /// A request the child sends mid-call is declined with `-32601`, and
    /// the call still completes with its own response.
    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_declines_a_request_from_the_child() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (script, log) = stdio_script(
            dir.path(),
            &format!(
                "next\n{STDIO_DISCOVER_REPLY}\
                 next\n\
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{\"progressToken\":1,\"progress\":1}}}}'\n\
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":\"srv-1\",\"method\":\"sampling/createMessage\",\"params\":{{}}}}'\n\
                 next\n\
                 printf '%s\\n' '{{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{{\"content\":[],\"isError\":false}}}}'\n"
            ),
        );
        let upstream = StdioUpstream::connect(stdio_opts(script))
            .await
            .expect("spawn stdio upstream");
        let result = upstream.call_tool("x", None).await.expect("call_tool");
        assert_eq!(result["isError"], false);
        upstream.close().await;

        let log = std::fs::read_to_string(log).expect("request log");
        let decline: Value =
            serde_json::from_str(log.lines().last().expect("the decline")).expect("JSON");
        assert_eq!(decline["id"], "srv-1");
        assert_eq!(decline["error"]["code"], -32601);
    }

    /// A JSON-RPC error's `data` reaches the caller over HTTP.
    #[tokio::test]
    async fn http_errors_keep_their_data() {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "server/discover" => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "supportedVersions": ["2026-07-28"], "capabilities": {} }
                }))
                .into_response(),
                _ => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {
                        "code": -32013,
                        "message": "limit reached",
                        "data": { "limit": "subscriptions", "max": 100 }
                    }
                }))
                .into_response(),
            }
        }
        let url = serve(Router::new().route("/mcp", post(handler))).await;
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect");
        let expected = json!({ "limit": "subscriptions", "max": 100 });

        let error = upstream.list_tools().await.unwrap_err();
        match &error {
            UpstreamError::JsonRpc { code, data, .. } => {
                assert_eq!(*code, -32013);
                assert_eq!(data.as_ref(), Some(&expected));
            }
            other => panic!("expected a JSON-RPC error, got {other:?}"),
        }
        assert!(
            !error.to_string().contains("subscriptions"),
            "the upstream's data stays out of the message: {error}"
        );

        let error = upstream.call_tool("x", None).await.unwrap_err();
        assert_eq!(error.jsonrpc_data(), Some(&expected));
    }

    /// The server answers an error with the status its code maps to. The
    /// error rides along whole: code, message and data.
    #[tokio::test]
    async fn an_error_status_keeps_its_jsonrpc_error() {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "server/discover" => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "supportedVersions": ["2026-07-28"], "capabilities": {} }
                }))
                .into_response(),
                _ => (
                    StatusCode::FORBIDDEN,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": {
                            "code": -32012,
                            "message": "forbidden",
                            "data": { "reason": "trust" }
                        }
                    })),
                )
                    .into_response(),
            }
        }
        let url = serve(Router::new().route("/mcp", post(handler))).await;
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect");

        let error = upstream.list_events().await.unwrap_err();
        assert!(
            matches!(error, UpstreamError::Http { status: 403, .. }),
            "{error:?}"
        );
        assert_eq!(error.jsonrpc_code(), Some(-32012));
        assert_eq!(error.jsonrpc_data(), Some(&json!({ "reason": "trust" })));
        assert!(
            !error.to_string().contains("trust"),
            "the upstream's data stays out of the message: {error}"
        );
    }

    // --- What goes on the wire (SEP-2575 `_meta`, SEP-2243 headers) ---

    /// One captured outbound POST: the request headers + JSON-RPC body.
    #[derive(Clone, Default)]
    struct Captured {
        headers: axum::http::HeaderMap,
        body: Value,
    }

    type Capture = Arc<Mutex<Vec<Captured>>>;

    /// Spawn a mock that records every POST's headers + body, answers
    /// `server/discover`, and answers everything else with a tool result.
    async fn spawn_capturing_mock(capture: Capture) -> String {
        async fn handler(
            axum::extract::State(capture): axum::extract::State<Capture>,
            headers: axum::http::HeaderMap,
            Json(body): Json<Value>,
        ) -> Response {
            capture.lock().unwrap().push(Captured {
                headers: headers.clone(),
                body: body.clone(),
            });
            let id = body.get("id").cloned();
            let result = if body.get("method").and_then(Value::as_str) == Some("server/discover") {
                discover_result(json!({}))
            } else {
                json!({ "content": [{ "type": "text", "text": "ok" }], "isError": false })
            };
            Json(json!({ "jsonrpc": "2.0", "id": id, "result": result })).into_response()
        }
        serve(
            Router::new()
                .route("/mcp", post(handler))
                .with_state(capture),
        )
        .await
    }

    fn capabilities_opts(url: String) -> UpstreamConnectOptions {
        let mut o = opts(url, true);
        o.client_capabilities = json!({ "sampling": {} });
        o
    }

    fn header<'a>(captured: &'a Captured, name: &str) -> Option<&'a str> {
        captured.headers.get(name).and_then(|v| v.to_str().ok())
    }

    #[tokio::test]
    async fn requests_carry_sep2243_headers_and_request_meta() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;
        let upstream = StreamableHttpUpstream::connect(capabilities_opts(url))
            .await
            .expect("connect");

        // `region` is promoted to `Mcp-Param-Region`; `note` carries a
        // non-ASCII value so `Mcp-Param-Note` uses the base64 sentinel.
        let schema = json!({
            "type": "object",
            "properties": {
                "region": { "type": "string", "x-mcp-header": "Region" },
                "note":   { "type": "string", "x-mcp-header": "Note" },
                "query":  { "type": "string" }
            }
        });
        let args = json!({ "region": "us-west1", "note": "世界", "query": "SELECT 1" });
        let options = ToolCallOptions {
            input_schema: Some(&schema),
            ..ToolCallOptions::default()
        };
        let result = upstream
            .call_tool_with("execute_sql", Some(&args), &options)
            .await
            .expect("tools/call");
        assert_eq!(result["content"][0]["text"], "ok");
        upstream.close().await;

        let posts = capture.lock().unwrap().clone();
        assert_eq!(
            posts.len(),
            2,
            "server/discover, then the call; nothing else"
        );

        let discover = &posts[0];
        assert_eq!(discover.body["method"], "server/discover");
        assert_eq!(discover.body["params"]["protocolVersion"], "2026-07-28");
        assert_eq!(
            discover.body["params"]["capabilities"],
            json!({ "sampling": {} })
        );
        assert_eq!(header(discover, "mcp-method"), Some("server/discover"));

        let call = &posts[1];
        for post in &posts {
            assert_eq!(header(post, "mcp-protocol-version"), Some("2026-07-28"));
            let meta = &post.body["params"]["_meta"];
            assert_eq!(
                meta["io.modelcontextprotocol/protocolVersion"],
                "2026-07-28"
            );
            assert_eq!(
                meta["io.modelcontextprotocol/clientInfo"]["name"],
                wire::CLIENT_NAME
            );
            assert_eq!(
                meta["io.modelcontextprotocol/clientCapabilities"],
                json!({ "sampling": {} })
            );
        }
        assert_eq!(header(call, "mcp-method"), Some("tools/call"));
        assert_eq!(header(call, "mcp-name"), Some("execute_sql"));
        assert_eq!(header(call, "mcp-param-region"), Some("us-west1"));
        assert_eq!(
            header(call, "mcp-param-note"),
            Some("=?base64?5LiW55WM?="),
            "non-ASCII param uses the base64 sentinel"
        );
    }

    #[tokio::test]
    async fn a_non_ascii_tool_name_is_encoded() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;
        let upstream = StreamableHttpUpstream::connect(capabilities_opts(url))
            .await
            .expect("connect");

        upstream
            .call_tool("выполнить", Some(&json!({})))
            .await
            .expect("tools/call");

        let posts = capture.lock().unwrap();
        assert_eq!(
            header(&posts[1], "mcp-name"),
            Some("=?base64?0LLRi9C/0L7Qu9C90LjRgtGM?="),
            "non-ASCII tool name carried via the encoded-word sentinel"
        );
    }

    /// The retry of a suspended call carries `requestState` and
    /// `inputResponses` beside `name` and `arguments`, never under `_meta`.
    #[tokio::test]
    async fn a_resumed_call_sends_the_answers_as_top_level_params() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;
        let upstream = StreamableHttpUpstream::connect(capabilities_opts(url))
            .await
            .expect("connect");
        let answers = json!({ "elic-1": { "action": "accept", "content": { "ok": true } } });

        upstream
            .call_tool_resuming(
                "deploy",
                Some(&json!({ "env": "prod" })),
                "c.state",
                &answers,
            )
            .await
            .expect("tools/call");

        let posts = capture.lock().unwrap();
        let params = &posts[1].body["params"];
        assert_eq!(params["name"], "deploy");
        assert_eq!(params["arguments"], json!({ "env": "prod" }));
        assert_eq!(params["requestState"], "c.state");
        assert_eq!(params["inputResponses"], answers);
        let meta = params["_meta"].as_object().expect("_meta");
        assert!(
            meta.keys()
                .all(|key| key.starts_with("io.modelcontextprotocol/")
                    && !key.ends_with("requestState")
                    && !key.ends_with("inputResponses"))
        );
    }

    /// A call whose response streams: the progress token rides in `_meta`,
    /// and every frame before the terminal response — notifications, and a
    /// request this wire never sends — is skipped.
    #[tokio::test]
    async fn a_streamed_call_returns_its_terminal_response() {
        async fn handler(Json(body): Json<Value>) -> Response {
            let id = body.get("id").cloned().unwrap_or(Value::Null);
            if body.get("method").and_then(Value::as_str) == Some("server/discover") {
                return Json(
                    json!({ "jsonrpc": "2.0", "id": id, "result": discover_result(json!({})) }),
                )
                .into_response();
            }
            let token = body["params"]["_meta"]["progressToken"].clone();
            let frames = [
                json!({ "jsonrpc": "2.0", "method": "notifications/progress",
                        "params": { "progressToken": token, "progress": 1, "total": 2 } }),
                json!({ "jsonrpc": "2.0", "id": "srv-1", "method": "roots/list", "params": {} }),
                json!({ "jsonrpc": "2.0", "id": id,
                        "result": { "content": [{ "type": "text", "text": token }], "isError": false } }),
            ];
            let text: String = frames
                .iter()
                .map(|frame| format!("event: message\ndata: {frame}\n\n"))
                .collect();
            let mut response = text.into_response();
            response.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                "text/event-stream".parse().unwrap(),
            );
            response
        }
        let url = serve(Router::new().route("/mcp", post(handler))).await;
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect");
        let token = json!("client-tok");
        let options = ToolCallOptions {
            progress_token: Some(&token),
            ..ToolCallOptions::default()
        };
        let result = upstream
            .call_tool_with("work", None, &options)
            .await
            .expect("tools/call");
        assert_eq!(result["content"][0]["text"], "client-tok");
    }

    /// Serves `server/discover`, and answers every other request with an
    /// SSE stream of `progress_frames` progress notifications of about 1 KiB
    /// each, then a result of `result_bytes` bytes of text.
    async fn spawn_progress_mock(progress_frames: usize, result_bytes: usize) -> String {
        serve(Router::new().route(
            "/mcp",
            post(move |Json(body): Json<Value>| async move {
                let id = body.get("id").cloned().unwrap_or(Value::Null);
                if body.get("method").and_then(Value::as_str) == Some("server/discover") {
                    return Json(
                        json!({ "jsonrpc": "2.0", "id": id, "result": discover_result(json!({})) }),
                    )
                    .into_response();
                }
                let padding = "p".repeat(1024);
                let mut text: String = (0..progress_frames)
                    .map(|n| {
                        let frame = json!({ "jsonrpc": "2.0", "method": "notifications/progress",
                            "params": { "progressToken": "t", "progress": n, "message": padding } });
                        format!("event: message\ndata: {frame}\n\n")
                    })
                    .collect();
                let result = json!({ "jsonrpc": "2.0", "id": id, "result": {
                    "content": [{ "type": "text", "text": "r".repeat(result_bytes) }],
                    "isError": false,
                } });
                text.push_str(&format!("event: message\ndata: {result}\n\n"));
                let mut response = text.into_response();
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    "text/event-stream".parse().unwrap(),
                );
                response
            }),
        ))
        .await
    }

    fn small_cap_opts(url: String) -> UpstreamConnectOptions {
        let mut o = opts(url, true);
        o.max_response_bytes = 16 * 1024;
        o
    }

    /// Only the event being read counts against the response cap: progress
    /// that adds up to far more than the cap does not fail a call whose
    /// answer fits, and an answer over the cap still does.
    #[tokio::test]
    async fn a_streamed_answer_is_capped_by_itself_not_by_its_progress() {
        let url = spawn_progress_mock(64, 1024).await;
        let upstream = StreamableHttpUpstream::connect(small_cap_opts(url))
            .await
            .expect("connect");
        let result = upstream.call_tool("work", None).await.expect("tools/call");
        assert_eq!(result["content"][0]["text"], "r".repeat(1024));

        let url = spawn_progress_mock(1, 32 * 1024).await;
        let upstream = StreamableHttpUpstream::connect(small_cap_opts(url))
            .await
            .expect("connect");
        let error = upstream.call_tool("work", None).await.unwrap_err();
        assert!(
            matches!(error, UpstreamError::ResponseTooLarge { .. }),
            "{error:?}"
        );
    }

    /// A connection that skips `server/discover` sends nothing until its
    /// first request and reads no capabilities.
    #[tokio::test]
    async fn a_connection_without_discovery_sends_only_its_requests() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;
        let mut o = opts(url, true);
        o.discover = false;
        let upstream = StreamableHttpUpstream::connect(o).await.expect("connect");
        assert!(capture.lock().unwrap().is_empty());
        assert!(upstream.server_capabilities().is_none());

        upstream
            .call_tool("search", None)
            .await
            .expect("tools/call");
        let posts = capture.lock().unwrap();
        assert_eq!(posts.len(), 1, "the call is the only request");
        assert_eq!(posts[0].body["method"], "tools/call");
    }

    const LIST_CHANGED_FRAME: &str =
        "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\n";

    /// An SSE body. `Beats` sends an SSE comment every `every` and a
    /// notification on every fourth tick, `beats` ticks in all. `Silent`
    /// sends one notification and then nothing while holding the
    /// connection open.
    enum StreamScript {
        Beats { beats: usize, every: Duration },
        Silent,
    }

    fn sse_response(script: StreamScript) -> Response {
        let stream = async_stream::stream! {
            match script {
                StreamScript::Beats { beats, every } => {
                    for tick in 0..beats {
                        tokio::time::sleep(every).await;
                        let frame = if tick % 4 == 3 { LIST_CHANGED_FRAME } else { ": keep-alive\n\n" };
                        yield Ok::<_, std::convert::Infallible>(axum::body::Bytes::from(frame));
                    }
                }
                StreamScript::Silent => {
                    yield Ok(axum::body::Bytes::from(LIST_CHANGED_FRAME));
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            }
        };
        let mut response = axum::body::Body::from_stream(stream).into_response();
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            "text/event-stream".parse().unwrap(),
        );
        response
    }

    /// Answers `server/discover`, and `subscriptions/listen` with a stream
    /// per `script`.
    async fn spawn_stream_mock(script: fn() -> StreamScript) -> String {
        serve(Router::new().route(
            "/mcp",
            post(move |Json(body): Json<Value>| async move {
                let id = body.get("id").cloned();
                match body.get("method").and_then(Value::as_str).unwrap_or("") {
                    "subscriptions/listen" => sse_response(script()),
                    "server/discover" => Json(
                        json!({ "jsonrpc": "2.0", "id": id, "result": discover_result(json!({})) }),
                    )
                    .into_response(),
                    _ => StatusCode::ACCEPTED.into_response(),
                }
            }),
        ))
        .await
    }

    fn short_timeout_opts(url: String) -> UpstreamConnectOptions {
        let mut o = opts(url, true);
        o.timeout = Duration::from_millis(300);
        o
    }

    fn beating() -> StreamScript {
        StreamScript::Beats {
            beats: 32,
            every: Duration::from_millis(50),
        }
    }

    /// A stream that keeps beating outlives the per-call timeout: only
    /// silence ends it. The stream runs about 1.6 s against a 300 ms
    /// per-call timeout, so a total deadline would cut it after the first
    /// notification at most.
    #[tokio::test]
    async fn a_beating_stream_outlives_the_call_timeout() {
        use futures::StreamExt;
        let url = spawn_stream_mock(beating).await;
        let upstream = StreamableHttpUpstream::connect(short_timeout_opts(url))
            .await
            .expect("connect")
            .with_stream_idle_timeout(Duration::from_millis(200));
        let stream = upstream
            .open_subscriptions(&SubscriptionSpec::all_list_changed())
            .await
            .expect("open stream");
        let started = std::time::Instant::now();
        let received: Vec<Value> = tokio::time::timeout(Duration::from_secs(10), stream.collect())
            .await
            .expect("the stream ends when the upstream closes it");
        assert_eq!(received.len(), 8, "{received:?}");
        assert!(
            started.elapsed() > Duration::from_millis(1200),
            "the stream lived {:?}",
            started.elapsed()
        );
        assert_eq!(received[0]["method"], "notifications/tools/list_changed");
    }

    /// A stream that goes silent ends after the idle timeout instead of
    /// hanging until the connection dies.
    #[tokio::test]
    async fn a_silent_stream_ends_after_the_idle_timeout() {
        use futures::StreamExt;
        let url = spawn_stream_mock(|| StreamScript::Silent).await;
        let upstream = StreamableHttpUpstream::connect(short_timeout_opts(url))
            .await
            .expect("connect")
            .with_stream_idle_timeout(Duration::from_millis(200));
        let mut stream = upstream
            .open_subscriptions(&SubscriptionSpec::all_list_changed())
            .await
            .expect("open stream");
        let first = stream.next().await.expect("the one notification");
        assert_eq!(first["method"], "notifications/tools/list_changed");
        let started = std::time::Instant::now();
        let next = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("the idle watchdog ends the stream");
        assert!(next.is_none());
        assert!(
            started.elapsed() >= Duration::from_millis(200),
            "ended after {:?}",
            started.elapsed()
        );
    }

    /// A refused listen surfaces as the upstream's error, not as a stream.
    #[tokio::test]
    async fn a_refused_listen_is_an_error() {
        let url = spawn_mock().await;
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect");
        let Err(error) = upstream
            .open_subscriptions(&SubscriptionSpec::all_list_changed())
            .await
        else {
            panic!("a refused listen must not open a stream");
        };
        assert_eq!(error.jsonrpc_code(), Some(-32601));
    }

    #[test]
    fn the_default_idle_timeout_is_twice_the_heartbeat_ceiling() {
        assert_eq!(DEFAULT_STREAM_IDLE_TIMEOUT, Duration::from_secs(60));
    }
}
