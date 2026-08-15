//! Outbound MCP client transport for federation.
//!
//! [`McpUpstream`] is the direction-clean client seam (kept behind a
//! trait so additional transports and a possible cdylib extraction
//! stay open).
//! [`StreamableHttpUpstream`] implements it over `reqwest` with the same
//! DNS-rebinding/SSRF guard the HTTP backend uses (`net-core`): resolve,
//! reject private addresses, pin the vetted IP to close the rebinding
//! TOCTOU window.

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
use mcpg_plugin_backend_net_core::safe_dns;

/// MCP protocol version MCPG advertises as a client on the legacy
/// (session-bound) wire. MCPG always speaks a version it implements
/// itself, never an upstream's.
///
/// On the legacy wire the federation client does NOT emit the SEP-2243
/// `Mcp-Method` / `Mcp-Name` / `Mcp-Param-{Name}` routing headers: those
/// are a `2026-07-28`-only contract and a `2025-11-25` peer does not
/// validate them (the spec even directs intermediaries to reject
/// header-routed requests whose negotiated version predates header–body
/// validation).
const FEDERATION_PROTOCOL_VERSION: &str =
    mcpg_mcp_wire::v_2025_11_25::wire::SUPPORTED_PROTOCOL_VERSION;
/// MCP protocol version MCPG advertises as a client on the modern,
/// stateless wire (opt-in per upstream). The `2026-07-28` revision
/// removed the `initialize` handshake and protocol-level sessions:
/// every request carries its identity in `_meta` and MCPG emits the
/// SEP-2243 routing headers (`Mcp-Method` / `Mcp-Name` /
/// `Mcp-Param-{Name}`) on id-bearing POSTs.
const MODERN_FEDERATION_PROTOCOL_VERSION: &str =
    mcpg_mcp_wire::v_2026_07_28::wire::SUPPORTED_PROTOCOL_VERSION;
/// Loop-detection header. Set on every upstream request.
const VIA_HEADER: &str = "mcpg-upstream-via";
/// Defensive cap on imported tools from a single upstream.
const MAX_IMPORTED_TOOLS: usize = 10_000;

/// Failure modes of an upstream MCP call.
#[derive(Debug)]
pub enum UpstreamError {
    /// Connection setup failed (bad URL, DNS, client build).
    Connect(String),
    /// Transport-level failure (network, body read).
    Transport(String),
    /// Non-2xx HTTP response on a POST. Carries the status and, when the
    /// body held a JSON-RPC error, its code — the wire-version probe uses
    /// these to tell "legacy peer rejecting a modern method" from a real
    /// failure.
    Http {
        status: u16,
        jsonrpc_code: Option<i64>,
    },
    /// Malformed / unexpected protocol payload.
    Protocol(String),
    /// Upstream resolved to a private address and the guard rejected it.
    Rebinding(String),
    /// Upstream response exceeded the configured byte cap.
    ResponseTooLarge { limit: u64 },
    /// Upstream returned a JSON-RPC error.
    JsonRpc { code: i64, message: String },
}

impl fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(m) => write!(f, "upstream connect error: {m}"),
            Self::Transport(m) => write!(f, "upstream transport error: {m}"),
            Self::Http {
                status,
                jsonrpc_code: Some(code),
            } => write!(f, "upstream returned HTTP {status} (JSON-RPC error {code})"),
            Self::Http {
                status,
                jsonrpc_code: None,
            } => write!(f, "upstream returned HTTP {status}"),
            Self::Protocol(m) => write!(f, "upstream protocol error: {m}"),
            Self::Rebinding(m) => write!(f, "upstream blocked by DNS-rebinding guard: {m}"),
            Self::ResponseTooLarge { limit } => {
                write!(f, "upstream response exceeded {limit} bytes")
            }
            Self::JsonRpc { code, message } => {
                write!(f, "upstream JSON-RPC error {code}: {message}")
            }
        }
    }
}

impl std::error::Error for UpstreamError {}

/// Connection parameters for a single upstream session.
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
    /// Client capabilities advertised to the upstream at `initialize` (P3):
    /// the subset of `sampling`/`elicitation`/`roots` the downstream client
    /// supports, so the upstream knows it may issue those server-requests.
    /// `{}` when there is nothing to bridge (import sessions, no downstream).
    pub client_capabilities: Value,
    /// Wire transport (P4): `StreamableHttp` uses `url`; `Stdio` spawns
    /// `command`/`args`/`env`.
    pub transport: crate::transport::UpstreamTransport,
    /// Speak the stateless `2026-07-28` client wire to this upstream
    /// (SEP-2243 routing headers + per-request `_meta` identity, no
    /// `initialize`, no `Mcp-Session-Id`). `false` (default) keeps the
    /// session-bound `2025-11-25` client wire, byte-identical to legacy.
    /// Only the `StreamableHttp` transport honors this.
    pub modern: bool,
    /// Probe the wire at connect (SEP-2575 backward-compat sequence):
    /// attempt `server/discover`; fall back to the legacy `initialize`
    /// when the peer rejects it. Overrides `modern` with the detected
    /// wire. Only the `StreamableHttp` transport honors this.
    pub probe: bool,
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
    /// (`StdioStderr` channel). `false` nulls stderr — the historical
    /// behavior, and the only useful choice without a tap.
    pub capture_stdio_stderr: bool,
    /// Computes request-scoped authorization headers ([`crate::signer`]).
    /// `None` (default) sends only the static header map. Only the
    /// `StreamableHttp` transport honors this — stdio has no request headers.
    pub signer: Option<crate::signer::SharedSigner>,
}

/// What to subscribe to, independent of how the wire expresses it.
///
/// The two revisions disagree about mechanism, not meaning: `2026-07-28`
/// takes the whole set in one `subscriptions/listen` call, while
/// `2025-11-25` subscribes per resource URI and delivers list-changed
/// pushes on the standing GET stream whether or not anyone asked. Callers
/// describe what they want and let the client pick.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionSpec {
    /// Resource URIs to watch for content changes
    /// (`notifications/resources/updated`).
    pub resource_uris: Vec<String>,
    pub tools_list_changed: bool,
    pub prompts_list_changed: bool,
    pub resources_list_changed: bool,
}

impl SubscriptionSpec {
    /// Every catalog change, no per-resource watches. What a UI wants when
    /// it is showing lists and nothing more specific.
    pub fn all_list_changed() -> Self {
        Self {
            resource_uris: Vec::new(),
            tools_list_changed: true,
            prompts_list_changed: true,
            resources_list_changed: true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.resource_uris.is_empty()
            && !self.tools_list_changed
            && !self.prompts_list_changed
            && !self.resources_list_changed
    }

    /// The modern wire's typed-array form.
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
        out
    }
}

/// A connected upstream MCP server: list tools, call a tool, close.
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
    async fn call_tool(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        self.call_tool_with_meta(name, arguments, None).await
    }

    /// `tools/call` carrying request-scoped `params._meta`.
    ///
    /// The distinction matters: `_meta` belongs on **params**, beside
    /// `name` and `arguments` — not inside `arguments`, where the
    /// server would treat it as a tool input and never read it. MRTR
    /// resumption (SEP-2322) depends on it, since that is how
    /// `requestState` and `inputResponses` travel.
    async fn call_tool_with_meta(
        &self,
        name: &str,
        arguments: Option<&Value>,
        meta: Option<&Value>,
    ) -> Result<Value, UpstreamError>;

    /// `tools/call` with server-request bridging (P3); `progress_token` is the
    /// downstream client's `_meta.progressToken` (if any). `input_schema` is
    /// the upstream tool's declared `inputSchema` (when known) — used on the
    /// modern wire to promote SEP-2243 `Mcp-Param-{Name}` headers; ignored on
    /// the legacy wire.
    async fn call_tool_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        input_schema: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
        progress_token: Option<&Value>,
    ) -> Result<Value, UpstreamError>;

    /// `resources/read` with server-request bridging (P3).
    async fn read_resource_bridged(
        &self,
        uri: &str,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError>;

    /// `prompts/get` with server-request bridging (P3).
    async fn get_prompt_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError>;

    /// Ask for argument completions (`completion/complete`).
    ///
    /// `reference` names what is being completed — a prompt or a resource
    /// template — and `argument` carries the name plus the prefix typed so
    /// far. The wire shape is identical on both revisions; completion is one
    /// of the few methods 2026-07-28 left alone.
    async fn complete(
        &self,
        reference: &Value,
        argument: &Value,
        context: Option<&Value>,
    ) -> Result<Value, UpstreamError>;

    /// Open the upstream's server→client notification stream (P2-D), boxed so
    /// the trait stays dyn-compatible across transports.
    async fn open_notifications(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError>;

    /// Subscribe to the changes `spec` names and stream them.
    ///
    /// Distinct from [`Self::open_notifications`], which takes whatever the
    /// upstream pushes: this asks for specific resources, which is the only
    /// way to learn that one changed rather than that the catalog did.
    async fn open_subscriptions(
        &self,
        spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError>;

    /// The wire actually spoken to this upstream. Differs from the
    /// configured hint when connect probed (`protocol_version: auto`);
    /// the engine caches it per federation so later connects skip the
    /// probe.
    fn wire_is_modern(&self) -> bool {
        false
    }

    async fn close(&self);
}

/// Handles an upstream server→client request (P3) during a bridged call. The
/// engine implements this to bridge the request to the downstream client and
/// await its reply. `Ok(result)` is sent back to the upstream as a JSON-RPC
/// result; `Err((code, message))` as a JSON-RPC error.
#[async_trait]
pub trait UpstreamServerRequestHandler: Send + Sync {
    async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)>;

    /// Forward a server→client *notification* (e.g. `notifications/progress`)
    /// received mid-call to the downstream client (P3-D). Default: ignore.
    async fn forward_notification(&self, _method: &str, _params: Value) {}
}

/// MCP client over Streamable HTTP.
pub struct StreamableHttpUpstream {
    client: reqwest::Client,
    opts: UpstreamConnectOptions,
    /// The wire this connection resolved to speak: the configured
    /// `opts.modern` hint, or the probe's verdict when `opts.probe`.
    modern: bool,
    /// Captured from the `initialize` response's `Mcp-Session-Id`.
    session_id: Option<String>,
    next_id: AtomicU64,
}

impl StreamableHttpUpstream {
    /// Connect: build the guarded client. On the legacy wire this runs
    /// the `initialize` handshake and sends `notifications/initialized`;
    /// the modern (`2026-07-28`) wire is stateless — there is no
    /// handshake and no session, so connect just builds the client and
    /// every request carries its own `_meta` identity (SEP-2575). With
    /// `opts.probe`, the wire is detected first (`server/discover`, then
    /// the legacy fallback).
    pub async fn connect(opts: UpstreamConnectOptions) -> Result<Self, UpstreamError> {
        let client = build_guarded_client(&opts).await?;
        let mut upstream = Self {
            client,
            modern: opts.modern,
            opts,
            session_id: None,
            next_id: AtomicU64::new(1),
        };
        if upstream.opts.probe {
            upstream.probe_wire().await?;
        } else if !upstream.modern {
            upstream.initialize().await?;
        }
        Ok(upstream)
    }

    /// SEP-2575 backward-compatibility probe: attempt the modern
    /// `server/discover`; a peer that rejects it (unsupported protocol
    /// version, unknown method, or a hard HTTP 4xx on the modern
    /// request) is legacy — fall back to the `initialize` handshake.
    /// Transport/DNS/auth failures propagate unchanged so a broken
    /// upstream is not silently misread as legacy.
    async fn probe_wire(&mut self) -> Result<(), UpstreamError> {
        self.modern = true;
        let id = self.next_id();
        let params = json!({
            "protocolVersion": MODERN_FEDERATION_PROTOCOL_VERSION,
            "clientInfo": { "name": wire::CLIENT_NAME, "version": env!("CARGO_PKG_VERSION") },
            "capabilities": self.opts.client_capabilities.clone(),
        });
        match self
            .post(
                &JsonRpcRequest::call(id, "server/discover", Some(params)),
                true,
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if probe_indicates_legacy(&e) => {
                self.modern = false;
                self.initialize().await
            }
            Err(e) => Err(e),
        }
    }

    /// The per-request `_meta.io.modelcontextprotocol/*` identity triple
    /// the modern wire carries in place of the removed `initialize`
    /// handshake (SEP-2575): the protocol version, this gateway's client
    /// identity, and the client capabilities MCPG-as-client advertises.
    fn modern_request_meta(&self) -> Value {
        use mcpg_mcp_wire::v_2026_07_28::wire::meta::{
            META_KEY_CLIENT_CAPABILITIES, META_KEY_CLIENT_INFO, META_KEY_PROTOCOL_VERSION,
        };
        json!({
            META_KEY_PROTOCOL_VERSION: MODERN_FEDERATION_PROTOCOL_VERSION,
            META_KEY_CLIENT_INFO: {
                "name": wire::CLIENT_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
            META_KEY_CLIENT_CAPABILITIES: self.opts.client_capabilities.clone(),
        })
    }

    /// Merge the modern per-request `_meta` identity triple into a
    /// request's `params`, preserving any existing `_meta` keys (e.g. a
    /// bridged `progressToken`).
    fn inject_modern_meta(&self, params: &mut Value) {
        if let Some(obj) = params.as_object_mut() {
            let meta = obj.entry("_meta").or_insert_with(|| json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                for (k, v) in self.modern_request_meta().as_object().into_iter().flatten() {
                    meta_obj.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
    }

    async fn initialize(&mut self) -> Result<(), UpstreamError> {
        let id = self.next_id();
        // With no sampling/elicitation/roots capability advertised, a
        // well-behaved upstream won't emit server requests mid-call.
        let params = json!({
            "protocolVersion": FEDERATION_PROTOCOL_VERSION,
            "capabilities": self.opts.client_capabilities.clone(),
            "clientInfo": { "name": wire::CLIENT_NAME, "version": env!("CARGO_PKG_VERSION") },
        });
        let (_result, session) = self
            .post(&JsonRpcRequest::call(id, "initialize", Some(params)), false)
            .await?;
        self.session_id = session;
        // Strict version negotiation is a follow-up; the client accepts
        // the upstream's `initialize` result as-is.
        self.post(
            &JsonRpcRequest::notification("notifications/initialized", None),
            true,
        )
        .await?;
        Ok(())
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Send one JSON-RPC message. Returns `(result, session_id_header)`.
    /// For notifications (`id == None`) the body is drained and `result`
    /// is `None`. `after_init` adds the session + protocol-version
    /// headers (omitted on the `initialize` request itself).
    ///
    /// On the modern wire this also injects the per-request `_meta`
    /// identity triple (SEP-2575) and the SEP-2243 routing headers
    /// derived from the body's method / params (`input_schema` enables
    /// `tools/call` param promotion); on the legacy wire `body` and the
    /// headers are byte-identical to before.
    async fn post(
        &self,
        body: &JsonRpcRequest,
        after_init: bool,
    ) -> Result<(Option<Value>, Option<String>), UpstreamError> {
        self.post_with_schema(body, after_init, None).await
    }

    async fn post_with_schema(
        &self,
        body: &JsonRpcRequest,
        after_init: bool,
        input_schema: Option<&Value>,
    ) -> Result<(Option<Value>, Option<String>), UpstreamError> {
        let resp = if self.modern && body.id.is_some() {
            // Carry the request-scoped `_meta` identity + SEP-2243 routing
            // headers on the modern wire. Notifications carry no identity
            // (this revision defines no client→server notification over
            // Streamable HTTP), so they take the plain path.
            let mut params = body.params.clone().unwrap_or_else(|| json!({}));
            self.inject_modern_meta(&mut params);
            let headers = self.modern_routing_headers(body.method, &params, input_schema);
            let rebuilt = JsonRpcRequest {
                jsonrpc: body.jsonrpc,
                id: body.id,
                method: body.method,
                params: Some(params),
            };
            self.send_post_with_headers(&rebuilt, after_init, &headers)
                .await?
        } else {
            self.send_post(body, after_init).await?
        };
        let session = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        // Notification: no JSON-RPC response expected.
        if body.id.is_none() {
            return Ok((None, session));
        }
        if let Some(len) = resp.content_length()
            && len > self.opts.max_response_bytes
        {
            return Err(UpstreamError::ResponseTooLarge {
                limit: self.opts.max_response_bytes,
            });
        }
        let is_sse = is_event_stream(&resp);
        let text = read_capped(resp, self.opts.max_response_bytes).await?;
        tap_frame(
            &self.opts.tap,
            FrameDirection::Received,
            FrameChannel::HttpResponse,
            text.as_bytes(),
        );
        let parsed = wire::parse_jsonrpc_body(is_sse, &text).map_err(UpstreamError::Protocol)?;
        if let Some(err) = parsed.error {
            return Err(UpstreamError::JsonRpc {
                code: err.code,
                message: err.message,
            });
        }
        Ok((parsed.result, session))
    }

    /// Build + send a POST, returning the validated response (status checked,
    /// body not yet read). Shared by [`post`] (read+parse) and the bridged
    /// tool-call loop (stream). `body` is any serializable JSON-RPC message —
    /// a request, or a response to an upstream server-request.
    async fn send_post<B: serde::Serialize + ?Sized>(
        &self,
        body: &B,
        after_init: bool,
    ) -> Result<reqwest::Response, UpstreamError> {
        self.send_post_with_headers(body, after_init, &[]).await
    }

    /// As [`send_post`], plus the SEP-2243 routing headers
    /// (`Mcp-Method` / `Mcp-Name` / `Mcp-Param-{Name}`) the modern wire
    /// mirrors onto id-bearing POSTs. `extra_headers` is empty on the
    /// legacy wire.
    ///
    /// On the modern wire the protocol-version header is sent on every
    /// POST (SEP-2575) and `Mcp-Session-Id` is never sent (stateless,
    /// SEP-2567); on the legacy wire the version + session headers are
    /// attached only `after_init`, byte-identical to before.
    async fn send_post_with_headers<B: serde::Serialize + ?Sized>(
        &self,
        body: &B,
        after_init: bool,
        extra_headers: &[(String, String)],
    ) -> Result<reqwest::Response, UpstreamError> {
        let mut req = self
            .client
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
        if self.modern {
            req = req.header("mcp-protocol-version", MODERN_FEDERATION_PROTOCOL_VERSION);
            for (name, value) in extra_headers {
                req = req.header(name.as_str(), value.as_str());
            }
        } else if after_init {
            req = req.header("mcp-protocol-version", FEDERATION_PROTOCOL_VERSION);
            if let Some(sid) = &self.session_id {
                req = req.header("mcp-session-id", sid);
            }
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
            if self.modern {
                headers.push((
                    "mcp-protocol-version".into(),
                    MODERN_FEDERATION_PROTOCOL_VERSION.into(),
                ));
                headers.extend(extra_headers.iter().cloned());
            } else if after_init {
                headers.push((
                    "mcp-protocol-version".into(),
                    FEDERATION_PROTOCOL_VERSION.into(),
                ));
                if let Some(sid) = &self.session_id {
                    headers.push(("mcp-session-id".into(), sid.clone()));
                }
            }
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
            // Surface the JSON-RPC error code when the error body carries
            // one (e.g. 400 + `-32022` unsupported protocol version) so
            // the wire probe can classify the rejection.
            let jsonrpc_code = match read_capped(resp, self.opts.max_response_bytes).await {
                Ok(text) => {
                    tap_frame(
                        &self.opts.tap,
                        FrameDirection::Received,
                        FrameChannel::HttpResponse,
                        text.as_bytes(),
                    );
                    serde_json::from_str::<Value>(&text)
                        .ok()
                        .and_then(|v| v.get("error")?.get("code")?.as_i64())
                }
                Err(_) => None,
            };
            return Err(UpstreamError::Http {
                status: status.as_u16(),
                jsonrpc_code,
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

    /// SEP-2243 routing headers for a modern id-bearing request:
    /// `Mcp-Method` (the JSON-RPC method, always), `Mcp-Name` (the tool
    /// name / resource uri / prompt name for `tools/call` /
    /// `resources/read` / `prompts/get`), and the `Mcp-Param-{Name}`
    /// param promotions for `tools/call` when an `inputSchema` is known.
    /// Non-ASCII `Mcp-Name` values use the `=?base64?…?=` sentinel.
    /// Empty on the legacy wire.
    fn modern_routing_headers(
        &self,
        method: &str,
        params: &Value,
        input_schema: Option<&Value>,
    ) -> Vec<(String, String)> {
        use mcpg_mcp_wire::v_2026_07_28::wire::{METHOD_HEADER, NAME_HEADER, encode_header_value};
        if !self.modern {
            return Vec::new();
        }
        let mut headers = vec![(METHOD_HEADER.to_owned(), method.to_owned())];
        // `Mcp-Name` mirrors `params.name` (tools/call, prompts/get) or
        // `params.uri` (resources/read).
        let name = match method {
            "tools/call" | "prompts/get" => params.get("name").and_then(Value::as_str),
            "resources/read" => params.get("uri").and_then(Value::as_str),
            _ => None,
        };
        if let Some(name) = name {
            headers.push((NAME_HEADER.to_owned(), encode_header_value(name)));
        }
        // `Mcp-Param-{Name}` promotion (tools/call only) reuses the
        // server-side promoter so the constraint + encoding rules are
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

    /// POST a request and, if the upstream answers with an SSE stream, handle
    /// interleaved server→client requests via `handler` (each reply POSTed back
    /// to the upstream session) until the terminal result. A plain JSON
    /// response (no bridging) returns immediately. Shared by the bridged
    /// tools/call, resources/read, and prompts/get paths (P3). When
    /// `progress_token` is set it is attached as `_meta.progressToken` so the
    /// upstream reports progress under the downstream client's token.
    async fn send_request_bridged(
        &self,
        method: &'static str,
        mut params: Value,
        progress_token: Option<&Value>,
        input_schema: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        if let Some(token) = progress_token
            && let Some(obj) = params.as_object_mut()
        {
            let meta = obj.entry("_meta").or_insert_with(|| json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                meta_obj.insert("progressToken".to_owned(), token.clone());
            }
        }
        // Modern wire: carry the per-request identity (SEP-2575) +
        // SEP-2243 routing headers; legacy wire: no `_meta` triple, no
        // routing headers.
        if self.modern {
            self.inject_modern_meta(&mut params);
        }
        let routing_headers = self.modern_routing_headers(method, &params, input_schema);
        let id = self.next_id();
        let resp = self
            .send_post_with_headers(
                &JsonRpcRequest::call(id, method, Some(params)),
                true,
                &routing_headers,
            )
            .await?;

        if !is_event_stream(&resp) {
            // No bridging needed — a single JSON-RPC response.
            let text = read_capped(resp, self.opts.max_response_bytes).await?;
            tap_frame(
                &self.opts.tap,
                FrameDirection::Received,
                FrameChannel::HttpResponse,
                text.as_bytes(),
            );
            let parsed = wire::parse_jsonrpc_body(false, &text).map_err(UpstreamError::Protocol)?;
            if let Some(err) = parsed.error {
                return Err(UpstreamError::JsonRpc {
                    code: err.code,
                    message: err.message,
                });
            }
            return parsed
                .result
                .ok_or_else(|| UpstreamError::Protocol(format!("{method} returned no result")));
        }

        let stream =
            jsonrpc_message_stream(resp, self.opts.max_response_bytes, self.opts.tap.clone());
        futures::pin_mut!(stream);
        use futures::StreamExt;
        while let Some(msg) = stream.next().await {
            let frame_method = msg.get("method").and_then(Value::as_str);
            match (frame_method, msg.get("id")) {
                // Server→client request: bridge it, POST the reply upstream.
                (Some(frame_method), Some(req_id)) => {
                    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                    let reply = handler.handle(frame_method, params).await;
                    self.post_server_response(req_id.clone(), reply).await?;
                }
                // Terminal response to our request (has id, no method).
                (None, Some(_)) => {
                    if let Some(err) = msg.get("error") {
                        return Err(UpstreamError::JsonRpc {
                            code: err.get("code").and_then(Value::as_i64).unwrap_or(-32603),
                            message: err
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("upstream error")
                                .to_owned(),
                        });
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
                // Notification (method, no id): forward it to the client (P3-D).
                (Some(frame_method), None) => {
                    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                    handler.forward_notification(frame_method, params).await;
                }
                _ => {}
            }
        }
        Err(UpstreamError::Protocol(format!(
            "{method} stream ended without a result"
        )))
    }

    /// POST a JSON-RPC response to an upstream server-request back onto the
    /// session, draining the ack.
    async fn post_server_response(
        &self,
        id: Value,
        reply: Result<Value, (i64, String)>,
    ) -> Result<(), UpstreamError> {
        let body = match reply {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
            }
        };
        let resp = self.send_post(&body, true).await?;
        // Drain the ack (202 / empty / small json); body is uninteresting
        // to the client but still shown to a tap.
        if let Ok(text) = read_capped(resp, self.opts.max_response_bytes).await {
            tap_frame(
                &self.opts.tap,
                FrameDirection::Received,
                FrameChannel::HttpResponse,
                text.as_bytes(),
            );
        }
        Ok(())
    }

    /// Open the upstream's server→client SSE stream (`GET` with
    /// `Accept: text/event-stream`) and yield parsed JSON-RPC *notification*
    /// objects (no `id`, has `method`) as they arrive. The federation
    /// listener uses this to react to `*/list_changed` + `resources/updated`
    /// pushes. The returned stream ends when the upstream closes the
    /// connection; the caller reconnects with backoff.
    async fn open_notifications_stream(
        &self,
    ) -> Result<impl futures::Stream<Item = Value> + Send + use<>, UpstreamError> {
        let mut headers: Vec<(String, String)> = vec![
            ("accept".into(), "text/event-stream".into()),
            (VIA_HEADER.into(), self.opts.gateway_via.clone()),
            (
                "mcp-protocol-version".into(),
                FEDERATION_PROTOCOL_VERSION.into(),
            ),
        ];
        for (name, value) in &self.opts.headers {
            headers.push((name.clone(), value.clone()));
        }
        if let Some(token) = &self.opts.bearer_token {
            headers.push(("authorization".into(), format!("Bearer {token}")));
        }
        if let Some(sid) = &self.session_id {
            headers.push(("mcp-session-id".into(), sid.clone()));
        }
        // Unconditional here, unlike the POST path: this runs once per
        // federation for the lifetime of a stream, not once per call.
        let signed = self.sign_headers("GET", None, &headers)?;
        headers.extend(signed);
        let mut req = self.client.get(&self.opts.url);
        for (name, value) in &headers {
            req = req.header(name.as_str(), value.as_str());
        }
        let resp = req.send().await.map_err(|e| {
            UpstreamError::Transport(format!("notification GET to {} failed: {e}", self.opts.url))
        })?;
        if !resp.status().is_success() {
            return Err(UpstreamError::Transport(format!(
                "notification stream returned HTTP {}",
                resp.status()
            )));
        }
        Ok(notification_stream(
            resp,
            self.opts.max_response_bytes,
            self.opts.tap.clone(),
        ))
    }

    /// Open the modern replacement for the GET notification stream: a
    /// long-lived `subscriptions/listen` POST-SSE subscribed to the three
    /// URI-free catalog-change targets. The server's ack / response
    /// envelope / completion frames are dropped by the notification
    /// filter (envelope frames carry an id; unknown notification methods
    /// are ignored by the engine), leaving the `*/list_changed` pushes.
    /// Per-URI `resources/updated` targets are not requested here —
    /// subscribed federated resources are covered by poll synthesis.
    async fn open_subscriptions_listen(
        &self,
    ) -> Result<impl futures::Stream<Item = Value> + Send + use<>, UpstreamError> {
        self.open_subscriptions_listen_for(&SubscriptionSpec::all_list_changed())
            .await
    }

    /// `subscriptions/listen` for exactly what `spec` names.
    async fn open_subscriptions_listen_for(
        &self,
        spec: &SubscriptionSpec,
    ) -> Result<impl futures::Stream<Item = Value> + Send + use<>, UpstreamError> {
        use mcpg_mcp_wire::v_2026_07_28::wire::subscriptions::{
            METHOD_SUBSCRIPTIONS_LISTEN, SubscriptionsListenParams,
        };
        let params = SubscriptionsListenParams {
            subscriptions: spec.targets(),
            meta: None,
        };
        let mut params = serde_json::to_value(&params)
            .map_err(|e| UpstreamError::Protocol(format!("listen params serialize: {e}")))?;
        self.inject_modern_meta(&mut params);
        let headers = self.modern_routing_headers(METHOD_SUBSCRIPTIONS_LISTEN, &params, None);
        let id = self.next_id();
        let resp = self
            .send_post_with_headers(
                &JsonRpcRequest::call(id, METHOD_SUBSCRIPTIONS_LISTEN, Some(params)),
                true,
                &headers,
            )
            .await?;
        if !is_event_stream(&resp) {
            // A JSON body is the server declining the stream.
            let text = read_capped(resp, self.opts.max_response_bytes).await?;
            let parsed = wire::parse_jsonrpc_body(false, &text).map_err(UpstreamError::Protocol)?;
            return Err(match parsed.error {
                Some(err) => UpstreamError::JsonRpc {
                    code: err.code,
                    message: err.message,
                },
                None => {
                    UpstreamError::Protocol("subscriptions/listen did not open a stream".into())
                }
            });
        }
        Ok(notification_stream(
            resp,
            self.opts.max_response_bytes,
            self.opts.tap.clone(),
        ))
    }
}

/// Incrementally parse an SSE byte stream into JSON-RPC notification values.
/// SSE events are separated by a blank line; we accumulate bytes (so a chunk
/// split across a UTF-8 boundary or mid-frame is handled), drain whole
/// frames on `\n\n`, and surface only notifications (object with `method`,
/// no `id`). A frame buffer that grows past 4× the response cap without a
/// boundary aborts the stream (defensive against a non-framing upstream).
fn notification_stream(
    mut resp: reqwest::Response,
    max_response_bytes: u64,
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
        while let Ok(Some(chunk)) = resp.chunk().await {
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

/// Whether a `server/discover` probe failure means "legacy peer" (fall
/// back to `initialize`) rather than a real outage. A legacy MCP server
/// answers the modern request with HTTP 400 + `-32022`
/// (unsupported protocol version), 404/405/406 from a strict router, or
/// a 2xx JSON-RPC `-32601`/`-32600`/`-32602` from a legacy dispatcher.
fn probe_indicates_legacy(e: &UpstreamError) -> bool {
    match e {
        UpstreamError::Http { status, .. } => {
            matches!(*status, 400 | 404 | 405 | 406 | 501)
        }
        UpstreamError::JsonRpc { code, .. } => {
            matches!(*code, -32022 | -32601 | -32600 | -32602)
        }
        _ => false,
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

/// Incrementally parse an SSE byte stream into JSON-RPC messages, yielding
/// **every** frame (requests, responses, and notifications) — unlike
/// [`notification_stream`], which filters to notifications. Used by the bridged
/// tool-call loop, which must act on interleaved server-requests and the
/// terminal response alike. Same framing + cap behaviour as `notification_stream`.
fn jsonrpc_message_stream(
    mut resp: reqwest::Response,
    max_response_bytes: u64,
    tap: Option<crate::tap::SharedTap>,
) -> impl futures::Stream<Item = Value> + Send + use<> {
    let cap = max_response_bytes.saturating_mul(4);
    async_stream::stream! {
        let mut buf: Vec<u8> = Vec::new();
        // Bytes already searched. Only the trailing `needle.len() - 1` bytes
        // can start a delimiter that completes in the next chunk.
        let mut scanned = 0usize;
        while let Ok(Some(chunk)) = resp.chunk().await {
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > cap {
                break;
            }
            while let Some(idx) = find_subslice_from(&buf, b"\n\n", scanned) {
                let frame: Vec<u8> = buf.drain(..idx + 2).collect();
                // The searched prefix left with the frame.
                scanned = 0;
                tap_frame(&tap, FrameDirection::Received, FrameChannel::HttpSse, &frame);
                let Ok(text) = std::str::from_utf8(&frame) else {
                    continue;
                };
                for line in text.lines() {
                    let Some(data) = line.strip_prefix("data:") else {
                        continue;
                    };
                    if let Ok(val) = serde_json::from_str::<Value>(data.trim()) {
                        yield val;
                    }
                }
            }
            // Same linear-scan bookkeeping as the notification stream.
            scanned = buf.len().saturating_sub(1);
        }
    }
}

#[async_trait]
impl McpUpstream for StreamableHttpUpstream {
    async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let id = self.next_id();
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let (result, _) = self
                .post(&JsonRpcRequest::call(id, "tools/list", params), true)
                .await?;
            let result = result
                .ok_or_else(|| UpstreamError::Protocol("tools/list returned no result".into()))?;
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
            let id = self.next_id();
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let (result, _) = self
                .post(&JsonRpcRequest::call(id, "resources/list", params), true)
                .await?;
            let result = result.ok_or_else(|| {
                UpstreamError::Protocol("resources/list returned no result".into())
            })?;
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
            let id = self.next_id();
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let (result, _) = self
                .post(
                    &JsonRpcRequest::call(id, "resources/templates/list", params),
                    true,
                )
                .await?;
            let result = result.ok_or_else(|| {
                UpstreamError::Protocol("resources/templates/list returned no result".into())
            })?;
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
        let id = self.next_id();
        let params = json!({ "uri": uri });
        let (result, _) = self
            .post(
                &JsonRpcRequest::call(id, "resources/read", Some(params)),
                true,
            )
            .await?;
        result.ok_or_else(|| UpstreamError::Protocol("resources/read returned no result".into()))
    }

    async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError> {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let id = self.next_id();
            let params = cursor.as_ref().map(|c| json!({ "cursor": c }));
            let (result, _) = self
                .post(&JsonRpcRequest::call(id, "prompts/list", params), true)
                .await?;
            let result = result
                .ok_or_else(|| UpstreamError::Protocol("prompts/list returned no result".into()))?;
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
        let id = self.next_id();
        let params = json!({
            "name": name,
            "arguments": arguments.cloned().unwrap_or_else(|| json!({})),
        });
        let (result, _) = self
            .post(&JsonRpcRequest::call(id, "prompts/get", Some(params)), true)
            .await?;
        result.ok_or_else(|| UpstreamError::Protocol("prompts/get returned no result".into()))
    }

    async fn call_tool_with_meta(
        &self,
        name: &str,
        arguments: Option<&Value>,
        meta: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let id = self.next_id();
        let mut params = json!({
            "name": name,
            "arguments": arguments.cloned().unwrap_or_else(|| json!({})),
        });
        if let (Some(meta), Some(obj)) = (meta, params.as_object_mut()) {
            obj.insert("_meta".to_owned(), meta.clone());
        }
        let (result, _) = self
            .post(&JsonRpcRequest::call(id, "tools/call", Some(params)), true)
            .await?;
        result.ok_or_else(|| UpstreamError::Protocol("tools/call returned no result".into()))
    }

    async fn call_tool_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        input_schema: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
        progress_token: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let params = json!({
            "name": name,
            "arguments": arguments.cloned().unwrap_or_else(|| json!({})),
        });
        self.send_request_bridged("tools/call", params, progress_token, input_schema, handler)
            .await
    }

    async fn read_resource_bridged(
        &self,
        uri: &str,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        self.send_request_bridged("resources/read", json!({ "uri": uri }), None, None, handler)
            .await
    }

    async fn get_prompt_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        let params = json!({
            "name": name,
            "arguments": arguments.cloned().unwrap_or_else(|| json!({})),
        });
        self.send_request_bridged("prompts/get", params, None, None, handler)
            .await
    }

    async fn open_notifications(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        // The modern wire removed the standalone GET notification stream
        // (a 2026-07-28 server answers GET with 405); change notifications
        // arrive on a `subscriptions/listen` POST-SSE stream instead. An
        // upstream that rejects the method parks on a never-yielding
        // stream (no hot reconnect loop) — the TTL capability refresh
        // remains its freshness path.
        if self.modern {
            return match self.open_subscriptions_listen().await {
                Ok(stream) => Ok(Box::pin(stream)),
                Err(e) if probe_indicates_legacy(&e) => {
                    tracing::debug!(
                        url = %self.opts.url, error = %e,
                        "upstream does not serve subscriptions/listen; parking listener"
                    );
                    Ok(Box::pin(futures::stream::pending()))
                }
                Err(e) => Err(e),
            };
        }
        Ok(Box::pin(self.open_notifications_stream().await?))
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
        let id = self.next_id();
        let (result, _) = self
            .post(
                &JsonRpcRequest::call(
                    id,
                    mcpg_mcp_wire::v_2026_07_28::wire::completion::METHOD_COMPLETION_COMPLETE,
                    Some(params),
                ),
                true,
            )
            .await?;
        result
            .ok_or_else(|| UpstreamError::Protocol("completion/complete returned no result".into()))
    }

    async fn open_subscriptions(
        &self,
        spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        if spec.is_empty() {
            return Ok(Box::pin(futures::stream::pending()));
        }
        if self.modern {
            return Ok(Box::pin(self.open_subscriptions_listen_for(spec).await?));
        }
        // Legacy: per-URI subscription is a request of its own, and the
        // pushes arrive on the standing GET stream. list-changed needs no
        // subscription there — a server that supports it pushes regardless.
        for uri in &spec.resource_uris {
            self.post(
                &JsonRpcRequest::call(
                    self.next_id(),
                    "resources/subscribe",
                    Some(json!({ "uri": uri })),
                ),
                true,
            )
            .await?;
        }
        Ok(Box::pin(self.open_notifications_stream().await?))
    }

    fn wire_is_modern(&self) -> bool {
        self.modern
    }

    async fn close(&self) {
        // The modern wire is stateless — no session to tear down, and a
        // 2026-07-28 server answers DELETE with 405 (SEP-2567).
        if self.modern {
            return;
        }
        // Best-effort session teardown; a dead upstream is fine.
        if let Some(sid) = &self.session_id {
            let mut headers: Vec<(String, String)> = vec![
                ("mcp-session-id".into(), sid.clone()),
                (
                    "mcp-protocol-version".into(),
                    FEDERATION_PROTOCOL_VERSION.into(),
                ),
                (VIA_HEADER.into(), self.opts.gateway_via.clone()),
            ];
            match self.sign_headers("DELETE", None, &headers) {
                Ok(signed) => headers.extend(signed),
                Err(_) => return,
            }
            let mut req = self.client.delete(&self.opts.url);
            for (name, value) in &headers {
                req = req.header(name.as_str(), value.as_str());
            }
            let _ = req.send().await;
        }
    }
}

/// MCP client over a stdio child process (P4-A.2). One bidirectional pipe
/// (child stdin/stdout, newline-delimited JSON-RPC), so a single `io` Mutex
/// serializes each request/response cycle: the active call owns the stream and
/// reads it until *its* response, handling any interleaved server→client
/// requests (bridge) + notifications (forward) inline — the same shape as the
/// HTTP SSE loop. Because the channel is shared, there is no separate
/// notification listener (the engine skips listeners for stdio); pushes that
/// arrive between calls are drained on the next call.
pub struct StdioUpstream {
    opts: UpstreamConnectOptions,
    next_id: AtomicU64,
    io: tokio::sync::Mutex<StdioIo>,
}

struct StdioIo {
    /// Kept so the child is reaped on drop (`kill_on_drop`) + explicit close.
    child: tokio::process::Child,
    stdin: tokio::process::ChildStdin,
    stdout: tokio::io::BufReader<tokio::process::ChildStdout>,
}

impl StdioUpstream {
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
        };
        upstream.initialize().await?;
        Ok(upstream)
    }

    async fn initialize(&self) -> Result<(), UpstreamError> {
        let params = json!({
            "protocolVersion": FEDERATION_PROTOCOL_VERSION,
            "capabilities": self.opts.client_capabilities.clone(),
            "clientInfo": { "name": wire::CLIENT_NAME, "version": env!("CARGO_PKG_VERSION") },
        });
        self.call("initialize", params, None, None).await?;
        self.notify("notifications/initialized").await
    }

    async fn notify(&self, method: &'static str) -> Result<(), UpstreamError> {
        let msg = json!({ "jsonrpc": "2.0", "method": method });
        let mut io = self.io.lock().await;
        write_line(&mut io.stdin, &msg, &self.opts.tap).await
    }

    /// Core request/response over the serialized pipe. Writes the request, then
    /// reads frames until *our* response id: interleaved server→client requests
    /// go to `handler` (the reply is written back), notifications to
    /// `handler.forward_notification`. With `handler: None` (plain calls)
    /// server-requests are declined and notifications ignored.
    async fn call(
        &self,
        method: &'static str,
        mut params: Value,
        progress_token: Option<&Value>,
        handler: Option<&dyn UpstreamServerRequestHandler>,
    ) -> Result<Value, UpstreamError> {
        if let Some(token) = progress_token
            && let Some(obj) = params.as_object_mut()
        {
            let meta = obj.entry("_meta").or_insert_with(|| json!({}));
            if let Some(meta_obj) = meta.as_object_mut() {
                meta_obj.insert("progressToken".to_owned(), token.clone());
            }
        }
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
                // Server→client request: bridge (or decline), reply on stdin.
                (Some(frame_method), Some(req_id)) => {
                    let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                    let reply = match handler {
                        Some(h) => h.handle(frame_method, params).await,
                        None => Err((
                            -32601,
                            format!("server-request '{frame_method}' not supported (no bridge)"),
                        )),
                    };
                    let resp = match reply {
                        Ok(result) => json!({ "jsonrpc": "2.0", "id": req_id, "result": result }),
                        Err((code, message)) => json!({
                            "jsonrpc": "2.0", "id": req_id,
                            "error": { "code": code, "message": message }
                        }),
                    };
                    write_line(&mut io.stdin, &resp, &self.opts.tap).await?;
                }
                // Terminal response to our request.
                (None, Some(resp_id)) if resp_id == &json!(id) => {
                    if let Some(err) = msg.get("error") {
                        return Err(UpstreamError::JsonRpc {
                            code: err.get("code").and_then(Value::as_i64).unwrap_or(-32603),
                            message: err
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("upstream error")
                                .to_owned(),
                        });
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
                // Notification: forward via the handler (if bridging).
                (Some(frame_method), None) => {
                    if let Some(h) = handler {
                        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));
                        h.forward_notification(frame_method, params).await;
                    }
                }
                _ => {} // stray response for another id — ignore (serialized io)
            }
        }
    }
}

#[async_trait]
impl McpUpstream for StdioUpstream {
    async fn list_tools(&self) -> Result<Vec<UpstreamTool>, UpstreamError> {
        let r = self.call("tools/list", json!({}), None, None).await?;
        Ok(serde_json::from_value::<ListToolsResult>(r)
            .map_err(|e| UpstreamError::Protocol(format!("invalid tools/list result: {e}")))?
            .tools)
    }

    async fn list_resources(&self) -> Result<Vec<UpstreamResource>, UpstreamError> {
        let r = self.call("resources/list", json!({}), None, None).await?;
        Ok(serde_json::from_value::<ListResourcesResult>(r)
            .map_err(|e| UpstreamError::Protocol(format!("invalid resources/list result: {e}")))?
            .resources)
    }

    async fn list_resource_templates(
        &self,
    ) -> Result<Vec<UpstreamResourceTemplate>, UpstreamError> {
        let r = self
            .call("resources/templates/list", json!({}), None, None)
            .await?;
        Ok(serde_json::from_value::<ListResourceTemplatesResult>(r)
            .map_err(|e| {
                UpstreamError::Protocol(format!("invalid resources/templates/list result: {e}"))
            })?
            .resource_templates)
    }

    async fn read_resource(&self, uri: &str) -> Result<Value, UpstreamError> {
        self.call("resources/read", json!({ "uri": uri }), None, None)
            .await
    }

    async fn list_prompts(&self) -> Result<Vec<UpstreamPrompt>, UpstreamError> {
        let r = self.call("prompts/list", json!({}), None, None).await?;
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
        self.call("prompts/get", params, None, None).await
    }

    async fn call_tool_with_meta(
        &self,
        name: &str,
        arguments: Option<&Value>,
        meta: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let mut params =
            json!({ "name": name, "arguments": arguments.cloned().unwrap_or_else(|| json!({})) });
        if let (Some(meta), Some(obj)) = (meta, params.as_object_mut()) {
            obj.insert("_meta".to_owned(), meta.clone());
        }
        self.call("tools/call", params, None, None).await
    }

    async fn call_tool_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        // stdio never speaks the modern wire (config-validated), so the
        // declared inputSchema is irrelevant — there are no SEP-2243
        // routing headers over a pipe.
        _input_schema: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
        progress_token: Option<&Value>,
    ) -> Result<Value, UpstreamError> {
        let params =
            json!({ "name": name, "arguments": arguments.cloned().unwrap_or_else(|| json!({})) });
        self.call("tools/call", params, progress_token, Some(handler))
            .await
    }

    async fn read_resource_bridged(
        &self,
        uri: &str,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        self.call("resources/read", json!({ "uri": uri }), None, Some(handler))
            .await
    }

    async fn get_prompt_bridged(
        &self,
        name: &str,
        arguments: Option<&Value>,
        handler: &dyn UpstreamServerRequestHandler,
    ) -> Result<Value, UpstreamError> {
        let params =
            json!({ "name": name, "arguments": arguments.cloned().unwrap_or_else(|| json!({})) });
        self.call("prompts/get", params, None, Some(handler)).await
    }

    async fn open_notifications(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        // stdio has no separate notification channel — notifications are drained
        // during call cycles. Return a never-yielding stream so a listener (if
        // ever spawned) parks instead of reconnect-spawning child processes.
        Ok(Box::pin(futures::stream::pending()))
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
            None,
            None,
        )
        .await
    }

    async fn open_subscriptions(
        &self,
        _spec: &SubscriptionSpec,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Value> + Send>>, UpstreamError> {
        // stdio has one bidirectional pipe and no separate stream: pushes
        // are drained during call cycles, so there is nothing to open.
        Ok(Box::pin(futures::stream::pending()))
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
/// transport-agnostic handle (P4 transport abstraction).
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

/// Build a `reqwest::Client` whose DNS is pinned to a validated,
/// non-private address — the same rebinding guard `net-core` applies to
/// HTTP bindings. Pinning closes the TOCTOU window where an
/// attacker-controlled record could flip to a private IP after the
/// check.
async fn build_guarded_client(
    opts: &UpstreamConnectOptions,
) -> Result<reqwest::Client, UpstreamError> {
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

    let mut builder = reqwest::Client::builder()
        .timeout(opts.timeout)
        .redirect(reqwest::redirect::Policy::none())
        .resolve(&host, resolved);
    // A `tunnel://` upstream authenticates its org to the relay's federation
    // ingress with this header on every request. Set it as a client default so
    // POST / SSE / DELETE all carry it. The relay consumes it and does not
    // forward it, so it never reaches the tunnelled gateway.
    if let Some(token) = &opts.tunnel_token {
        let mut headers = reqwest::header::HeaderMap::new();
        let value = reqwest::header::HeaderValue::from_str(token).map_err(|_| {
            UpstreamError::Connect("tunnel token is not a valid HTTP header value".to_owned())
        })?;
        headers.insert(TUNNEL_TOKEN_HEADER, value);
        builder = builder.default_headers(headers);
    }
    builder
        .build()
        .map_err(|e| UpstreamError::Connect(format!("client build failed: {e}")))
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

    /// The typed-array form is what goes on the modern wire, and its order
    /// is what the server echoes back — per-resource watches first, so a
    /// caller can line the acknowledgement up with what it asked for.
    #[test]
    fn a_spec_becomes_the_typed_targets_it_names() {
        use mcpg_mcp_wire::v_2026_07_28::wire::subscriptions::SubscriptionTarget;
        let spec = SubscriptionSpec {
            resource_uris: vec!["docs://a".into(), "docs://b".into()],
            tools_list_changed: true,
            prompts_list_changed: false,
            resources_list_changed: true,
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

    use super::*;
    use axum::Json;
    use axum::response::{IntoResponse, Response};
    use axum::routing::post;
    use axum::{Router, http::StatusCode};

    async fn mock_handler(Json(body): Json<Value>) -> Response {
        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let id = body.get("id").cloned();
        match method {
            "initialize" => {
                let mut resp = Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "mock", "version": "1" }
                    }
                }))
                .into_response();
                resp.headers_mut()
                    .insert("mcp-session-id", "sess-mock-1".parse().unwrap());
                resp
            }
            "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
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
        let app = Router::new().route("/mcp", post(mock_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/mcp")
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
            transport: crate::transport::UpstreamTransport::StreamableHttp,
            headers: std::collections::BTreeMap::new(),
            command: None,
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            modern: false,
            probe: false,
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
        assert_eq!(upstream.session_id.as_deref(), Some("sess-mock-1"));

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

    /// A `2026-07-28` mock: answers `server/discover`; every other method
    /// (including `initialize`) is method-not-found, like a server that
    /// dropped the legacy handshake.
    async fn spawn_modern_mock() -> String {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "server/discover" => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": {
                        "resultType": "discover",
                        "supportedVersions": ["2026-07-28"],
                        "serverInfo": { "name": "modern-mock", "version": "1" },
                        "capabilities": { "tools": {} }
                    }
                }))
                .into_response(),
                _ => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32601, "message": "method not found" }
                }))
                .into_response(),
            }
        }
        let app = Router::new().route("/mcp", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/mcp")
    }

    /// A strict legacy mock: rejects the modern probe with HTTP 400 +
    /// `-32022` (unsupported protocol version) — the shape a `2025-11-25`
    /// gateway produces — while serving the legacy handshake normally.
    async fn spawn_strict_legacy_mock() -> String {
        async fn handler(Json(body): Json<Value>) -> Response {
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            let id = body.get("id").cloned();
            match method {
                "server/discover" => (
                    StatusCode::BAD_REQUEST,
                    Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32022, "message": "unsupported protocol version" }
                    })),
                )
                    .into_response(),
                "initialize" => {
                    let mut resp = Json(json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "protocolVersion": "2025-11-25",
                            "capabilities": { "tools": {} },
                            "serverInfo": { "name": "strict", "version": "1" }
                        }
                    }))
                    .into_response();
                    resp.headers_mut()
                        .insert("mcp-session-id", "sess-strict-1".parse().unwrap());
                    resp
                }
                "notifications/initialized" => StatusCode::ACCEPTED.into_response(),
                _ => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": { "code": -32601, "message": "method not found" }
                }))
                .into_response(),
            }
        }
        let app = Router::new().route("/mcp", post(handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/mcp")
    }

    fn probing_opts(url: String) -> UpstreamConnectOptions {
        let mut o = opts(url, true);
        o.probe = true;
        o
    }

    #[tokio::test]
    async fn probe_detects_modern_upstream_and_skips_handshake() {
        let url = spawn_modern_mock().await;
        let upstream = StreamableHttpUpstream::connect(probing_opts(url))
            .await
            .expect("probing connect against a modern upstream");
        assert!(upstream.wire_is_modern());
        assert!(
            upstream.session_id.is_none(),
            "modern wire is stateless: no handshake, no session"
        );
    }

    #[tokio::test]
    async fn probe_falls_back_to_legacy_on_method_not_found() {
        // The plain legacy mock answers unknown methods with 200 +
        // `-32601`; the probe must read that as "legacy peer" and run
        // the `initialize` handshake.
        let url = spawn_mock().await;
        let upstream = StreamableHttpUpstream::connect(probing_opts(url))
            .await
            .expect("probing connect against a legacy upstream");
        assert!(!upstream.wire_is_modern());
        assert_eq!(upstream.session_id.as_deref(), Some("sess-mock-1"));
    }

    #[tokio::test]
    async fn probe_falls_back_to_legacy_on_http_400_unsupported_version() {
        let url = spawn_strict_legacy_mock().await;
        let upstream = StreamableHttpUpstream::connect(probing_opts(url))
            .await
            .expect("probing connect against a strict legacy upstream");
        assert!(!upstream.wire_is_modern());
        assert_eq!(upstream.session_id.as_deref(), Some("sess-strict-1"));
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

    /// P4-A.2: spawn a canned stdio MCP server (a `/bin/sh` script that replies
    /// to each request line in order) and drive initialize → list → call over
    /// the child's stdin/stdout. Unix-only (the release target is linux-gnu).
    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_transport_connects_lists_and_calls() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("mock-mcp.sh");
        // Requests arrive as id 1 (initialize), then notifications/initialized
        // (no reply), then id 2 (tools/list), id 3 (tools/call).
        std::fs::write(
            &script,
            "#!/bin/sh\n\
             read line\n\
             printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"serverInfo\":{\"name\":\"m\",\"version\":\"1\"}}}'\n\
             read line\n\
             read line\n\
             printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"echo\",\"description\":\"e\",\"inputSchema\":{\"type\":\"object\"}}]}}'\n\
             read line\n\
             printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"stdio-ok\"}],\"isError\":false}}'\n",
        )
        .expect("write script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        let opts = UpstreamConnectOptions {
            url: String::new(),
            bearer_token: None,
            tunnel_token: None,
            allow_private: true,
            max_response_bytes: 1 << 20,
            timeout: Duration::from_secs(5),
            gateway_via: "via-1".to_owned(),
            client_capabilities: serde_json::json!({}),
            transport: crate::transport::UpstreamTransport::Stdio,
            headers: std::collections::BTreeMap::new(),
            command: Some(script.to_string_lossy().into_owned()),
            args: Vec::new(),
            env: std::collections::BTreeMap::new(),
            modern: false,
            probe: false,
            tap: None,
            capture_stdio_stderr: false,
            signer: None,
        };
        let upstream = StdioUpstream::connect(opts)
            .await
            .expect("spawn + initialize stdio upstream");
        let tools = upstream.list_tools().await.expect("list_tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "echo");
        let result = upstream.call_tool("echo", None).await.expect("call_tool");
        assert_eq!(result["content"][0]["text"], "stdio-ok");
        upstream.close().await;
    }

    // --- Modern (2026-07-28) federation-client EMIT (SEP-2243) ---

    use std::sync::{Arc, Mutex};

    /// One captured outbound POST: the request headers + JSON-RPC body.
    #[derive(Clone, Default)]
    struct Captured {
        headers: axum::http::HeaderMap,
        body: Value,
    }

    type Capture = Arc<Mutex<Vec<Captured>>>;

    /// No-op bridge handler — a modern upstream never issues server-requests
    /// on the stream (MRTR replaces them), so this is never asked anything.
    struct NoBridge;
    #[async_trait]
    impl UpstreamServerRequestHandler for NoBridge {
        async fn handle(&self, _method: &str, _params: Value) -> Result<Value, (i64, String)> {
            Err((-32601, "no bridge".into()))
        }
    }

    /// Spawn a mock that records every POST's headers + body and answers
    /// `tools/call` inline. It mints no session header.
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
            Json(json!({
                "jsonrpc": "2.0", "id": id,
                "result": { "content": [{ "type": "text", "text": "ok" }], "isError": false }
            }))
            .into_response()
        }
        let app = Router::new()
            .route("/mcp", post(handler))
            .with_state(capture);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}/mcp")
    }

    fn modern_opts(url: String) -> UpstreamConnectOptions {
        let mut o = opts(url, true);
        o.modern = true;
        o.client_capabilities = json!({ "sampling": {} });
        o
    }

    #[tokio::test]
    async fn modern_upstream_emits_sep2243_headers_and_request_meta() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;

        // Modern connect must NOT handshake — the first POST is the call.
        let upstream = StreamableHttpUpstream::connect(modern_opts(url))
            .await
            .expect("connect modern");
        assert!(
            upstream.session_id.is_none(),
            "modern wire is stateless: no session captured"
        );

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
        let result = upstream
            .call_tool_bridged("execute_sql", Some(&args), Some(&schema), &NoBridge, None)
            .await
            .expect("modern tools/call");
        assert_eq!(result["content"][0]["text"], "ok");

        let p = {
            let posts = capture.lock().unwrap();
            assert_eq!(posts.len(), 1, "no handshake — exactly one POST");
            posts[0].clone()
        };
        let h = |name: &str| p.headers.get(name).and_then(|v| v.to_str().ok());

        // Version header is the modern wire string; no session header.
        assert_eq!(h("mcp-protocol-version"), Some("2026-07-28"));
        assert!(
            p.headers.get("mcp-session-id").is_none(),
            "modern wire MUST NOT send Mcp-Session-Id"
        );

        // SEP-2243 routing headers.
        assert_eq!(h("mcp-method"), Some("tools/call"));
        assert_eq!(h("mcp-name"), Some("execute_sql"));
        assert_eq!(h("mcp-param-region"), Some("us-west1"));
        assert_eq!(
            h("mcp-param-note"),
            Some("=?base64?5LiW55WM?="),
            "non-ASCII param uses the base64 sentinel"
        );

        // Per-request `_meta` identity triple (SEP-2575).
        let meta = &p.body["params"]["_meta"];
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

        upstream.close().await;
        assert_eq!(
            capture.lock().unwrap().len(),
            1,
            "modern close() issues no DELETE"
        );
    }

    #[tokio::test]
    async fn modern_upstream_encodes_non_ascii_tool_name() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;
        let upstream = StreamableHttpUpstream::connect(modern_opts(url))
            .await
            .expect("connect modern");

        upstream
            .call_tool_bridged("выполнить", Some(&json!({})), None, &NoBridge, None)
            .await
            .expect("modern tools/call");

        let posts = capture.lock().unwrap();
        let h = posts[0]
            .headers
            .get("mcp-name")
            .and_then(|v| v.to_str().ok());
        assert_eq!(
            h,
            Some("=?base64?0LLRi9C/0L7Qu9C90LjRgtGM?="),
            "non-ASCII tool name carried via the encoded-word sentinel"
        );
    }

    #[tokio::test]
    async fn legacy_upstream_emits_no_sep2243_headers_and_handshakes() {
        let capture: Capture = Arc::new(Mutex::new(Vec::new()));
        let url = spawn_capturing_mock(Arc::clone(&capture)).await;

        // Legacy (default) connect handshakes (initialize + initialized),
        // then the tool call — three POSTs total, none carrying SEP-2243
        // headers or a per-request `_meta` triple. Byte-identical to before.
        let upstream = StreamableHttpUpstream::connect(opts(url, true))
            .await
            .expect("connect legacy");
        upstream
            .call_tool_bridged(
                "execute_sql",
                Some(&json!({ "region": "us-west1" })),
                None,
                &NoBridge,
                None,
            )
            .await
            .expect("legacy tools/call");

        let posts = capture.lock().unwrap();
        // initialize, notifications/initialized, tools/call.
        assert_eq!(posts.len(), 3);
        let call = posts
            .iter()
            .find(|p| p.body.get("method").and_then(Value::as_str) == Some("tools/call"))
            .expect("tools/call POST");
        assert!(
            call.headers.get("mcp-method").is_none(),
            "no SEP-2243 Mcp-Method on legacy"
        );
        assert!(
            call.headers.get("mcp-name").is_none(),
            "no SEP-2243 Mcp-Name on legacy"
        );
        assert!(
            call.headers.get("mcp-param-region").is_none(),
            "no Mcp-Param on legacy"
        );
        assert_eq!(
            call.headers
                .get("mcp-protocol-version")
                .and_then(|v| v.to_str().ok()),
            Some("2025-11-25"),
            "legacy wire version header unchanged"
        );
        // Legacy params carry no modern `_meta` identity triple.
        assert!(
            call.body["params"].get("_meta").is_none(),
            "legacy request body carries no per-request _meta triple"
        );
    }
}
