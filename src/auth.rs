//! The client half of MCP authorization: reading a `WWW-Authenticate`
//! challenge, then walking the discovery chain — RFC 9728
//! protected-resource metadata on the server's own URL, then RFC 8414
//! authorization-server metadata — to the audience and token endpoint.
//!
//! Two callers with different needs share it. The gateway wants the
//! answer, so [`discover_oauth`] returns just that. The inspector wants
//! to SHOW the chain, including which step failed and why, so
//! [`discover_oauth_traced`] returns every step it took alongside the
//! outcome.
//!
//! Every fetch is SSRF-guarded: the host is resolved once,
//! private/loopback addresses are refused unless the policy opts in,
//! and the vetted address is pinned on the client so a DNS rebind
//! between checks cannot redirect the request.

use std::time::Duration;

use serde::Deserialize;

use mcpg_plugin_backend_net_core::safe_dns;

/// Per-request timeout against metadata endpoints.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on a metadata response body.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// Network posture for discovery fetches. Registry upstreams are
/// TLS-only by construction, so production wiring keeps
/// `allow_insecure_http` false; tests may relax it for loopback mocks.
#[derive(Debug, Clone, Copy)]
pub struct DiscoveryPolicy {
    pub allow_private: bool,
    pub allow_insecure_http: bool,
}

/// What discovery yields for one server: the token audience (the
/// RFC 9728 `resource` identifier) and the AS token endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredOauth {
    pub resource: String,
    pub token_endpoint: String,
    /// The AS issuer, as it validated against the metadata URL.
    pub issuer: String,
    /// Where to send the user for an authorization-code grant. Absent on
    /// an AS that only issues tokens machine-to-machine.
    pub authorization_endpoint: Option<String>,
    /// RFC 7591 dynamic client registration, when offered.
    pub registration_endpoint: Option<String>,
    pub scopes_supported: Vec<String>,
    /// RFC 7636; `S256` is the only method worth using and the only one
    /// the inspector sends.
    pub code_challenge_methods_supported: Vec<String>,
    /// The server accepts a client-metadata-document URL as `client_id`.
    /// A client with a public origin can then skip registration entirely.
    pub client_id_metadata_document_supported: bool,
}

impl DiscoveredOauth {
    /// The per-call issuer config the template credential issuers
    /// consume (`audience` / `resource` / `redeem_token_url`).
    pub fn into_call_config(self) -> serde_json::Value {
        serde_json::json!({
            "audience": self.resource,
            "resource": self.resource,
            "redeem_token_url": self.token_endpoint,
        })
    }
}

/// One step of the discovery chain, as it happened.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DiscoveryStep {
    /// Stable identifier: `protected-resource-metadata`,
    /// `authorization-server-metadata`.
    pub step: &'static str,
    pub url: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// A `WWW-Authenticate: Bearer ...` challenge, as a server sends it on
/// a 401 (or a 403 for a scope step-up). The fields an MCP client acts
/// on: `resource_metadata` points at the RFC 9728 document, and `scope`
/// is authoritative for what to ask for next.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct BearerChallenge {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_metadata: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl BearerChallenge {
    /// Parse a `WWW-Authenticate` header value. Returns `None` when the
    /// header names no `Bearer` scheme. Unknown parameters are ignored
    /// rather than rejected — a challenge carrying an extension
    /// parameter is still a usable challenge.
    pub fn parse(header: &str) -> Option<Self> {
        let rest = header
            .strip_prefix("Bearer")
            .or_else(|| header.strip_prefix("bearer"))?;
        let mut out = Self::default();
        for param in split_params(rest) {
            let Some((key, value)) = param.split_once('=') else {
                continue;
            };
            let value = value.trim().trim_matches('"').to_owned();
            match key.trim().to_ascii_lowercase().as_str() {
                "realm" => out.realm = Some(value),
                "error" => out.error = Some(value),
                "error_description" => out.error_description = Some(value),
                "resource_metadata" => out.resource_metadata = Some(value),
                "scope" => out.scope = Some(value),
                _ => {}
            }
        }
        Some(out)
    }
}

/// Split challenge parameters on commas that are not inside a quoted
/// string - `scope="a,b"` is one parameter, not two.
fn split_params(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

/// RFC 9728 §2 — the subset consumed here.
#[derive(Debug, Deserialize)]
struct ProtectedResourceMetadata {
    resource: String,
    #[serde(default)]
    authorization_servers: Vec<String>,
}

/// RFC 8414 §2 — the subset consumed here.
#[derive(Debug, Deserialize)]
struct AuthorizationServerMetadata {
    issuer: String,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    registration_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
    #[serde(default)]
    code_challenge_methods_supported: Vec<String>,
    /// The server accepts a URL that resolves to a client-metadata
    /// document as `client_id`, so a client with a public origin needs no
    /// registration step at all.
    #[serde(default)]
    client_id_metadata_document_supported: bool,
}

/// Discover the OAuth metadata for one server URL.
///
/// The answer only — callers that want to show the chain use
/// [`discover_oauth_traced`], which this delegates to so the two can
/// never describe different walks.
pub async fn discover_oauth(
    server_url: &str,
    policy: DiscoveryPolicy,
) -> Result<DiscoveredOauth, String> {
    discover_oauth_traced(server_url, policy).await.1
}

/// Discover the OAuth metadata for one server URL, reporting every
/// step attempted. The steps are returned whether or not discovery
/// succeeded: a chain that stops at the first well-known URL is
/// exactly what an operator needs to see.
pub async fn discover_oauth_traced(
    server_url: &str,
    policy: DiscoveryPolicy,
) -> (Vec<DiscoveryStep>, Result<DiscoveredOauth, String>) {
    let mut steps = Vec::new();
    let result = walk(server_url, policy, &mut steps).await;
    (steps, result)
}

async fn walk(
    server_url: &str,
    policy: DiscoveryPolicy,
    steps: &mut Vec<DiscoveryStep>,
) -> Result<DiscoveredOauth, String> {
    let resource = server_url.trim_end_matches('/');
    let prm_url = well_known_url(resource, "oauth-protected-resource")?;
    let rm: ProtectedResourceMetadata = record(
        steps,
        "protected-resource-metadata",
        &prm_url,
        fetch_json(&prm_url, policy).await,
    )?;
    // RFC 9728 §3.3: the client MUST verify the metadata's `resource`
    // is the identifier it derived the well-known URI from — otherwise
    // a compromised host could claim to protect someone else's
    // resource and steer audience-bound tokens to it.
    if rm.resource.trim_end_matches('/') != resource {
        return Err(format!(
            "protected-resource metadata resource {:?} does not match server url {:?}",
            rm.resource, server_url
        ));
    }
    let authz_server = rm
        .authorization_servers
        .first()
        .ok_or_else(|| "protected-resource metadata lists no authorization_servers".to_owned())?;
    if rm.authorization_servers.len() > 1 {
        tracing::debug!(
            server = %server_url,
            count = rm.authorization_servers.len(),
            "multiple authorization servers advertised; using the first"
        );
    }

    let asm_url = well_known_url(
        authz_server.trim_end_matches('/'),
        "oauth-authorization-server",
    )?;
    let asm: AuthorizationServerMetadata = record(
        steps,
        "authorization-server-metadata",
        &asm_url,
        fetch_json(&asm_url, policy).await,
    )?;
    // RFC 8414 §3.3: the returned issuer must equal the URL the
    // metadata was derived from.
    if asm.issuer.trim_end_matches('/') != authz_server.trim_end_matches('/') {
        return Err(format!(
            "authorization-server metadata issuer {:?} does not match {:?}",
            asm.issuer, authz_server
        ));
    }
    let token_endpoint = asm
        .token_endpoint
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "authorization-server metadata has no token_endpoint".to_owned())?;
    if !token_endpoint.starts_with("https://")
        && !(policy.allow_insecure_http && token_endpoint.starts_with("http://"))
    {
        return Err(format!("token_endpoint {token_endpoint:?} must be https"));
    }
    Ok(DiscoveredOauth {
        resource: rm.resource,
        token_endpoint,
        issuer: asm.issuer,
        authorization_endpoint: asm.authorization_endpoint.filter(|s| !s.is_empty()),
        registration_endpoint: asm.registration_endpoint.filter(|s| !s.is_empty()),
        scopes_supported: asm.scopes_supported,
        code_challenge_methods_supported: asm.code_challenge_methods_supported,
        client_id_metadata_document_supported: asm.client_id_metadata_document_supported,
    })
}

/// Record one fetch as a step and pass its outcome through.
fn record<T>(
    steps: &mut Vec<DiscoveryStep>,
    step: &'static str,
    url: &str,
    outcome: Result<T, String>,
) -> Result<T, String> {
    steps.push(DiscoveryStep {
        step,
        url: url.to_owned(),
        ok: outcome.is_ok(),
        detail: outcome.as_ref().err().cloned(),
    });
    outcome
}

/// Build the path-aware well-known URL (RFC 8414 §3 / RFC 9728 §3.1):
/// the well-known segment is inserted between the authority and the
/// identifier's path, so `https://h/mcp` → `https://h/.well-known/<seg>/mcp`.
fn well_known_url(identifier: &str, segment: &str) -> Result<String, String> {
    let url =
        url::Url::parse(identifier).map_err(|e| format!("invalid url {identifier:?}: {e}"))?;
    let origin = format!(
        "{}://{}",
        url.scheme(),
        url.host_str()
            .ok_or_else(|| format!("url {identifier:?} has no host"))?
    );
    let origin = match url.port() {
        Some(p) => format!("{origin}:{p}"),
        None => origin,
    };
    let path = url.path().trim_end_matches('/');
    Ok(if path.is_empty() {
        format!("{origin}/.well-known/{segment}")
    } else {
        format!("{origin}/.well-known/{segment}{path}")
    })
}

/// A client that may only reach the address this URL resolved to, right now.
///
/// Scheme check, one DNS resolution through the private-address gate, then the
/// result pinned for the life of the client. Every outbound probe in the
/// inspector and the gateway's discovery walk goes through here, because the
/// alternative is one call site that builds a plain `reqwest::Client` and
/// quietly becomes the way out of the pod.
pub async fn guarded_client(
    url_str: &str,
    policy: DiscoveryPolicy,
    timeout: std::time::Duration,
) -> Result<reqwest::Client, String> {
    let url = url::Url::parse(url_str).map_err(|e| format!("invalid url {url_str:?}: {e}"))?;
    match url.scheme() {
        "https" => {}
        "http" if policy.allow_insecure_http => {}
        other => return Err(format!("scheme {other:?} not permitted for {url_str:?}")),
    }
    let host = url
        .host_str()
        .ok_or_else(|| format!("url {url_str:?} has no host"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("url {url_str:?} has no known port"))?;
    let addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;
    let mut chosen = None;
    for addr in addrs {
        if policy.allow_private || !safe_dns::is_private_address(&addr.ip()) {
            chosen = Some(addr);
            break;
        }
    }
    let resolved = chosen.ok_or_else(|| {
        format!("host '{host}' resolved only to private/loopback addresses (not permitted)")
    })?;
    reqwest::Client::builder()
        .timeout(timeout)
        .resolve(&host, resolved)
        // The address pin above only binds THIS host. A redirect sends the
        // request to a different one, which reqwest resolves normally —
        // so following redirects steps straight around the pin and the
        // private-address check that produced it.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("client build failed: {e}"))
}

/// Guarded GET: scheme check, single DNS resolution with the private-
/// address gate, pinned connect, response-size cap.
async fn fetch_json<T: serde::de::DeserializeOwned>(
    url_str: &str,
    policy: DiscoveryPolicy,
) -> Result<T, String> {
    let client = guarded_client(url_str, policy, REQUEST_TIMEOUT).await?;
    let resp = client
        .get(url_str)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("request to {url_str} failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("{url_str} returned HTTP {status}"));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("body read failed: {e}"))?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(format!("response exceeded {MAX_RESPONSE_BYTES} bytes"));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid metadata document: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Json;
    use axum::routing::get;

    #[test]
    fn well_known_urls_are_path_aware() {
        assert_eq!(
            well_known_url("https://h.example/mcp", "oauth-protected-resource").unwrap(),
            "https://h.example/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            well_known_url("https://h.example", "oauth-authorization-server").unwrap(),
            "https://h.example/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            well_known_url("https://h.example:8443/", "oauth-authorization-server").unwrap(),
            "https://h.example:8443/.well-known/oauth-authorization-server"
        );
    }

    /// Serve both metadata documents from one loopback mock and walk
    /// the full 9728 → 8414 chain.
    #[tokio::test]
    async fn discovers_resource_and_token_endpoint() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let server_url = format!("{base}/mcp");
        let rm = {
            let server_url = server_url.clone();
            let base = base.clone();
            move || {
                let doc = serde_json::json!({
                    "resource": server_url,
                    "authorization_servers": [base],
                });
                async move { Json(doc) }
            }
        };
        let asm = {
            let base = base.clone();
            move || {
                let doc = serde_json::json!({
                    "issuer": base,
                    "token_endpoint": format!("{base}/oauth2/token"),
                });
                async move { Json(doc) }
            }
        };
        let app = axum::Router::new()
            .route("/.well-known/oauth-protected-resource/mcp", get(rm))
            .route("/.well-known/oauth-authorization-server", get(asm));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let policy = DiscoveryPolicy {
            allow_private: true,
            allow_insecure_http: true,
        };
        let d = discover_oauth(&server_url, policy)
            .await
            .expect("discovers");
        assert_eq!(d.resource, server_url);
        assert_eq!(d.token_endpoint, format!("{base}/oauth2/token"));
        let cfg = d.into_call_config();
        assert_eq!(cfg["audience"], serde_json::json!(server_url));
        assert_eq!(
            cfg["redeem_token_url"],
            serde_json::json!(format!("{base}/oauth2/token"))
        );
    }

    /// A metadata document claiming a different resource is refused.
    #[tokio::test]
    async fn mismatched_resource_is_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let rm = || async {
            Json(serde_json::json!({
                "resource": "https://evil.example/mcp",
                "authorization_servers": ["https://evil.example"],
            }))
        };
        let app = axum::Router::new().route("/.well-known/oauth-protected-resource/mcp", get(rm));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let policy = DiscoveryPolicy {
            allow_private: true,
            allow_insecure_http: true,
        };
        let err = discover_oauth(&format!("{base}/mcp"), policy)
            .await
            .unwrap_err();
        assert!(err.contains("does not match"), "got: {err}");
    }

    /// Private addresses are refused without the opt-in.
    #[tokio::test]
    async fn private_address_refused_without_opt_in() {
        let policy = DiscoveryPolicy {
            allow_private: false,
            allow_insecure_http: true,
        };
        let err = discover_oauth("http://127.0.0.1:9/mcp", policy)
            .await
            .unwrap_err();
        assert!(err.contains("private"), "got: {err}");
    }

    /// http scheme is refused under the production policy.
    #[tokio::test]
    async fn insecure_http_refused_by_default() {
        let policy = DiscoveryPolicy {
            allow_private: true,
            allow_insecure_http: false,
        };
        let err = discover_oauth("http://127.0.0.1:9/mcp", policy)
            .await
            .unwrap_err();
        assert!(err.contains("scheme"), "got: {err}");
    }
}
