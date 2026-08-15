//! Per-request signing hook.
//!
//! Some upstream authorization schemes cannot be expressed as a static header
//! map: the credential is a signature over *this* request's method, authority,
//! path and body, so it has to be computed at send time. RFC 9421 HTTP Message
//! Signatures — and AAuth, which profiles them — work that way.
//!
//! The trait is deliberately dependency-free: it names no crypto and no
//! scheme. `mcp-client` never links a signer implementation; callers construct
//! one and hand it over in [`crate::UpstreamOptions::signer`].

use std::sync::Arc;

/// The parts of an outbound HTTP request a signer may cover.
///
/// `headers` are the headers already decided for this request, lowercase-named.
/// A signer that covers a header MUST use the value it finds here — those are
/// the bytes that go on the wire.
pub struct SigningRequest<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    /// Request body, or `None` for bodyless methods (GET, DELETE).
    pub body: Option<&'a [u8]>,
}

impl SigningRequest<'_> {
    /// Case-insensitive lookup over [`Self::headers`].
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Computes request-scoped authorization headers.
///
/// Returns the headers to add. A signer that needs a header it also covers
/// (e.g. `Content-Digest`) returns it here — the caller applies every returned
/// header verbatim, so what is signed is what is sent.
pub trait RequestSigner: Send + Sync + std::fmt::Debug {
    fn sign(&self, req: &SigningRequest<'_>) -> Result<Vec<(String, String)>, String>;
}

pub type SharedSigner = Arc<dyn RequestSigner>;
