//! Raw-frame observation seam.
//!
//! A [`FrameTap`] installed on a connection sees every byte the client
//! sends and receives, per channel, before any decoding — the
//! inspector's wire view hangs off this. The gateway installs no tap
//! and pays nothing.

use std::sync::Arc;

/// Which way a frame travelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameDirection {
    Sent,
    Received,
}

/// The channel a frame was observed on. `HttpResponse` is a buffered
/// body (plain JSON, or the full text of a per-request SSE stream);
/// `HttpSse` is one raw SSE event block — including its `event:` /
/// `id:` field lines — from a live stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameChannel {
    HttpRequest,
    HttpResponse,
    HttpSse,
    Stdio,
    StdioStderr,
}

impl FrameDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }
}

impl FrameChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HttpRequest => "http-request",
            Self::HttpResponse => "http-response",
            Self::HttpSse => "http-sse",
            Self::Stdio => "stdio",
            Self::StdioStderr => "stdio-stderr",
        }
    }
}

/// Observer for raw frames. Implementations must be cheap and
/// non-blocking — they run inline on the request path. Timestamps are
/// the implementor's concern.
pub trait FrameTap: Send + Sync {
    fn on_frame(&self, direction: FrameDirection, channel: FrameChannel, bytes: &[u8]);
}

pub type SharedTap = Arc<dyn FrameTap>;

/// Feed a frame to an optional tap without cluttering call sites.
pub(crate) fn tap_frame(
    tap: &Option<SharedTap>,
    direction: FrameDirection,
    channel: FrameChannel,
    bytes: &[u8],
) {
    if let Some(tap) = tap {
        tap.on_frame(direction, channel, bytes);
    }
}
