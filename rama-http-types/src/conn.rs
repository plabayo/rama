//! HTTP connection utilities.

use crate::dep::http::Version;
use crate::proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture};

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Context`] of a (h1) request
/// to customise the connection of the h1 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
pub struct Http1ClientContextParams {
    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Default is false.
    pub title_header_case: bool,
}

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Context`] of a (h2) request
/// to customise the connection of the h2 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
pub struct H2ClientContextParams {
    /// Pseudo order of the headers stream
    pub headers_pseudo_order: Option<PseudoHeaderOrder>,

    /// Early frames to be applied first
    pub early_frames: Option<EarlyFrameCapture>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Extension that when set will enforce this specific http version
pub struct EnforcedHttpVersion(pub Version);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
/// Original request version before it was changed
///
/// Changing of version happens because of things like tls alpn
pub struct OriginalHttpVersion(pub Version);
