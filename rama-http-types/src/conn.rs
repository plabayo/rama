//! HTTP connection utilities.

use crate::Version;
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
    /// Default is `false`.
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

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
/// Target http version
///
/// This can be set manually to enforce a specific version,
/// otherwise this will be set automatically by things such
/// tls alpn
pub struct TargetHttpVersion(pub Version);
