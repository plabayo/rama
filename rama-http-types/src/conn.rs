//! HTTP connection utilities.

use std::time::Duration;

use crate::Version;
use crate::proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture};

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Extensions`] of a (h1) request
/// to customise the connection of the h1 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct Http1ClientContextParams {
    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Default is `false`.
    pub title_header_case: bool,
}

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Extensions`] of a (h2) request
/// to customise the connection of the h2 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
///
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct H2ClientContextParams {
    /// Pseudo order of the headers stream
    pub headers_pseudo_order: Option<PseudoHeaderOrder>,

    /// Early frames to be applied first
    pub early_frames: Option<EarlyFrameCapture>,

    /// The `SETTINGS_INITIAL_WINDOW_SIZE` option for HTTP2
    /// stream-level flow control.
    pub init_stream_window_size: Option<u32>,

    /// The max connection-level flow control for HTTP2.
    pub init_connection_window_size: Option<u32>,

    /// An interval for HTTP2 Ping frames should be sent to keep a
    /// connection alive.
    pub keep_alive_interval: Option<Duration>,

    /// A timeout for receiving an acknowledgement of the keep-alive ping.
    pub keep_alive_timeout: Option<Duration>,

    /// Whether HTTP2 keep-alive should apply while the connection is idle.
    pub keep_alive_while_idle: Option<bool>,

    /// The max size of received header frames.
    pub max_header_list_size: Option<u32>,

    /// Whether to use an adaptive flow control.
    pub adaptive_window: Option<bool>,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
/// Target http version
///
/// This can be set manually to enforce a specific version,
/// otherwise this will be set automatically by things such
/// tls alpn
pub struct TargetHttpVersion(pub Version);
