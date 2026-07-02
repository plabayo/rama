//! HTTP connection utilities.

use std::time::Duration;

use crate::proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture, frame::Settings};
use rama_core::extensions::Extension;

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
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

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
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

    /// The `SETTINGS_MAX_FRAME_SIZE` option for HTTP2.
    pub max_frame_size: Option<u32>,

    /// The `SETTINGS_MAX_CONCURRENT_STREAMS` option for HTTP2,
    /// limiting the number of concurrent streams the remote peer
    /// may initiate.
    pub max_concurrent_streams: Option<u32>,

    /// Whether to use an adaptive flow control.
    pub adaptive_window: Option<bool>,

    /// The initial maximum of locally initiated (send) streams.
    ///
    /// This value is overwritten by the value included in the initial
    /// `SETTINGS` frame received from the peer.
    pub initial_max_send_streams: Option<usize>,

    /// The maximum write buffer size for each HTTP2 stream.
    pub max_send_buf_size: Option<u32>,

    /// The maximum number of HTTP2 concurrent locally reset streams.
    pub max_concurrent_reset_streams: Option<usize>,

    /// The maximum number of pending reset streams allowed before a
    /// `GOAWAY` will be sent.
    pub max_pending_accept_reset_streams: Option<usize>,

    /// The maximum number of local resets due to protocol errors made
    /// by the remote peer.
    pub max_local_error_reset_streams: Option<usize>,

    /// The duration to remember locally reset streams.
    pub reset_stream_duration: Option<Duration>,
}

pub use rama_net::http::TargetHttpVersion;

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
/// Per-conn override for the h2 server's initial SETTINGS frame, set on
/// the IO's [`Extensions`]. Any field left `None` retains the builder
/// default. `Some(value)` overrides one-to-one; this type can't express
/// "explicitly unset" — set the builder directly if you need that.
///
/// Used primarily by MITM relays. Note: [`HttpMitmRelay`][] only
/// auto-populates `enable_connect_protocol` and `max_concurrent_streams`;
/// other fields are independent per-direction budgets and remain
/// available as direct per-conn overrides for callers who want them.
///
/// [`HttpMitmRelay`]: https://docs.rs/rama-http-backend/latest/rama_http_backend/proxy/mitm/struct.HttpMitmRelay.html
/// [`Extensions`]: rama_core::extensions::Extensions
pub struct H2ServerContextParams {
    /// Whether to advertise the [extended CONNECT protocol][1] in the
    /// initial SETTINGS frame.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
    pub enable_connect_protocol: Option<bool>,

    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    pub max_concurrent_streams: Option<u32>,

    /// `SETTINGS_HEADER_TABLE_SIZE`.
    pub header_table_size: Option<u32>,

    /// `SETTINGS_MAX_FRAME_SIZE`.
    pub max_frame_size: Option<u32>,

    /// `SETTINGS_MAX_HEADER_LIST_SIZE`.
    pub max_header_list_size: Option<u32>,

    /// `SETTINGS_INITIAL_WINDOW_SIZE` (stream-level flow control).
    pub initial_stream_window_size: Option<u32>,

    /// Connection-level flow-control window.
    pub initial_connection_window_size: Option<u32>,

    /// Whether to use adaptive flow control. If `Some(true)`, the
    /// stream/connection window-size overrides above are reset to the
    /// spec default before adaptive control takes over.
    pub adaptive_window: Option<bool>,
}

#[derive(Debug, Clone, Extension)]
#[extension(tags(http))]
/// The peer's initial (first non-ACK) h2 [`Settings`] frame, set as an
/// extension on every h2 client response. Captured once per connection;
/// subsequent SETTINGS updates are not reflected. Stored once in
/// `Arc<PeerH2Settings>` and shared per-response via
/// [`rama_core::extensions::Extensions::insert_arc`].
pub struct PeerH2Settings(pub Settings);
