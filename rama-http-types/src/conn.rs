//! HTTP connection utilities.

use std::sync::Arc;
use std::time::Duration;

use crate::Version;
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

    /// Whether to use an adaptive flow control.
    pub adaptive_window: Option<bool>,
}

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Extension)]
#[extension(tags(http))]
/// Target http version
///
/// This can be set manually to enforce a specific version,
/// otherwise this will be set automatically by things such
/// tls alpn
pub struct TargetHttpVersion(pub Version);

#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
/// Optional parameters that can be set in the [`Extensions`] of an h2
/// server IO to override the connection's initial SETTINGS frame on a
/// per-connection basis.
///
/// Mirrors the per-connection knobs of the h2 server builder; any field
/// left `None` retains the server's configured default. Used primarily
/// by transparent proxies / MITM relays that need to mirror upstream h2
/// settings onto a sibling ingress connection.
///
/// Where the underlying builder field is itself `Option<T>` (e.g.
/// `max_concurrent_streams`, `header_table_size`), `Some(value)` here
/// overrides to `Some(value)` on the builder. This extension cannot
/// express "explicitly unset" / "no limit" — that's intentional, since
/// the mirroring use case always produces concrete values; configure
/// the server builder directly if you need that.
///
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
/// The initial h2 [`Settings`] frame received from the peer.
///
/// Set as an extension on every h2 response by the client, so
/// downstream consumers (e.g. an MITM relay mirroring upstream
/// SETTINGS onto its ingress connection) can observe the peer's
/// advertised parameters without poking at connection internals.
///
/// This captures the *first* non-ACK `SETTINGS` frame received
/// from the peer during the connection's lifetime; subsequent
/// updates are not reflected here. The settings frame is wrapped
/// in `Arc` so per-response insertion costs only a single atomic
/// bump rather than a struct copy.
pub struct PeerH2Settings(pub Arc<Settings>);
