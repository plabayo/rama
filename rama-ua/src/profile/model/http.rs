//! HTTP settings recorded by the legacy profile input schema.

use rama_http::proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// The settings for the HTTP/1.1 profile.
pub struct Http1Settings {
    /// Whether to enforce title case the headers.
    pub title_case_headers: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
/// The settings for the HTTP/2 profile.
pub struct Http2Settings {
    /// The pseudo headers to be used for the HTTP/2 profile.
    ///
    /// See [`PseudoHeader`] for more details.
    ///
    /// [`PseudoHeader`]: rama_http::proto::h2::PseudoHeader
    pub http_pseudo_headers: Option<PseudoHeaderOrder>,

    /// Frames to be sent at the start of a stream.
    pub early_frames: Option<EarlyFrameCapture>,
}
