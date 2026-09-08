use super::CaptureMetadata;
use crate::{
    CaptureOutcome, HeaderMap, HeaderValue, Method, StatusCode, Version,
    fingerprint::{AkamaiH2, Ja4H},
};
use rama_core::{bytes::Bytes, extensions::Extension};
use rama_net::{Protocol, address::Authority, uri::Uri};
use serde::{Deserialize, Serialize};

/// Correlates an HTTP exchange with its upgraded protocol adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension, Serialize, Deserialize)]
#[extension(tags(http))]
pub struct HttpExchangeId(pub u64);

/// HTTP observations on a transport connection.
#[derive(Debug, Clone, Serialize)]
pub struct HttpConnectionSummary {
    #[serde(flatten)]
    pub transport: rama_net::inspect::ConnectionSummary,
    pub request_count: usize,
    pub akamai_h2: Option<AkamaiH2>,
}
impl std::ops::Deref for HttpConnectionSummary {
    type Target = rama_net::inspect::ConnectionSummary;
    fn deref(&self) -> &Self::Target {
        &self.transport
    }
}
impl std::ops::DerefMut for HttpConnectionSummary {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.transport
    }
}

/// HTTP exchange data. Connection observations are obtained through `connection_id`.
#[derive(Debug, Clone, Serialize)]
pub struct HttpExchangeSummary {
    pub decision: Option<String>,
    pub id: u64,
    pub connection_id: u64,
    pub connection_display_id: u64,
    pub started_at: jiff::Timestamp,
    pub method: Method,
    pub http_version: Version,
    pub url: Uri,
    pub endpoint: Option<Authority>,
    pub protocol: Protocol,
    pub user_agent: Option<HeaderValue>,
    pub status: Option<StatusCode>,
    pub active: bool,
    pub response_started_at: Option<jiff::Timestamp>,
    pub completed_at: Option<jiff::Timestamp>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_truncated: bool,
    pub response_truncated: bool,
    pub ja4h: Option<std::sync::Arc<Ja4H>>,
    #[serde(skip)]
    pub metadata: CaptureMetadata,
}

pub(super) fn contains_folded(haystack: &str, needle: &str) -> bool {
    super::search::matches_display(&haystack, needle)
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureSnapshot {
    pub connections: Vec<HttpConnectionSummary>,
    pub connection_offset: usize,
    pub next_connection_cursor: Option<u64>,
    pub exchanges: Vec<HttpExchangeSummary>,
    pub total_connections: usize,
    pub active_connections: usize,
    pub total_requests: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StoredRecord {
    Interception {
        direction: crate::inspect::control::HttpMessageDirection,
        outcome: String,
        original_headers: HeaderMap,
        original_status: Option<StatusCode>,
        original_payload: Option<crate::inspect::control::Payload>,
        forwarded_headers: Option<HeaderMap>,
    },
    RequestHead {
        method: Method,
        url: Uri,
        version: Version,
        headers: HeaderMap,
    },
    RequestBody {
        #[serde(with = "rama_utils::bytes::serde_base64")]
        data: Bytes,
    },
    RequestTrailers {
        headers: HeaderMap,
    },
    RequestEnd {
        outcome: CaptureOutcome,
    },
    ResponseHead {
        status: StatusCode,
        version: Version,
        headers: HeaderMap,
    },
    ResponseBody {
        #[serde(with = "rama_utils::bytes::serde_base64")]
        data: Bytes,
    },
    ResponseTrailers {
        headers: HeaderMap,
    },
    ResponseEnd {
        outcome: CaptureOutcome,
    },
    ReplayResult {
        status: Option<StatusCode>,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureDetails {
    pub summary: HttpExchangeSummary,
    pub records: Vec<StoredRecord>,
    pub connection: Option<HttpConnectionSummary>,
    #[serde(skip)]
    pub metadata: CaptureMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedBody {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub struct ReplayRequest<B = super::CapturedBodySource> {
    pub method: Method,
    pub url: Uri,
    pub version: Version,
    pub protocol: Protocol,
    pub headers: HeaderMap,
    pub body: B,
    pub metadata: CaptureMetadata,
}
