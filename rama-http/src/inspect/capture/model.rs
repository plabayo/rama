use super::CaptureMetadata;
use crate::{
    CaptureOutcome, HeaderMap, HeaderValue, Method, StatusCode, Version,
    fingerprint::{AkamaiH2, Ja4H},
};
use rama_core::{bytes::Bytes, extensions::Extension};
use rama_net::{
    Protocol,
    address::{Authority, SocketAddress},
    uri::Uri,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension, Serialize, Deserialize)]
#[extension(tags(net))]
pub struct ConnectionId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(proxy))]
pub struct IngressProtocol(pub Protocol);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension, Serialize, Deserialize)]
#[extension(tags(http))]
pub struct ExchangeId(pub u64);

/// A downstream connection and its connection-scoped observations.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSummary {
    pub id: u64,
    pub display_id: u64,
    pub label: Option<String>,
    pub started_at: jiff::Timestamp,
    pub local_address: Option<SocketAddress>,
    pub peer_address: Option<SocketAddress>,
    pub ingress_protocol: Protocol,
    pub active: bool,
    pub ended_at: Option<jiff::Timestamp>,
    pub request_count: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub akamai_h2: Option<AkamaiH2>,
    #[serde(skip)]
    pub metadata: rama_inspect::Observations,
}

/// HTTP exchange data. Connection observations are obtained through `connection_id`.
#[derive(Debug, Clone, Serialize)]
pub struct ExchangeSummary {
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
    pub ja4h: Option<Ja4H>,
    #[serde(skip)]
    pub metadata: CaptureMetadata,
}

/// User-entered filter expressions; these are queries rather than captured values.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct CaptureFilter {
    pub search: String,
    pub connection_id: String,
    pub user_agent: String,
    pub endpoint: String,
    pub method: String,
    pub status: String,
    pub protocol: String,
}
impl CaptureFilter {
    pub(super) fn matches_dimensions(&self, summary: &ExchangeSummary) -> bool {
        matches_connection_id(summary.connection_display_id, &self.connection_id)
            && contains_folded(
                summary
                    .user_agent
                    .as_ref()
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default(),
                &self.user_agent,
            )
            && (self.endpoint.is_empty()
                || summary
                    .endpoint
                    .as_ref()
                    .is_some_and(|v| super::search::matches_display(v, &self.endpoint)))
            && (self.method.is_empty()
                || summary.method.as_str().eq_ignore_ascii_case(&self.method))
            && matches_status(summary, &self.status)
            && matches_protocol(summary.protocol.as_str(), &self.protocol)
    }
    pub fn search_matches_summary(&self, summary: &ExchangeSummary) -> bool {
        self.search.is_empty()
            || super::search::matches_display(
                &format_args!(
                    "{} {} {} {} {} {} {}",
                    summary.connection_display_id,
                    summary.method,
                    summary.http_version,
                    summary.url,
                    summary.protocol,
                    summary.status.map(|s| s.as_u16()).unwrap_or_default(),
                    summary
                        .user_agent
                        .as_ref()
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or_default()
                ),
                &self.search,
            )
            || summary
                .endpoint
                .as_ref()
                .is_some_and(|value| super::search::matches_display(value, &self.search))
    }
    pub fn is_empty(&self) -> bool {
        self.search.is_empty()
            && self.connection_id.is_empty()
            && self.user_agent.is_empty()
            && self.endpoint.is_empty()
            && self.method.is_empty()
            && self.status.is_empty()
            && self.protocol.is_empty()
    }
}
pub(super) fn matches_connection_id(id: u64, filter: &str) -> bool {
    let filter = filter.trim().trim_start_matches('#');
    filter.is_empty() || filter.parse::<u64>() == Ok(id)
}
pub(super) fn matches_status(summary: &ExchangeSummary, filter: &str) -> bool {
    match filter {
        "" => true,
        "pending" => summary.active || summary.status.is_none(),
        "2xx" => summary.status.is_some_and(|status| status.is_success()),
        "3xx" => summary.status.is_some_and(|status| status.is_redirection()),
        "4xx" => summary
            .status
            .is_some_and(|status| status.is_client_error()),
        "5xx" => summary
            .status
            .is_some_and(|status| status.is_server_error()),
        status => status
            .parse::<u16>()
            .ok()
            .is_some_and(|value| summary.status.is_some_and(|s| s.as_u16() == value)),
    }
}
pub(super) fn matches_protocol(protocol: &str, filter: &str) -> bool {
    filter.is_empty()
        || match filter {
            "other" => !["http", "https", "ws", "wss"]
                .iter()
                .any(|value| protocol.eq_ignore_ascii_case(value)),
            value => protocol.eq_ignore_ascii_case(value),
        }
}
pub(super) fn contains_folded(haystack: &str, needle: &str) -> bool {
    super::search::matches_display(&haystack, needle)
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptureSnapshot {
    pub connections: Vec<ConnectionSummary>,
    pub connection_offset: usize,
    pub next_connection_cursor: Option<u64>,
    pub exchanges: Vec<ExchangeSummary>,
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
        direction: String,
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
    pub summary: ExchangeSummary,
    pub records: Vec<StoredRecord>,
    pub connection: Option<ConnectionSummary>,
    #[serde(skip)]
    pub metadata: CaptureMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedBody {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub struct ReplayRequest {
    pub method: Method,
    pub url: Uri,
    pub version: Version,
    pub protocol: Protocol,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub metadata: CaptureMetadata,
}
