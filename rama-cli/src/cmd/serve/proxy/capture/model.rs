use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net))]
pub(in crate::cmd::serve::proxy) struct ConnectionId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(proxy))]
pub(in crate::cmd::serve::proxy) struct IngressProtocol(pub &'static str);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(http))]
pub(in crate::cmd::serve::proxy) struct ExchangeId(pub u64);

#[derive(Debug, Clone, Serialize)]
pub(in crate::cmd::serve::proxy) struct ConnectionSummary {
    pub id: u64,
    pub display_id: u64,
    pub label: Option<String>,
    pub started_at: jiff::Timestamp,
    pub local_address: String,
    pub peer_address: String,
    pub ingress_protocol: String,
    pub active: bool,
    pub ended_at: Option<jiff::Timestamp>,
    pub request_count: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::cmd::serve::proxy) struct ExchangeSummary {
    pub decision: Option<String>,
    pub id: u64,
    pub connection_id: u64,
    pub connection_display_id: u64,
    pub started_at: jiff::Timestamp,
    pub method: String,
    pub http_version: String,
    pub url: String,
    pub endpoint: String,
    pub protocol: String,
    pub ingress_local_address: Option<String>,
    pub ingress_peer_address: Option<String>,
    pub user_agent: Option<String>,
    pub user_agent_kind: Option<String>,
    pub status: Option<u16>,
    pub active: bool,
    pub response_started_at: Option<jiff::Timestamp>,
    pub completed_at: Option<jiff::Timestamp>,
    pub egress_local_address: Option<String>,
    pub egress_peer_address: Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_truncated: bool,
    pub response_truncated: bool,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub peetprint: Option<String>,
    pub ja4h: Option<String>,
    pub akamai_h2: Option<String>,
    pub known_fingerprint: Option<String>,
    pub has_emulation_profile: bool,
}

#[derive(Debug, Clone, Default)]
pub(in crate::cmd::serve::proxy) struct CaptureFilter {
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
                summary.user_agent.as_deref().unwrap_or_default(),
                &self.user_agent,
            )
            && contains_folded(&summary.endpoint, &self.endpoint)
            && (self.method.is_empty() || summary.method.eq_ignore_ascii_case(&self.method))
            && matches_status(summary, &self.status)
            && matches_protocol(&summary.protocol, &self.protocol)
    }

    pub(super) fn search_matches_summary(&self, summary: &ExchangeSummary) -> bool {
        if self.search.is_empty() {
            return true;
        }
        contains_folded(
            &format!(
                "{} {} {} {} {} {} {} {}",
                summary.connection_display_id,
                summary.method,
                summary.http_version,
                summary.url,
                summary.endpoint,
                summary.protocol,
                summary
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_default(),
                summary.user_agent.as_deref().unwrap_or_default()
            ),
            &self.search,
        )
    }

    pub(super) fn is_empty(&self) -> bool {
        self.search.is_empty()
            && self.connection_id.is_empty()
            && self.user_agent.is_empty()
            && self.endpoint.is_empty()
            && self.method.is_empty()
            && self.status.is_empty()
            && self.protocol.is_empty()
    }
}

pub(super) fn matches_connection_id(connection_id: u64, filter: &str) -> bool {
    let filter = filter.trim().trim_start_matches('#');
    filter.is_empty() || filter.parse::<u64>() == Ok(connection_id)
}

pub(super) fn matches_status(summary: &ExchangeSummary, filter: &str) -> bool {
    match filter {
        "" => true,
        "pending" => summary.active || summary.status.is_none(),
        "2xx" => summary
            .status
            .is_some_and(|status| (200..300).contains(&status)),
        "3xx" => summary
            .status
            .is_some_and(|status| (300..400).contains(&status)),
        "4xx" => summary
            .status
            .is_some_and(|status| (400..500).contains(&status)),
        "5xx" => summary
            .status
            .is_some_and(|status| (500..600).contains(&status)),
        status => summary
            .status
            .is_some_and(|actual| actual.to_string() == status),
    }
}

pub(super) fn matches_protocol(protocol: &str, filter: &str) -> bool {
    let protocol = protocol.to_ascii_lowercase();
    match filter {
        "" => true,
        "http" | "https" | "ws" | "wss" => protocol == filter,
        "other" => !matches!(protocol.as_str(), "http" | "https" | "ws" | "wss"),
        other => protocol.eq_ignore_ascii_case(other),
    }
}

pub(super) fn contains_folded(haystack: &str, needle: &str) -> bool {
    needle.is_empty() || haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::cmd::serve::proxy) struct CapturedTlsParameters {
    pub protocol_version: rama::tls::ProtocolVersion,
    pub application_layer_protocol: Option<rama::net::tls::ApplicationProtocol>,
    pub peer_certificate_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::cmd::serve::proxy) struct CaptureSnapshot {
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
pub(in crate::cmd::serve::proxy) enum StoredRecord {
    Interception {
        direction: String,
        outcome: String,
        original_headers: Vec<(String, String)>,
        original_status: Option<u16>,
        original_payload: Option<String>,
        forwarded_headers: Option<Vec<(String, String)>>,
    },
    RequestHead {
        method: String,
        url: String,
        version: String,
        headers: Vec<(String, String)>,
        emulation_profile: Option<Value>,
        tls_client_hello: Option<ClientHello>,
        ingress_tls: Option<CapturedTlsParameters>,
    },
    RequestBody {
        data: String,
    },
    RequestTrailers {
        headers: Vec<(String, String)>,
    },
    RequestEnd {
        outcome: String,
    },
    ResponseHead {
        status: u16,
        version: String,
        headers: Vec<(String, String)>,
        egress_tls: Option<CapturedTlsParameters>,
    },
    ResponseBody {
        data: String,
    },
    ResponseTrailers {
        headers: Vec<(String, String)>,
    },
    ResponseEnd {
        outcome: String,
    },
    WebSocketMessage {
        at: String,
        direction: String,
        kind: String,
        data: String,
        close_code: Option<u16>,
        #[serde(default)]
        replayed: bool,
        #[serde(default)]
        injected: bool,
    },
    ReplayResult {
        status: Option<u16>,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::cmd::serve::proxy) struct CaptureDetails {
    pub summary: ExchangeSummary,
    pub records: Vec<StoredRecord>,
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct InspectorDetails {
    pub summary: ExchangeSummary,
    pub records: Vec<StoredRecord>,
    pub websocket_page: usize,
    pub websocket_total: usize,
    pub websocket_replay_active: bool,
}

#[derive(Debug)]
pub(in crate::cmd::serve::proxy) enum WebSocketReplayError {
    CaptureNotFound,
    MessageNotFound,
    ControlFrame,
    Truncated,
    ConnectionClosed,
    SendFailed(String),
    InvalidCapture(BoxError),
    InvalidMessage(String),
}

impl fmt::Display for WebSocketReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureNotFound => f.write_str("capture not found"),
            Self::MessageNotFound => f.write_str("WebSocket message not found"),
            Self::ControlFrame => f.write_str("WebSocket control frames cannot be replayed"),
            Self::Truncated => f.write_str("truncated WebSocket data cannot be replayed safely"),
            Self::ConnectionClosed => f.write_str("the original WebSocket connection is closed"),
            Self::SendFailed(error) => write!(f, "failed to send WebSocket message: {error}"),
            Self::InvalidCapture(error) => write!(f, "read captured WebSocket message: {error}"),
            Self::InvalidMessage(error) => write!(f, "invalid WebSocket message: {error}"),
        }
    }
}

impl std::error::Error for WebSocketReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCapture(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::cmd::serve::proxy) enum CapturedBody {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub(in crate::cmd::serve::proxy) struct ReplayRequest {
    pub method: String,
    pub url: String,
    pub version: String,
    pub protocol: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub tls_client_hello: Option<ClientHello>,
}
