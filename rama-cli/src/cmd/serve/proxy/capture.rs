use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use parking_lot::RwLock;
use rama::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    extensions::Extension,
    futures::{Stream, async_stream::stream_fn},
    http::{
        Body, BodyCaptureEvent, BodyCaptureSink, CaptureBody, CaptureOutcome, HeaderMap, Request,
        Response, StreamingBody,
        body::util::BodyExt as _,
        ws::handshake::mitm::{
            WebSocketRelayDirection, WebSocketRelayInjector, WebSocketRelayMessage,
        },
    },
    net::stream::SocketInfo,
    tls::{
        SecureTransport,
        boring::core::{rand::rand_bytes, symm},
        fingerprint::{Ja3, Ja4, PeetPrint},
    },
    ua::{UserAgent, profile::UserAgentDatabase},
    utils::fs::{TempDir, TempPath, TempPathCleanup},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Mutex, watch},
};

const FILE_MAGIC: &[u8; 8] = b"RMCAP\0\x01\0";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net))]
pub(super) struct ConnectionId(pub u64);

#[derive(Debug, Clone, PartialEq, Eq, Extension)]
#[extension(tags(proxy))]
pub(super) struct IngressProtocol(pub &'static str);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(http))]
pub(super) struct ExchangeId(pub u64);

#[derive(Debug, Clone, Serialize)]
pub(super) struct ConnectionSummary {
    pub id: u64,
    pub started_at: String,
    pub local_address: String,
    pub peer_address: String,
    pub ingress_protocol: String,
    pub active: bool,
    pub request_count: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ExchangeSummary {
    pub id: u64,
    pub connection_id: u64,
    pub started_at: String,
    pub method: String,
    pub url: String,
    pub endpoint: String,
    pub protocol: String,
    pub user_agent: Option<String>,
    pub user_agent_kind: Option<String>,
    pub status: Option<u16>,
    pub active: bool,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub request_truncated: bool,
    pub response_truncated: bool,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
    pub peetprint: Option<String>,
    pub has_emulation_profile: bool,
}

#[derive(Debug, Clone, Default)]
pub(super) struct CaptureFilter {
    pub search: String,
    pub connection_id: String,
    pub user_agent: String,
    pub endpoint: String,
    pub method: String,
    pub status: String,
    pub protocol: String,
}

impl CaptureFilter {
    fn matches_dimensions(&self, summary: &ExchangeSummary) -> bool {
        matches_connection_id(summary.connection_id, &self.connection_id)
            && contains_folded(
                summary.user_agent.as_deref().unwrap_or_default(),
                &self.user_agent,
            )
            && contains_folded(&summary.endpoint, &self.endpoint)
            && (self.method.is_empty() || summary.method.eq_ignore_ascii_case(&self.method))
            && matches_status(summary, &self.status)
            && matches_protocol(&summary.protocol, &self.protocol)
    }

    fn search_matches_summary(&self, summary: &ExchangeSummary) -> bool {
        if self.search.is_empty() {
            return true;
        }
        contains_folded(
            &format!(
                "{} {} {} {} {} {} {}",
                summary.connection_id,
                summary.method,
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

    fn is_empty(&self) -> bool {
        self.search.is_empty()
            && self.connection_id.is_empty()
            && self.user_agent.is_empty()
            && self.endpoint.is_empty()
            && self.method.is_empty()
            && self.status.is_empty()
            && self.protocol.is_empty()
    }
}

fn matches_connection_id(connection_id: u64, filter: &str) -> bool {
    let filter = filter.trim().trim_start_matches('#');
    filter.is_empty() || filter.parse::<u64>() == Ok(connection_id)
}

fn matches_status(summary: &ExchangeSummary, filter: &str) -> bool {
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

fn matches_protocol(protocol: &str, filter: &str) -> bool {
    let protocol = protocol.to_ascii_lowercase();
    match filter {
        "" => true,
        "http" | "https" | "ws" | "wss" => protocol == filter,
        "other" => !matches!(protocol.as_str(), "http" | "https" | "ws" | "wss"),
        other => protocol.eq_ignore_ascii_case(other),
    }
}

fn contains_folded(haystack: &str, needle: &str) -> bool {
    needle.is_empty() || haystack.to_lowercase().contains(&needle.to_lowercase())
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CaptureSnapshot {
    pub connections: Vec<ConnectionSummary>,
    pub exchanges: Vec<ExchangeSummary>,
    pub total_connections: usize,
    pub active_connections: usize,
    pub total_requests: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(super) enum StoredRecord {
    RequestHead {
        method: String,
        url: String,
        version: String,
        headers: Vec<(String, String)>,
        emulation_profile: Option<Value>,
        tls_client_hello: Option<Value>,
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
    },
    ReplayResult {
        status: Option<u16>,
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct CaptureDetails {
    pub summary: ExchangeSummary,
    pub records: Vec<StoredRecord>,
}

#[derive(Debug, Clone)]
pub(super) struct InspectorDetails {
    pub summary: ExchangeSummary,
    pub records: Vec<StoredRecord>,
    pub websocket_page: usize,
    pub websocket_total: usize,
    pub websocket_replay_active: bool,
}

#[derive(Debug)]
pub(super) enum WebSocketReplayError {
    CaptureNotFound,
    MessageNotFound,
    ControlFrame,
    Truncated,
    ConnectionClosed,
    SendFailed(String),
    InvalidCapture(BoxError),
}

impl fmt::Display for WebSocketReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CaptureNotFound => f.write_str("capture not found"),
            Self::MessageNotFound => f.write_str("WebSocket message not found"),
            Self::ControlFrame => f.write_str("WebSocket control frames cannot be replayed"),
            Self::Truncated => f.write_str("truncated WebSocket data cannot be replayed safely"),
            Self::ConnectionClosed => f.write_str("the original WebSocket connection is closed"),
            Self::SendFailed(error) => write!(f, "failed to replay WebSocket message: {error}"),
            Self::InvalidCapture(error) => write!(f, "read captured WebSocket message: {error}"),
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
pub(super) enum CapturedBody {
    Request,
    Response,
}

#[derive(Debug, Clone)]
pub(super) struct ReplayRequest {
    pub method: String,
    pub url: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub user_agent: Option<String>,
}

struct CapturedConnection {
    summary_template: ConnectionSummary,
    ingress_protocol: RwLock<String>,
    active: AtomicBool,
    request_count: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl CapturedConnection {
    fn snapshot(&self) -> ConnectionSummary {
        let mut summary = self.summary_template.clone();
        summary
            .ingress_protocol
            .clone_from(&self.ingress_protocol.read());
        summary.active = self.active.load(Ordering::Relaxed);
        summary.request_count = self.request_count.load(Ordering::Relaxed);
        summary.bytes_in = self.bytes_in.load(Ordering::Relaxed);
        summary.bytes_out = self.bytes_out.load(Ordering::Relaxed);
        summary
    }
}

struct CapturedExchange {
    summary_template: ExchangeSummary,
    connection: Option<Arc<CapturedConnection>>,
    status: AtomicU16,
    active: AtomicBool,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    request_truncated: AtomicBool,
    response_truncated: AtomicBool,
    websocket_injector: RwLock<Option<WebSocketRelayInjector>>,
    file: Mutex<File>,
    path: TempPath,
    request_stored: AtomicU64,
    response_stored: AtomicU64,
}

impl CapturedExchange {
    fn snapshot(&self) -> ExchangeSummary {
        let mut summary = self.summary_template.clone();
        let status = self.status.load(Ordering::Relaxed);
        summary.status = (status != 0).then_some(status);
        summary.active = self.active.load(Ordering::Relaxed);
        summary.request_bytes = self.request_bytes.load(Ordering::Relaxed);
        summary.response_bytes = self.response_bytes.load(Ordering::Relaxed);
        summary.request_truncated = self.request_truncated.load(Ordering::Relaxed);
        summary.response_truncated = self.response_truncated.load(Ordering::Relaxed);
        summary
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

struct CaptureRegistry<T> {
    entries: BTreeMap<u64, Arc<T>>,
    order: VecDeque<u64>,
}

impl<T> Default for CaptureRegistry<T> {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
        }
    }
}

struct CaptureStoreInner {
    key: [u8; 32],
    temp_cleanup: TempPathCleanup,
    next_connection_id: AtomicU64,
    next_exchange_id: AtomicU64,
    connections: RwLock<CaptureRegistry<CapturedConnection>>,
    exchanges: RwLock<CaptureRegistry<CapturedExchange>>,
    max_connections: usize,
    max_exchanges: usize,
    body_limit: u64,
    changes: watch::Sender<u64>,
    ua_db: Arc<UserAgentDatabase>,
    // Keep this last so exchange files and their cleanup guards drop before the
    // directory performs its synchronous best-effort shutdown cleanup.
    temp_dir: TempDir,
}

#[derive(Clone)]
pub(super) struct CaptureStore(Arc<CaptureStoreInner>);

impl fmt::Debug for CaptureStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureStore")
            .field("directory", &self.0.temp_dir.path())
            .field("max_connections", &self.0.max_connections)
            .field("max_exchanges", &self.0.max_exchanges)
            .field("body_limit", &self.0.body_limit)
            .finish_non_exhaustive()
    }
}

impl CaptureStore {
    pub(super) fn new(
        max_connections: usize,
        max_exchanges: usize,
        body_limit: u64,
        ua_db: Arc<UserAgentDatabase>,
    ) -> Result<Self, BoxError> {
        let temp_dir = TempDir::with_prefix("rama-proxy-mitm-")
            .context("create encrypted MITM capture directory")?;
        let mut key = [0_u8; 32];
        rand_bytes(&mut key).context("generate in-memory MITM capture key")?;
        let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
        tokio::spawn(temp_cleanup_worker.run());
        let (changes, _) = watch::channel(0);
        Ok(Self(Arc::new(CaptureStoreInner {
            key,
            temp_cleanup,
            next_connection_id: AtomicU64::new(1),
            next_exchange_id: AtomicU64::new(1),
            connections: RwLock::new(CaptureRegistry::default()),
            exchanges: RwLock::new(CaptureRegistry::default()),
            max_connections: max_connections.max(1),
            max_exchanges: max_exchanges.max(1),
            body_limit,
            changes,
            ua_db,
            temp_dir,
        })))
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }

    fn changed(&self) {
        self.0
            .changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    pub(super) fn begin_connection(&self, socket: Option<SocketInfo>, ingress: &str) -> u64 {
        let id = self.0.next_connection_id.fetch_add(1, Ordering::Relaxed);
        let (local_address, peer_address) = socket
            .map(|socket| {
                (
                    socket
                        .local_addr()
                        .map(|address| address.to_string())
                        .unwrap_or_else(|| "unknown".to_owned()),
                    socket.peer_addr().to_string(),
                )
            })
            .unwrap_or_else(|| ("unknown".to_owned(), "unknown".to_owned()));
        let connection = Arc::new(CapturedConnection {
            summary_template: ConnectionSummary {
                id,
                started_at: jiff::Timestamp::now().to_string(),
                local_address,
                peer_address,
                ingress_protocol: ingress.to_owned(),
                active: true,
                request_count: 0,
                bytes_in: 0,
                bytes_out: 0,
            },
            ingress_protocol: RwLock::new(ingress.to_owned()),
            active: AtomicBool::new(true),
            request_count: AtomicUsize::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        });
        {
            let mut connections = self.0.connections.write();
            connections.entries.insert(id, connection);
            connections.order.push_back(id);
        }
        self.trim_connections();
        self.changed();
        id
    }

    pub(super) fn set_connection_protocol(&self, id: u64, protocol: &str) {
        if let Some(connection) = self.0.connections.read().entries.get(&id).cloned() {
            *connection.ingress_protocol.write() = protocol.to_owned();
            self.changed();
        }
    }

    pub(super) fn finish_connection(&self, id: u64) {
        let mut connections = self.0.connections.write();
        let Some(connection) = connections.entries.get(&id) else {
            return;
        };
        let is_unused_http = connection.request_count.load(Ordering::Relaxed) == 0
            && connection.ingress_protocol.read().as_str() == "http";
        if is_unused_http {
            connections.entries.remove(&id);
            connections.order.retain(|candidate| *candidate != id);
        } else {
            connection.active.store(false, Ordering::Relaxed);
        }
        drop(connections);
        self.trim_connections();
        self.changed();
    }

    /// Forget a connection that has only served the inspector itself.
    ///
    /// A shared proxy/UI listener cannot distinguish the two at accept time.
    /// The first parsed origin-form dashboard request can, and is allowed to
    /// remove the provisional entry as long as no proxied exchange has been
    /// associated with it.
    pub(super) fn discard_connection_if_empty(&self, id: u64) -> bool {
        let removed = {
            let mut connections = self.0.connections.write();
            let is_empty = connections
                .entries
                .get(&id)
                .is_some_and(|entry| entry.request_count.load(Ordering::Relaxed) == 0);
            if !is_empty {
                false
            } else {
                connections.entries.remove(&id);
                if let Some(index) = connections
                    .order
                    .iter()
                    .position(|candidate| *candidate == id)
                {
                    connections.order.remove(index);
                }
                true
            }
        };
        if removed {
            self.changed();
        }
        removed
    }

    fn trim_connections(&self) {
        let mut connections = self.0.connections.write();
        loop {
            if connections.order.len() <= self.0.max_connections {
                break;
            }
            let remove = connections
                .order
                .iter()
                .copied()
                .enumerate()
                .find_map(|(index, id)| {
                    let active = match connections.entries.get(&id) {
                        Some(entry) => entry.active.load(Ordering::Relaxed),
                        None => false,
                    };
                    (!active).then_some((index, id))
                });
            let Some((index, id)) = remove else { break };
            connections.order.remove(index);
            connections.entries.remove(&id);
        }
    }

    async fn begin_exchange(&self, parts: &rama::http::request::Parts) -> Result<u64, BoxError> {
        let id = self.0.next_exchange_id.fetch_add(1, Ordering::Relaxed);
        let connection_id = parts
            .extensions
            .get_ref::<ConnectionId>()
            .map(|id| id.0)
            .unwrap_or_default();
        let connection = (connection_id != 0)
            .then(|| {
                self.0
                    .connections
                    .read()
                    .entries
                    .get(&connection_id)
                    .cloned()
            })
            .flatten();
        let secure = parts.extensions.get_ref::<SecureTransport>().is_some();
        let websocket = parts
            .headers
            .get("upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        let protocol = match (secure, websocket) {
            (true, true) => "wss",
            (true, false) => "https",
            (false, true) => "ws",
            (false, false) => "http",
        }
        .to_owned();
        let user_agent = parts
            .headers
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let parsed_ua = user_agent.as_deref().map(UserAgent::new);
        let user_agent_kind = parsed_ua.as_ref().and_then(UserAgent::info).map(|info| {
            info.version
                .map(|version| format!("{} {version}", info.kind))
                .unwrap_or_else(|| info.kind.to_string())
        });
        let profile = parsed_ua
            .as_ref()
            .and_then(|ua| self.0.ua_db.get(ua))
            .map(|profile| {
                json!({
                    "user_agent": profile.ua_str(),
                    "kind": profile.ua_kind.to_string(),
                    "version": profile.ua_version,
                    "platform": profile.platform.map(|platform| platform.to_string()),
                    "http": profile.http,
                    "tls": profile.tls,
                    "runtime": profile.runtime,
                })
            });
        let ja3 = Ja3::compute(&parts.extensions).ok().map(|fp| fp.hash());
        let ja4 = Ja4::compute(&parts.extensions)
            .ok()
            .map(|fp| fp.to_string());
        let peetprint = PeetPrint::compute(&parts.extensions)
            .ok()
            .map(|fp| fp.to_string());
        let endpoint = parts
            .uri
            .authority()
            .map(|authority| authority.to_string())
            .or_else(|| {
                parts
                    .headers
                    .get("host")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "unknown".to_owned());
        let path = self
            .0
            .temp_dir
            .path()
            .join(format!("exchange-{id}.capture"));
        let mut file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .await
            .context("create encrypted MITM exchange file")?;
        file.write_all(FILE_MAGIC)
            .await
            .context("write MITM capture magic")?;
        let path = TempPath::new(path, self.0.temp_cleanup.clone());
        let entry = Arc::new(CapturedExchange {
            summary_template: ExchangeSummary {
                id,
                connection_id,
                started_at: jiff::Timestamp::now().to_string(),
                method: parts.method.to_string(),
                url: parts.uri.to_string(),
                endpoint,
                protocol,
                user_agent,
                user_agent_kind,
                status: None,
                active: true,
                request_bytes: 0,
                response_bytes: 0,
                request_truncated: false,
                response_truncated: false,
                ja3,
                ja4,
                peetprint,
                has_emulation_profile: profile.is_some(),
            },
            connection,
            status: AtomicU16::new(0),
            active: AtomicBool::new(true),
            request_bytes: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            request_truncated: AtomicBool::new(false),
            response_truncated: AtomicBool::new(false),
            websocket_injector: RwLock::new(None),
            file: Mutex::new(file),
            path,
            request_stored: AtomicU64::new(0),
            response_stored: AtomicU64::new(0),
        });
        {
            let mut exchanges = self.0.exchanges.write();
            exchanges.entries.insert(id, entry.clone());
            exchanges.order.push_back(id);
        }
        if let Err(error) = self
            .append(
                id,
                &entry,
                &StoredRecord::RequestHead {
                    method: parts.method.to_string(),
                    url: parts.uri.to_string(),
                    version: format!("{:?}", parts.version),
                    headers: headers_to_vec(&parts.headers),
                    emulation_profile: profile,
                    tls_client_hello: parts
                        .extensions
                        .get_ref::<SecureTransport>()
                        .and_then(SecureTransport::client_hello)
                        .and_then(|hello| serde_json::to_value(hello).ok()),
                },
            )
            .await
        {
            let removed = {
                let mut exchanges = self.0.exchanges.write();
                exchanges.order.retain(|current| *current != id);
                exchanges.entries.remove(&id)
            };
            drop(removed);
            self.0.temp_cleanup.flush().await;
            return Err(error);
        }
        if let Some(connection) = &entry.connection {
            _ = connection.request_count.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_add(1)),
            );
        }
        self.trim_exchanges();
        self.changed();
        Ok(id)
    }

    fn trim_exchanges(&self) {
        let mut exchanges = self.0.exchanges.write();
        loop {
            if exchanges.order.len() <= self.0.max_exchanges {
                break;
            }
            let remove = exchanges
                .order
                .iter()
                .copied()
                .enumerate()
                .find_map(|(index, id)| {
                    let active = match exchanges.entries.get(&id) {
                        Some(entry) => entry.active.load(Ordering::Relaxed),
                        None => false,
                    };
                    (!active).then_some((index, id))
                });
            let Some((index, id)) = remove else { break };
            exchanges.order.remove(index);
            // Dropping the path queues deletion without stalling proxy traffic
            // on filesystem cleanup. TempDir remains the shutdown safety net.
            drop(exchanges.entries.remove(&id));
        }
    }

    async fn response_head(
        &self,
        id: u64,
        parts: &rama::http::response::Parts,
    ) -> Result<(), BoxError> {
        let entry = self.0.exchanges.read().entries.get(&id).cloned();
        if let Some(entry) = entry {
            entry.status.store(parts.status.as_u16(), Ordering::Relaxed);
            self.append(
                id,
                &entry,
                &StoredRecord::ResponseHead {
                    status: parts.status.as_u16(),
                    version: format!("{:?}", parts.version),
                    headers: headers_to_vec(&parts.headers),
                },
            )
            .await?;
            self.changed();
        }
        Ok(())
    }

    async fn append(
        &self,
        id: u64,
        entry: &CapturedExchange,
        record: &StoredRecord,
    ) -> Result<(), BoxError> {
        let plaintext = serde_json::to_vec(record).context("serialize MITM capture record")?;
        let mut nonce = [0_u8; NONCE_LEN];
        rand_bytes(&mut nonce).context("generate MITM capture nonce")?;
        let mut tag = [0_u8; TAG_LEN];
        let ciphertext = symm::encrypt_aead(
            symm::Cipher::aes_256_gcm(),
            &self.0.key,
            Some(&nonce),
            &id.to_be_bytes(),
            &plaintext,
            &mut tag,
        )
        .context("encrypt MITM capture record")?;
        let length = u32::try_from(ciphertext.len()).context("MITM record too large")?;
        let mut framed = Vec::with_capacity(4 + NONCE_LEN + TAG_LEN + ciphertext.len());
        framed.extend_from_slice(&length.to_be_bytes());
        framed.extend_from_slice(&nonce);
        framed.extend_from_slice(&tag);
        framed.extend_from_slice(&ciphertext);
        let mut file = entry.file.lock().await;
        file.write_all(&framed)
            .await
            .context("append encrypted MITM capture record")?;
        Ok(())
    }

    async fn body_event(&self, id: u64, direction: BodyDirection, event: BodyCaptureEvent) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        match event {
            BodyCaptureEvent::Frame(frame) => match frame.into_data() {
                Ok(data) => {
                    let len = data.len() as u64;
                    let stored = match direction {
                        BodyDirection::Request => entry
                            .request_stored
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                                Some(current.saturating_add(len).min(self.0.body_limit))
                            })
                            .unwrap_or_default(),
                        BodyDirection::Response => entry
                            .response_stored
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                                Some(current.saturating_add(len).min(self.0.body_limit))
                            })
                            .unwrap_or_default(),
                    };
                    let remaining = usize::try_from(self.0.body_limit.saturating_sub(stored))
                        .unwrap_or(usize::MAX);
                    let captured = &data[..data.len().min(remaining)];
                    if !captured.is_empty() {
                        let record = match direction {
                            BodyDirection::Request => StoredRecord::RequestBody {
                                data: BASE64.encode(captured),
                            },
                            BodyDirection::Response => StoredRecord::ResponseBody {
                                data: BASE64.encode(captured),
                            },
                        };
                        if let Err(error) = self.append(id, &entry, &record).await {
                            rama::telemetry::tracing::debug!(
                                "failed to append captured body data: {error}"
                            );
                        }
                    }
                    match direction {
                        BodyDirection::Request => {
                            saturating_add(&entry.request_bytes, len);
                            if captured.len() < data.len() {
                                entry.request_truncated.store(true, Ordering::Relaxed);
                            }
                        }
                        BodyDirection::Response => {
                            saturating_add(&entry.response_bytes, len);
                            if captured.len() < data.len() {
                                entry.response_truncated.store(true, Ordering::Relaxed);
                            }
                        }
                    }
                    if let Some(connection) = &entry.connection {
                        match direction {
                            BodyDirection::Request => saturating_add(&connection.bytes_in, len),
                            BodyDirection::Response => saturating_add(&connection.bytes_out, len),
                        }
                    }
                }
                Err(frame) => {
                    if let Ok(trailers) = frame.into_trailers() {
                        let record = match direction {
                            BodyDirection::Request => StoredRecord::RequestTrailers {
                                headers: headers_to_vec(&trailers),
                            },
                            BodyDirection::Response => StoredRecord::ResponseTrailers {
                                headers: headers_to_vec(&trailers),
                            },
                        };
                        if let Err(error) = self.append(id, &entry, &record).await {
                            rama::telemetry::tracing::debug!(
                                "failed to append captured body trailers: {error}"
                            );
                        }
                    }
                }
            },
            BodyCaptureEvent::End(outcome) => {
                let outcome = capture_outcome(outcome).to_owned();
                let record = match direction {
                    BodyDirection::Request => StoredRecord::RequestEnd { outcome },
                    BodyDirection::Response => StoredRecord::ResponseEnd { outcome },
                };
                if let Err(error) = self.append(id, &entry, &record).await {
                    rama::telemetry::tracing::debug!(
                        "failed to append captured body outcome: {error}"
                    );
                }
                if direction == BodyDirection::Response {
                    entry.active.store(false, Ordering::Relaxed);
                    self.trim_exchanges();
                }
            }
        }
        self.changed();
    }

    pub(super) async fn record_websocket_message(
        &self,
        id: u64,
        direction: String,
        kind: String,
        data: Vec<u8>,
        close_code: Option<u16>,
    ) {
        self.record_websocket_message_inner(id, direction, kind, data, close_code, false)
            .await;
    }

    async fn record_websocket_message_inner(
        &self,
        id: u64,
        direction: String,
        kind: String,
        mut data: Vec<u8>,
        close_code: Option<u16>,
        replayed: bool,
    ) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        let body_direction = if direction.eq_ignore_ascii_case("ingress") {
            BodyDirection::Request
        } else {
            BodyDirection::Response
        };
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let counter = match body_direction {
            BodyDirection::Request => &entry.request_stored,
            BodyDirection::Response => &entry.response_stored,
        };
        let stored = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(len).min(self.0.body_limit))
            })
            .unwrap_or_default();
        let remaining =
            usize::try_from(self.0.body_limit.saturating_sub(stored)).unwrap_or(usize::MAX);
        data.truncate(remaining);
        if let Err(error) = self
            .append(
                id,
                &entry,
                &StoredRecord::WebSocketMessage {
                    at: jiff::Timestamp::now().to_string(),
                    direction,
                    kind,
                    data: BASE64.encode(&data),
                    close_code,
                    replayed,
                },
            )
            .await
        {
            rama::telemetry::tracing::debug!(
                "failed to append captured WebSocket message: {error}"
            );
        }
        match body_direction {
            BodyDirection::Request => {
                saturating_add(&entry.request_bytes, len);
                if (data.len() as u64) < len {
                    entry.request_truncated.store(true, Ordering::Relaxed);
                }
            }
            BodyDirection::Response => {
                saturating_add(&entry.response_bytes, len);
                if (data.len() as u64) < len {
                    entry.response_truncated.store(true, Ordering::Relaxed);
                }
            }
        }
        if let Some(connection) = &entry.connection {
            match body_direction {
                BodyDirection::Request => saturating_add(&connection.bytes_in, len),
                BodyDirection::Response => saturating_add(&connection.bytes_out, len),
            }
        }
        self.changed();
    }

    pub(super) fn register_websocket_injector(&self, id: u64, injector: WebSocketRelayInjector) {
        if !injector.is_open() {
            return;
        }
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        let mut current = entry.websocket_injector.write();
        let replace = current.is_none();
        if replace {
            *current = Some(injector.clone());
        }
        drop(current);
        if replace {
            let store = self.clone();
            tokio::spawn(async move {
                injector.closed().await;
                store.changed();
            });
            self.changed();
        }
    }

    pub(super) async fn replay_websocket_message(
        &self,
        id: u64,
        message_index: usize,
    ) -> Result<(), WebSocketReplayError> {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return Err(WebSocketReplayError::CaptureNotFound);
        };
        let (mut reader, mut remaining, _) = self
            .snapshot_reader(&entry)
            .await
            .map_err(WebSocketReplayError::InvalidCapture)?;
        let mut current_index = 0_usize;
        let (direction, kind, encoded) = loop {
            let record = read_record(
                &mut reader,
                &mut remaining,
                &self.0.key,
                entry.summary_template.id,
            )
            .await
            .map_err(WebSocketReplayError::InvalidCapture)?;
            let Some(record) = record else {
                return Err(WebSocketReplayError::MessageNotFound);
            };
            let StoredRecord::WebSocketMessage {
                direction,
                kind,
                data,
                ..
            } = record
            else {
                continue;
            };
            if current_index == message_index {
                break (direction, kind, data);
            }
            current_index = current_index.saturating_add(1);
        };

        let direction = if direction.eq_ignore_ascii_case("ingress") {
            if entry.request_truncated.load(Ordering::Relaxed) {
                return Err(WebSocketReplayError::Truncated);
            }
            WebSocketRelayDirection::Ingress
        } else {
            if entry.response_truncated.load(Ordering::Relaxed) {
                return Err(WebSocketReplayError::Truncated);
            }
            WebSocketRelayDirection::Egress
        };
        let data = BASE64
            .decode(encoded)
            .context("decode captured WebSocket message")
            .map_err(WebSocketReplayError::InvalidCapture)?;
        let message = match kind.as_str() {
            "text" => WebSocketRelayMessage::Text(
                String::from_utf8(data.clone())
                    .context("decode captured WebSocket text")
                    .map_err(WebSocketReplayError::InvalidCapture)?
                    .into(),
            ),
            "binary" => WebSocketRelayMessage::Binary(Bytes::from(data.clone())),
            _ => return Err(WebSocketReplayError::ControlFrame),
        };
        let injector = entry
            .websocket_injector
            .read()
            .clone()
            .filter(WebSocketRelayInjector::is_open)
            .ok_or(WebSocketReplayError::ConnectionClosed)?;
        injector
            .send(direction, message)
            .await
            .map_err(|error| WebSocketReplayError::SendFailed(error.to_string()))?;
        self.record_websocket_message_inner(id, format!("{direction:?}"), kind, data, None, true)
            .await;
        Ok(())
    }

    pub(super) async fn record_replay_result(&self, id: u64, result: Result<u16, String>) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        let record = match result {
            Ok(status) => StoredRecord::ReplayResult {
                status: Some(status),
                error: None,
            },
            Err(error) => StoredRecord::ReplayResult {
                status: None,
                error: Some(error),
            },
        };
        if let Err(error) = self.append(id, &entry, &record).await {
            rama::telemetry::tracing::debug!("failed to append replay result: {error}");
        }
        self.changed();
    }

    #[cfg(test)]
    async fn snapshot(&self, filter: &CaptureFilter) -> CaptureSnapshot {
        self.snapshot_limited(filter, usize::MAX, usize::MAX).await
    }

    #[cfg(test)]
    async fn snapshot_limited(
        &self,
        filter: &CaptureFilter,
        connection_limit: usize,
        exchange_limit: usize,
    ) -> CaptureSnapshot {
        self.snapshot_limited_for_connections(
            filter,
            &BTreeSet::new(),
            connection_limit,
            exchange_limit,
        )
        .await
    }

    pub(super) async fn snapshot_limited_for_connections(
        &self,
        filter: &CaptureFilter,
        selected_connections: &BTreeSet<u64>,
        connection_limit: usize,
        exchange_limit: usize,
    ) -> CaptureSnapshot {
        let (exchange_summaries, total_requests, matching_connections) =
            if filter.is_empty() && selected_connections.is_empty() {
                let exchanges = self.0.exchanges.read();
                (
                    exchanges
                        .entries
                        .values()
                        .rev()
                        .take(exchange_limit)
                        .map(|entry| entry.snapshot())
                        .collect(),
                    exchanges.entries.len(),
                    None,
                )
            } else if filter.is_empty() {
                let exchanges = self.0.exchanges.read();
                let mut summaries = Vec::with_capacity(exchange_limit.min(exchanges.entries.len()));
                let mut total = 0;
                for exchange in exchanges.entries.values().rev() {
                    let summary = exchange.snapshot();
                    if !selected_connections.contains(&summary.connection_id) {
                        continue;
                    }
                    total += 1;
                    if summaries.len() < exchange_limit {
                        summaries.push(summary);
                    }
                }
                (summaries, total, None)
            } else {
                // Filtering captured payload can await disk reads. Clone only the
                // retained Arc handles here so no synchronous guard crosses await.
                let exchanges = self
                    .0
                    .exchanges
                    .read()
                    .entries
                    .values()
                    .rev()
                    .cloned()
                    .collect::<Vec<_>>();
                let mut summaries = Vec::with_capacity(exchange_limit.min(exchanges.len()));
                let mut matching_connections = std::collections::BTreeSet::new();
                let mut total = 0;
                for exchange in exchanges {
                    let summary = exchange.snapshot();
                    if !filter.matches_dimensions(&summary) {
                        continue;
                    }
                    if !filter.search_matches_summary(&summary) {
                        let Ok(records) = self.read_records(&exchange).await else {
                            continue;
                        };
                        if !records_match_search(&records, &filter.search) {
                            continue;
                        }
                    }
                    matching_connections.insert(summary.connection_id);
                    if !selected_connections.is_empty()
                        && !selected_connections.contains(&summary.connection_id)
                    {
                        continue;
                    }
                    total += 1;
                    if summaries.len() < exchange_limit {
                        summaries.push(summary);
                    }
                }
                (summaries, total, Some(matching_connections))
            };

        let connections = self.0.connections.read();
        let mut connection_summaries =
            Vec::with_capacity(connection_limit.min(connections.entries.len()));
        let mut total_connections = 0;
        let mut active_connections = 0;
        let mut bytes_in = 0_u64;
        let mut bytes_out = 0_u64;
        for connection in connections.entries.values().rev() {
            let summary = connection.snapshot();
            if matching_connections
                .as_ref()
                .is_some_and(|ids| !ids.contains(&summary.id))
            {
                continue;
            }
            total_connections += 1;
            active_connections += usize::from(summary.active);
            bytes_in = bytes_in.saturating_add(summary.bytes_in);
            bytes_out = bytes_out.saturating_add(summary.bytes_out);
            if connection_summaries.len() < connection_limit {
                connection_summaries.push(summary);
            }
        }

        CaptureSnapshot {
            connections: connection_summaries,
            exchanges: exchange_summaries,
            total_connections,
            active_connections,
            total_requests,
            bytes_in,
            bytes_out,
        }
    }

    pub(super) async fn details(&self, id: u64) -> Result<CaptureDetails, BoxError> {
        let entry = self.exchange(id)?;
        let summary = entry.snapshot();
        let records = self.read_records(&entry).await?;
        Ok(CaptureDetails { summary, records })
    }

    pub(super) async fn inspector_details(
        &self,
        id: u64,
        requested_websocket_page: usize,
        websocket_page_size: usize,
    ) -> Result<InspectorDetails, BoxError> {
        let entry = self.exchange(id)?;
        let summary = entry.snapshot();
        let websocket_replay_active = entry
            .websocket_injector
            .read()
            .as_ref()
            .is_some_and(WebSocketRelayInjector::is_open);
        let (mut reader, mut remaining, snapshot_len) = self.snapshot_reader(&entry).await?;
        let mut records = Vec::new();
        let mut websocket_total = 0_usize;
        while let Some(record) = read_record(
            &mut reader,
            &mut remaining,
            &self.0.key,
            entry.summary_template.id,
        )
        .await?
        {
            match record {
                StoredRecord::RequestBody { .. } | StoredRecord::ResponseBody { .. } => {}
                StoredRecord::WebSocketMessage { .. } => {
                    websocket_total = websocket_total.saturating_add(1);
                }
                record => records.push(record),
            }
        }

        if websocket_total == 0 || websocket_page_size == 0 {
            return Ok(InspectorDetails {
                summary,
                records,
                websocket_page: 0,
                websocket_total,
                websocket_replay_active,
            });
        }

        let websocket_page =
            requested_websocket_page.min((websocket_total - 1) / websocket_page_size);
        let end = websocket_total.saturating_sub(websocket_page * websocket_page_size);
        let start = end.saturating_sub(websocket_page_size);
        let (mut reader, mut remaining) = open_reader(entry.path.as_ref(), snapshot_len).await?;
        let mut websocket_index = 0_usize;
        while websocket_index < end
            && let Some(record) = read_record(
                &mut reader,
                &mut remaining,
                &self.0.key,
                entry.summary_template.id,
            )
            .await?
        {
            if matches!(record, StoredRecord::WebSocketMessage { .. }) {
                if websocket_index >= start {
                    records.push(record);
                }
                websocket_index = websocket_index.saturating_add(1);
            }
        }

        Ok(InspectorDetails {
            summary,
            records,
            websocket_page,
            websocket_total,
            websocket_replay_active,
        })
    }

    pub(super) async fn body_stream(
        &self,
        id: u64,
        body: CapturedBody,
        limit: Option<u64>,
    ) -> Result<impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static, BoxError> {
        let entry = self.exchange(id)?;
        let (mut reader, mut remaining, _) = self.snapshot_reader(&entry).await?;
        let key = self.0.key;
        Ok(stream_fn(move |mut yielder| async move {
            let _entry = entry;
            let mut emitted = 0_u64;
            loop {
                let record = match read_record(&mut reader, &mut remaining, &key, id).await {
                    Ok(Some(record)) => record,
                    Ok(None) => break,
                    Err(error) => {
                        yielder.yield_item(Err(error)).await;
                        break;
                    }
                };
                let (
                    (CapturedBody::Request, StoredRecord::RequestBody { data: encoded })
                    | (CapturedBody::Response, StoredRecord::ResponseBody { data: encoded }),
                ) = ((body, record),)
                else {
                    continue;
                };
                let mut data = match BASE64.decode(encoded).context("decode captured body frame") {
                    Ok(data) => data,
                    Err(error) => {
                        yielder.yield_item(Err(error)).await;
                        break;
                    }
                };
                if let Some(limit) = limit {
                    let remaining_limit = limit.saturating_sub(emitted);
                    if remaining_limit == 0 {
                        break;
                    }
                    data.truncate(usize::try_from(remaining_limit).unwrap_or(usize::MAX));
                }
                emitted = emitted.saturating_add(data.len() as u64);
                if !data.is_empty() {
                    yielder.yield_item(Ok(Bytes::from(data))).await;
                }
            }
        }))
    }

    pub(super) async fn websocket_message_stream(
        &self,
        id: u64,
        message_index: usize,
    ) -> Result<impl Stream<Item = Result<Bytes, BoxError>> + Send + 'static, BoxError> {
        let entry = self.exchange(id)?;
        let (mut reader, mut remaining, _) = self.snapshot_reader(&entry).await?;
        let key = self.0.key;
        Ok(stream_fn(move |mut yielder| async move {
            let _entry = entry;
            let mut current_index = 0_usize;
            loop {
                let record = match read_record(&mut reader, &mut remaining, &key, id).await {
                    Ok(Some(record)) => record,
                    Ok(None) => break,
                    Err(error) => {
                        yielder.yield_item(Err(error)).await;
                        break;
                    }
                };
                let StoredRecord::WebSocketMessage { data, .. } = record else {
                    continue;
                };
                if current_index != message_index {
                    current_index = current_index.saturating_add(1);
                    continue;
                }
                match BASE64
                    .decode(data)
                    .context("decode captured WebSocket message")
                {
                    Ok(data) => yielder.yield_item(Ok(Bytes::from(data))).await,
                    Err(error) => yielder.yield_item(Err(error)).await,
                }
                break;
            }
        }))
    }

    fn exchange(&self, id: u64) -> Result<Arc<CapturedExchange>, BoxError> {
        self.0
            .exchanges
            .read()
            .entries
            .get(&id)
            .cloned()
            .context("capture not found")
    }

    async fn read_records(&self, entry: &CapturedExchange) -> Result<Vec<StoredRecord>, BoxError> {
        let (mut reader, mut remaining, _) = self.snapshot_reader(entry).await?;
        let mut records = Vec::new();
        while let Some(record) = read_record(
            &mut reader,
            &mut remaining,
            &self.0.key,
            entry.summary_template.id,
        )
        .await?
        {
            records.push(record);
        }
        Ok(records)
    }

    async fn snapshot_reader(
        &self,
        entry: &CapturedExchange,
    ) -> Result<(File, u64, u64), BoxError> {
        let mut file = entry.file.lock().await;
        file.flush().await.context("flush encrypted capture")?;
        let snapshot_len = file
            .metadata()
            .await
            .context("read encrypted capture snapshot size")?
            .len();
        drop(file);
        let (reader, remaining) = open_reader(entry.path.as_ref(), snapshot_len).await?;
        Ok((reader, remaining, snapshot_len))
    }

    pub(super) async fn replay_request(&self, id: u64) -> Result<ReplayRequest, BoxError> {
        let details = self.details(id).await?;
        if details.summary.request_truncated {
            return Err(std::io::Error::other(
                "captured request body was truncated and cannot be replayed safely",
            )
            .into());
        }
        let mut head = None;
        let mut body = Vec::new();
        for record in details.records {
            match record {
                StoredRecord::RequestHead {
                    method,
                    url,
                    version,
                    headers,
                    ..
                } => head = Some((method, url, version, headers)),
                StoredRecord::RequestBody { data } => body.extend(
                    BASE64
                        .decode(data)
                        .context("decode captured request body")?,
                ),
                _ => {}
            }
        }
        let (method, mut url, version, headers) = head.context("captured request head missing")?;
        if url.starts_with('/') {
            let scheme = if details.summary.protocol.contains("https")
                || details.summary.protocol.contains("wss")
            {
                "https"
            } else {
                "http"
            };
            url = format!("{scheme}://{}{url}", details.summary.endpoint);
        }
        Ok(ReplayRequest {
            method,
            url,
            version,
            headers,
            body,
            user_agent: details.summary.user_agent,
        })
    }

    pub(super) async fn export_profiles(
        &self,
        request_ids: &BTreeSet<u64>,
        connection_ids: &BTreeSet<u64>,
    ) -> Result<Value, BoxError> {
        let mut profiles = Vec::new();
        let mut exported_requests = BTreeSet::new();
        let mut covered_connections = BTreeSet::new();
        for id in request_ids {
            if let Ok(details) = self.details(*id).await
                && let Some(profile) = captured_emulation_profile(&details)
            {
                profiles.push(json!({
                    "connection_id": details.summary.connection_id,
                    "request_id": details.summary.id,
                    "profile": profile,
                }));
                exported_requests.insert(details.summary.id);
                if connection_ids.contains(&details.summary.connection_id) {
                    covered_connections.insert(details.summary.connection_id);
                }
            }
        }

        // A connection can carry many requests but has one effective client
        // emulation identity. Pick its newest profile-bearing request unless an
        // explicitly selected request already represents that connection.
        let candidates = self
            .0
            .exchanges
            .read()
            .entries
            .values()
            .rev()
            .map(|entry| {
                (
                    entry.summary_template.id,
                    entry.summary_template.connection_id,
                )
            })
            .filter(|(_, connection_id)| connection_ids.contains(connection_id))
            .collect::<Vec<_>>();
        for (request_id, connection_id) in candidates {
            if covered_connections.contains(&connection_id)
                || exported_requests.contains(&request_id)
            {
                continue;
            }
            if let Ok(details) = self.details(request_id).await
                && let Some(profile) = captured_emulation_profile(&details)
            {
                profiles.push(json!({
                    "connection_id": connection_id,
                    "request_id": request_id,
                    "profile": profile,
                }));
                exported_requests.insert(request_id);
                covered_connections.insert(connection_id);
            }
        }
        Ok(json!({ "profiles": profiles }))
    }
}

async fn open_reader(path: &std::path::Path, snapshot_len: u64) -> Result<(File, u64), BoxError> {
    let mut reader = File::open(path).await.context("open encrypted capture")?;
    let current_len = reader
        .metadata()
        .await
        .context("read encrypted capture size")?
        .len();
    if current_len < snapshot_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "encrypted capture shrank while opening its snapshot",
        )
        .into());
    }
    let mut magic = [0_u8; FILE_MAGIC.len()];
    reader
        .read_exact(&mut magic)
        .await
        .context("read capture magic")?;
    if &magic != FILE_MAGIC {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid MITM capture file",
        )
        .into());
    }
    let remaining = snapshot_len
        .checked_sub(FILE_MAGIC.len() as u64)
        .context("encrypted capture snapshot is shorter than its magic")?;
    Ok((reader, remaining))
}

async fn read_record(
    reader: &mut File,
    remaining: &mut u64,
    key: &[u8; 32],
    id: u64,
) -> Result<Option<StoredRecord>, BoxError> {
    if *remaining == 0 {
        return Ok(None);
    }
    if *remaining < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "truncated encrypted capture record length",
        )
        .into());
    }
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .await
        .context("read capture record length")?;
    let length = u32::from_be_bytes(length) as usize;
    let framed_len = 4_u64
        .saturating_add(NONCE_LEN as u64)
        .saturating_add(TAG_LEN as u64)
        .saturating_add(length as u64);
    if framed_len > *remaining {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "encrypted capture record extends beyond its snapshot",
        )
        .into());
    }
    let mut nonce = [0_u8; NONCE_LEN];
    let mut tag = [0_u8; TAG_LEN];
    let mut ciphertext = vec![0_u8; length];
    reader
        .read_exact(&mut nonce)
        .await
        .context("read capture nonce")?;
    reader
        .read_exact(&mut tag)
        .await
        .context("read capture tag")?;
    reader
        .read_exact(&mut ciphertext)
        .await
        .context("read capture ciphertext")?;
    *remaining -= framed_len;
    let plaintext = symm::decrypt_aead(
        symm::Cipher::aes_256_gcm(),
        key,
        Some(&nonce),
        &id.to_be_bytes(),
        &ciphertext,
        &tag,
    )
    .context("decrypt MITM capture record")?;
    Ok(Some(
        serde_json::from_slice(&plaintext).context("decode MITM capture record")?,
    ))
}

fn captured_emulation_profile(details: &CaptureDetails) -> Option<Value> {
    details.records.iter().find_map(|record| match record {
        StoredRecord::RequestHead {
            emulation_profile, ..
        } => emulation_profile.clone(),
        _ => None,
    })
}

fn records_match_search(records: &[StoredRecord], needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }
    records.iter().any(|record| {
        if serde_json::to_string(record).is_ok_and(|json| contains_folded(&json, needle)) {
            return true;
        }
        match record {
            StoredRecord::RequestBody { data }
            | StoredRecord::ResponseBody { data }
            | StoredRecord::WebSocketMessage { data, .. } => BASE64
                .decode(data)
                .ok()
                .is_some_and(|data| contains_folded(&String::from_utf8_lossy(&data), needle)),
            _ => false,
        }
    })
}

fn capture_outcome(outcome: CaptureOutcome) -> &'static str {
    match outcome {
        CaptureOutcome::Complete => "complete",
        CaptureOutcome::Error => "error",
        CaptureOutcome::Aborted => "aborted",
    }
}

fn headers_to_vec(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_original_str().into_owned(),
                value
                    .to_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|_| format!("base64:{}", BASE64.encode(value.as_bytes()))),
            )
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyDirection {
    Request,
    Response,
}

#[derive(Clone)]
struct EncryptedBodySink {
    store: CaptureStore,
    exchange_id: u64,
    direction: BodyDirection,
}

impl BodyCaptureSink for EncryptedBodySink {
    fn capture(&self, event: BodyCaptureEvent) -> impl Future<Output = ()> + Send + 'static {
        let this = self.clone();
        async move {
            this.store
                .body_event(this.exchange_id, this.direction, event)
                .await;
        }
    }

    fn aborted(&self) {
        let this = self.clone();
        tokio::spawn(async move {
            this.store
                .body_event(
                    this.exchange_id,
                    this.direction,
                    BodyCaptureEvent::End(CaptureOutcome::Aborted),
                )
                .await;
        });
    }
}

#[derive(Debug, Clone)]
pub(super) struct CaptureHttpLayer {
    store: Option<CaptureStore>,
}

impl CaptureHttpLayer {
    pub(super) fn new(store: Option<CaptureStore>) -> Self {
        Self { store }
    }
}

impl<S> Layer<S> for CaptureHttpLayer {
    type Service = CaptureHttpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CaptureHttpService {
            inner,
            store: self.store.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct CaptureHttpService<S> {
    inner: S,
    store: Option<CaptureStore>,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CaptureHttpService<S>
where
    S: Service<Request<Body>, Output = Response<ResBody>>,
    ReqBody:
        StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody:
        StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response<Body>;
    type Error = S::Error;

    async fn serve(&self, request: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (parts, body) = request.into_parts();
        let Some(store) = &self.store else {
            return self
                .inner
                .serve(Request::from_parts(parts, Body::new(body)))
                .await
                .map(|response| response.map(Body::new));
        };
        let id = match store.begin_exchange(&parts).await {
            Ok(id) => id,
            Err(error) => {
                rama::telemetry::tracing::error!("failed to begin MITM capture: {error}");
                return self
                    .inner
                    .serve(Request::from_parts(parts, Body::new(body)))
                    .await
                    .map(|response| response.map(Body::new));
            }
        };
        parts.extensions.insert(ExchangeId(id));
        let request = Request::from_parts(
            parts,
            Body::new(CaptureBody::new(
                body.map_err(Into::into),
                EncryptedBodySink {
                    store: store.clone(),
                    exchange_id: id,
                    direction: BodyDirection::Request,
                },
            )),
        );
        let response = match self.inner.serve(request).await {
            Ok(response) => response,
            Err(error) => {
                store
                    .body_event(
                        id,
                        BodyDirection::Response,
                        BodyCaptureEvent::End(CaptureOutcome::Error),
                    )
                    .await;
                return Err(error);
            }
        };
        let (parts, body) = response.into_parts();
        if let Err(error) = store.response_head(id, &parts).await {
            rama::telemetry::tracing::debug!("failed to capture response head: {error}");
        }
        Ok(Response::from_parts(
            parts,
            Body::new(CaptureBody::new(
                body.map_err(Into::into),
                EncryptedBodySink {
                    store: store.clone(),
                    exchange_id: id,
                    direction: BodyDirection::Response,
                },
            )),
        ))
    }
}

#[derive(Debug, Clone)]
pub(super) struct ObserveConnectionLayer {
    store: CaptureStore,
    label: &'static str,
}

impl ObserveConnectionLayer {
    pub(super) fn new(store: CaptureStore, label: &'static str) -> Self {
        Self { store, label }
    }
}

impl<S> Layer<S> for ObserveConnectionLayer {
    type Service = ObserveConnectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ObserveConnectionService {
            inner,
            store: self.store.clone(),
            label: self.label,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ObserveConnectionService<S> {
    inner: S,
    store: CaptureStore,
    label: &'static str,
}

impl<S, IO> Service<IO> for ObserveConnectionService<S>
where
    IO: rama::io::Io + Unpin + rama::extensions::ExtensionsRef + 'static,
    S: Service<IO>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: IO) -> Result<Self::Output, Self::Error> {
        let socket = input.extensions().get_ref::<SocketInfo>().cloned();
        let id = self.store.begin_connection(socket, self.label);
        input.extensions().insert(ConnectionId(id));
        let result = self.inner.serve(input).await;
        self.store.finish_connection(id);
        result
    }
}

#[derive(Debug, Clone)]
pub(super) struct MarkProtocolLayer {
    store: Option<CaptureStore>,
    protocol: &'static str,
}

impl MarkProtocolLayer {
    pub(super) fn new(store: Option<CaptureStore>, protocol: &'static str) -> Self {
        Self { store, protocol }
    }
}

impl<S> Layer<S> for MarkProtocolLayer {
    type Service = MarkProtocolService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MarkProtocolService {
            inner,
            store: self.store.clone(),
            protocol: self.protocol,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct MarkProtocolService<S> {
    inner: S,
    store: Option<CaptureStore>,
    protocol: &'static str,
}

impl<S, IO> Service<IO> for MarkProtocolService<S>
where
    IO: rama::extensions::ExtensionsRef + Send + Sync + 'static,
    S: Service<IO>,
{
    type Output = S::Output;
    type Error = S::Error;

    async fn serve(&self, input: IO) -> Result<Self::Output, Self::Error> {
        input.extensions().insert(IngressProtocol(self.protocol));
        if let Some(id) = input.extensions().get_ref::<ConnectionId>()
            && let Some(store) = &self.store
        {
            store.set_connection_protocol(id.0, self.protocol);
        }
        self.inner.serve(input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama::extensions::ExtensionsRef as _;
    use rama::futures::StreamExt as _;
    use std::{convert::Infallible, time::Duration};
    use tokio::task::JoinSet;

    fn test_store() -> CaptureStore {
        test_store_with_limits(8, 8, 1024)
    }

    fn test_store_with_limits(
        max_connections: usize,
        max_exchanges: usize,
        body_limit: u64,
    ) -> CaptureStore {
        CaptureStore::new(
            max_connections,
            max_exchanges,
            body_limit,
            Arc::new(UserAgentDatabase::try_embedded().unwrap()),
        )
        .unwrap()
    }

    fn decoded_body(records: &[StoredRecord], request: bool) -> Vec<u8> {
        records
            .iter()
            .filter_map(|record| match (request, record) {
                (true, StoredRecord::RequestBody { data })
                | (false, StoredRecord::ResponseBody { data }) => BASE64.decode(data).ok(),
                _ => None,
            })
            .flatten()
            .collect()
    }

    #[tokio::test]
    async fn encrypted_records_round_trip_without_plaintext_on_disk() {
        let store = test_store();
        let request = Request::builder()
            .method("POST")
            .uri("http://example.test/private")
            .header("authorization", "Bearer secret-value")
            .body(Body::from("private-payload"))
            .unwrap();
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(Response::new(Body::from("private-response")))
            }),
        );
        let response = service.serve(request).await.unwrap();
        response.into_body().collect().await.unwrap();

        let details = store.details(1).await.unwrap();
        assert_eq!(details.summary.status, Some(200));
        let bytes = tokio::fs::read(store.0.temp_dir.path().join("exchange-1.capture"))
            .await
            .unwrap();
        assert!(!bytes.windows(12).any(|window| window == b"secret-value"));
        assert!(!bytes.windows(15).any(|window| window == b"private-payload"));
        assert!(details.records.iter().any(|record| matches!(
            record,
            StoredRecord::ResponseBody { data } if BASE64.decode(data).unwrap() == b"private-response"
        )));
    }

    #[tokio::test]
    async fn inspector_metadata_is_body_free_and_body_decryption_streams_with_a_limit() {
        let store = test_store_with_limits(8, 8, 4096);
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    "request-stream"
                );
                Ok::<_, Infallible>(Response::new(Body::from("response-stream")))
            }),
        );
        service
            .serve(Request::new(Body::from("request-stream")))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        let details = store.inspector_details(1, 0, 100).await.unwrap();
        assert!(!details.records.iter().any(|record| matches!(
            record,
            StoredRecord::RequestBody { .. } | StoredRecord::ResponseBody { .. }
        )));

        let stream = store
            .body_stream(1, CapturedBody::Request, Some(7))
            .await
            .unwrap();
        let chunks = stream.collect::<Vec<_>>().await;
        let body = chunks
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(body, b"request");

        let stream = store
            .body_stream(1, CapturedBody::Response, None)
            .await
            .unwrap();
        let chunks = stream.collect::<Vec<_>>().await;
        let body = chunks
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(body, b"response-stream");
    }

    #[tokio::test]
    async fn websocket_inspector_pages_are_bounded_and_include_control_events() {
        let store = test_store_with_limits(8, 8, 4096);
        let request = Request::builder()
            .uri("http://example.test/socket")
            .body(Body::empty())
            .unwrap();
        let exchange_id = store.begin_exchange(&request.into_parts().0).await.unwrap();
        for index in 0..100 {
            store
                .record_websocket_message(
                    exchange_id,
                    "Ingress".to_owned(),
                    "text".to_owned(),
                    format!("message-{index}").into_bytes(),
                    None,
                )
                .await;
        }
        store
            .record_websocket_message(
                exchange_id,
                "Egress".to_owned(),
                "close".to_owned(),
                b"done".to_vec(),
                Some(1000),
            )
            .await;

        let first_message = store
            .websocket_message_stream(exchange_id, 0)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(first_message, b"message-0");
        let close_message = store
            .websocket_message_stream(exchange_id, 100)
            .await
            .unwrap()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(close_message, b"done");

        let latest = store.inspector_details(exchange_id, 0, 100).await.unwrap();
        assert_eq!(latest.websocket_total, 101);
        assert_eq!(
            latest
                .records
                .iter()
                .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
                .count(),
            100
        );
        assert!(latest.records.iter().any(|record| matches!(
            record,
            StoredRecord::WebSocketMessage {
                kind,
                close_code: Some(1000),
                ..
            } if kind == "close"
        )));
        let disabled = store.inspector_details(exchange_id, 99, 0).await.unwrap();
        assert_eq!(disabled.websocket_page, 0);
        assert_eq!(disabled.websocket_total, 101);
        assert!(
            !disabled
                .records
                .iter()
                .any(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
        );

        let older = store.inspector_details(exchange_id, 1, 100).await.unwrap();
        assert_eq!(older.websocket_page, 1);
        assert_eq!(
            older
                .records
                .iter()
                .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
                .count(),
            1
        );
        let clamped = store
            .inspector_details(exchange_id, usize::MAX, 100)
            .await
            .unwrap();
        assert_eq!(clamped.websocket_page, 1);
        assert_eq!(
            clamped
                .records
                .iter()
                .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
                .count(),
            1
        );
        let single_page = store
            .inspector_details(exchange_id, usize::MAX, 101)
            .await
            .unwrap();
        assert_eq!(single_page.websocket_page, 0);
        assert_eq!(
            single_page
                .records
                .iter()
                .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
                .count(),
            101
        );
    }

    #[tokio::test]
    async fn dropping_store_removes_encrypted_capture_directory() {
        let directory = {
            let store = test_store();
            let directory = store.0.temp_dir.path().to_owned();
            let service = CaptureHttpLayer::new(Some(store)).into_layer(rama::service::service_fn(
                async |request: Request| {
                    request.into_body().collect().await.unwrap();
                    Ok::<_, Infallible>(Response::new(Body::from("captured")))
                },
            ));
            let response = service.serve(Request::new(Body::empty())).await.unwrap();
            response.into_body().collect().await.unwrap();
            assert!(directory.join("exchange-1.capture").exists());
            directory
        };

        assert!(
            !directory.exists(),
            "dropping the last store must clean its encrypted temporary files"
        );
    }

    #[tokio::test]
    async fn body_capture_limit_does_not_limit_forwarded_traffic() {
        let store = test_store_with_limits(8, 8, 4);
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                assert_eq!(
                    request.into_body().collect().await.unwrap().to_bytes(),
                    "request-body"
                );
                Ok::<_, Infallible>(Response::new(Body::from("response-body")))
            }),
        );

        let response = service
            .serve(Request::new(Body::from("request-body")))
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "response-body"
        );

        let details = store.details(1).await.unwrap();
        assert_eq!(details.summary.request_bytes, 12);
        assert_eq!(details.summary.response_bytes, 13);
        assert!(details.summary.request_truncated);
        assert!(details.summary.response_truncated);
        assert_eq!(decoded_body(&details.records, true), b"requ");
        assert_eq!(decoded_body(&details.records, false), b"resp");
        assert!(details.records.iter().any(|record| matches!(
            record,
            StoredRecord::RequestEnd { outcome } if outcome == "complete"
        )));
        assert!(details.records.iter().any(|record| matches!(
            record,
            StoredRecord::ResponseEnd { outcome } if outcome == "complete"
        )));
        assert!(
            store
                .replay_request(1)
                .await
                .unwrap_err()
                .to_string()
                .contains("truncated")
        );
    }

    #[tokio::test]
    async fn failed_upstream_response_finishes_the_capture_as_an_error() {
        let store = test_store();
        let service =
            CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
                async |_request: Request| Err::<Response<Body>, _>("upstream failed"),
            ));

        service
            .serve(Request::new(Body::empty()))
            .await
            .unwrap_err();
        let details = store.details(1).await.unwrap();
        assert!(!details.summary.active);
        assert_eq!(details.summary.status, None);
        assert!(details.records.iter().any(|record| matches!(
            record,
            StoredRecord::ResponseEnd { outcome } if outcome == "error"
        )));
    }

    #[tokio::test]
    async fn encrypted_capture_authentication_rejects_tampering() {
        let store = test_store();
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(Response::new(Body::from("captured")))
            }),
        );
        service
            .serve(Request::new(Body::empty()))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        let path = store.0.temp_dir.path().join("exchange-1.capture");
        let mut bytes = tokio::fs::read(&path).await.unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        tokio::fs::write(path, bytes).await.unwrap();

        store.details(1).await.unwrap_err();
    }

    #[tokio::test]
    async fn completing_oldest_connection_enforces_retention_limit() {
        let store = test_store_with_limits(1, 8, 1024);
        let first = store.begin_connection(None, "http");
        let second = store.begin_connection(None, "socks5");
        assert_eq!(
            store
                .snapshot(&CaptureFilter::default())
                .await
                .connections
                .len(),
            2
        );

        store.finish_connection(first);
        let snapshot = store.snapshot(&CaptureFilter::default()).await;
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].id, second);
        assert!(snapshot.connections[0].active);
    }

    #[tokio::test]
    async fn finishing_an_unused_connection_removes_it_from_the_inspector() {
        let store = test_store();
        let id = store.begin_connection(None, "http");
        store.finish_connection(id);
        assert!(store.0.connections.read().order.is_empty());
        assert_eq!(
            store
                .snapshot(&CaptureFilter::default())
                .await
                .total_connections,
            0
        );

        let socks = store.begin_connection(None, "socks5");
        store.finish_connection(socks);
        let snapshot = store.snapshot(&CaptureFilter::default()).await;
        assert_eq!(snapshot.total_connections, 1);
        assert_eq!(snapshot.connections[0].id, socks);
        assert!(!snapshot.connections[0].active);
    }

    #[tokio::test]
    async fn active_oldest_connection_does_not_block_retiring_a_newer_one() {
        let store = test_store_with_limits(2, 8, 1024);
        let first = store.begin_connection(None, "http");
        let second = store.begin_connection(None, "https");
        store.finish_connection(second);
        let third = store.begin_connection(None, "socks5");

        let snapshot = store.snapshot(&CaptureFilter::default()).await;
        assert_eq!(snapshot.connections.len(), 2);
        assert!(snapshot.connections.iter().any(|entry| entry.id == first));
        assert!(snapshot.connections.iter().any(|entry| entry.id == third));
        assert!(!snapshot.connections.iter().any(|entry| entry.id == second));
    }

    #[tokio::test]
    async fn limited_snapshot_keeps_full_totals_without_cloning_every_row() {
        let store = test_store_with_limits(8, 8, 1024);
        let first = store.begin_connection(None, "http");
        let second = store.begin_connection(None, "https");
        let third = store.begin_connection(None, "socks5");

        let snapshot = store
            .snapshot_limited(&CaptureFilter::default(), 2, 0)
            .await;
        assert_eq!(snapshot.total_connections, 3);
        assert_eq!(snapshot.connections.len(), 2);
        assert_eq!(snapshot.connections[0].id, third);
        assert_eq!(snapshot.connections[1].id, second);
        assert!(!snapshot.connections.iter().any(|entry| entry.id == first));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_frames_use_atomic_metrics_and_serialized_encrypted_writes() {
        const TASKS: usize = 32;
        const PAYLOAD: &[u8] = b"data";

        let store = test_store_with_limits(8, 8, 4096);
        let connection_id = store.begin_connection(None, "http");
        let request = Request::builder()
            .uri("http://example.test/concurrent")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ConnectionId(connection_id));
        let exchange_id = store.begin_exchange(&request.into_parts().0).await.unwrap();
        let mut changes = store.subscribe();
        let before = *changes.borrow_and_update();

        let mut tasks = JoinSet::new();
        for _ in 0..TASKS {
            let store = store.clone();
            tasks.spawn(async move {
                store
                    .body_event(
                        exchange_id,
                        BodyDirection::Request,
                        BodyCaptureEvent::Frame(rama::http::body::Frame::data(
                            rama::bytes::Bytes::from_static(PAYLOAD),
                        )),
                    )
                    .await;
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }

        tokio::time::timeout(Duration::from_secs(1), changes.changed())
            .await
            .expect("capture change notification timed out")
            .unwrap();
        assert_eq!(*changes.borrow_and_update() - before, TASKS as u64);
        let snapshot = store.snapshot(&CaptureFilter::default()).await;
        assert_eq!(
            snapshot.connections[0].bytes_in,
            (TASKS * PAYLOAD.len()) as u64
        );
        assert_eq!(
            snapshot.exchanges[0].request_bytes,
            (TASKS * PAYLOAD.len()) as u64
        );
        let details = store.details(exchange_id).await.unwrap();
        assert_eq!(
            details
                .records
                .iter()
                .filter(|record| matches!(record, StoredRecord::RequestBody { .. }))
                .count(),
            TASKS
        );
    }

    #[tokio::test]
    async fn active_oldest_exchange_does_not_block_retiring_a_newer_one() {
        let store = test_store_with_limits(8, 2, 1024);
        let request_parts = |path: &str| {
            Request::builder()
                .uri(format!("http://example.test/{path}"))
                .body(Body::empty())
                .unwrap()
                .into_parts()
                .0
        };
        let first = store.begin_exchange(&request_parts("first")).await.unwrap();
        let second = store
            .begin_exchange(&request_parts("second"))
            .await
            .unwrap();
        store
            .body_event(
                second,
                BodyDirection::Response,
                BodyCaptureEvent::End(CaptureOutcome::Complete),
            )
            .await;
        let third = store.begin_exchange(&request_parts("third")).await.unwrap();

        let snapshot = store.snapshot(&CaptureFilter::default()).await;
        assert_eq!(snapshot.exchanges.len(), 2);
        assert!(snapshot.exchanges.iter().any(|entry| entry.id == first));
        assert!(snapshot.exchanges.iter().any(|entry| entry.id == third));
        assert!(!snapshot.exchanges.iter().any(|entry| entry.id == second));
        store.details(second).await.unwrap_err();
    }

    #[tokio::test]
    async fn filtered_limits_keep_exact_full_totals_and_connection_membership() {
        let store = test_store_with_limits(8, 8, 1024);
        let first = store.begin_connection(None, "http");
        let second = store.begin_connection(None, "http");
        let unrelated = store.begin_connection(None, "socks5");

        for (connection_id, path) in [(first, "matched-one"), (second, "matched-two")] {
            let request = Request::builder()
                .uri(format!("http://example.test/{path}"))
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(ConnectionId(connection_id));
            store.begin_exchange(&request.into_parts().0).await.unwrap();
        }

        let snapshot = store
            .snapshot_limited(
                &CaptureFilter {
                    search: "matched".to_owned(),
                    ..Default::default()
                },
                1,
                1,
            )
            .await;
        assert_eq!(snapshot.total_requests, 2);
        assert_eq!(snapshot.exchanges.len(), 1);
        assert_eq!(snapshot.total_connections, 2);
        assert_eq!(snapshot.active_connections, 2);
        assert_eq!(snapshot.connections.len(), 1);
        assert!(matches!(
            snapshot.connections[0].id,
            id if id == first || id == second
        ));
        assert_ne!(snapshot.connections[0].id, unrelated);
    }

    #[tokio::test]
    async fn selected_connections_filter_exchanges_without_hiding_other_connections() {
        let store = test_store_with_limits(8, 8, 1024);
        let first = store.begin_connection(None, "http");
        let second = store.begin_connection(None, "socks5");

        for connection_id in [first, second] {
            let request = Request::builder()
                .uri(format!("http://example.test/{connection_id}"))
                .body(Body::empty())
                .unwrap();
            request.extensions().insert(ConnectionId(connection_id));
            store.begin_exchange(&request.into_parts().0).await.unwrap();
        }

        let snapshot = store
            .snapshot_limited_for_connections(
                &CaptureFilter::default(),
                &BTreeSet::from([first]),
                8,
                8,
            )
            .await;
        assert_eq!(snapshot.total_connections, 2);
        assert_eq!(snapshot.connections.len(), 2);
        assert_eq!(snapshot.total_requests, 1);
        assert_eq!(snapshot.exchanges.len(), 1);
        assert_eq!(snapshot.exchanges[0].connection_id, first);

        let limited = store
            .snapshot_limited_for_connections(
                &CaptureFilter::default(),
                &BTreeSet::from([first, second]),
                8,
                1,
            )
            .await;
        assert_eq!(limited.total_requests, 2);
        assert_eq!(limited.exchanges.len(), 1);

        let structurally_filtered = store
            .snapshot_limited_for_connections(
                &CaptureFilter {
                    connection_id: first.to_string(),
                    ..Default::default()
                },
                &BTreeSet::from([first]),
                8,
                8,
            )
            .await;
        assert_eq!(structurally_filtered.total_connections, 1);
        assert_eq!(structurally_filtered.connections[0].id, first);
        assert_eq!(structurally_filtered.total_requests, 1);
        assert_eq!(structurally_filtered.exchanges[0].connection_id, first);
    }

    #[tokio::test]
    async fn provisional_dashboard_connections_can_only_be_discarded_while_empty() {
        let store = test_store_with_limits(8, 8, 1024);
        let dashboard = store.begin_connection(None, "http");
        assert!(store.discard_connection_if_empty(dashboard));
        assert!(store.0.connections.read().order.is_empty());
        assert!(!store.discard_connection_if_empty(dashboard));
        store.finish_connection(dashboard);
        assert_eq!(
            store
                .snapshot(&CaptureFilter::default())
                .await
                .total_connections,
            0
        );

        let proxied = store.begin_connection(None, "http");
        let request = Request::builder()
            .uri("http://example.test/proxied")
            .body(Body::empty())
            .unwrap();
        request.extensions().insert(ConnectionId(proxied));
        store.begin_exchange(&request.into_parts().0).await.unwrap();
        assert!(!store.discard_connection_if_empty(proxied));
        assert_eq!(
            store
                .snapshot(&CaptureFilter::default())
                .await
                .total_connections,
            1
        );
    }

    #[tokio::test]
    async fn replay_reconstructs_relative_url_headers_and_captured_body() {
        let store = test_store();
        let request = Request::builder()
            .method("PATCH")
            .uri("/resource")
            .header("host", "example.test:8080")
            .header("x-replay", "yes")
            .body(Body::from("patch-body"))
            .unwrap();
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        service
            .serve(request)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        let replay = store.replay_request(1).await.unwrap();
        assert_eq!(replay.method, "PATCH");
        assert_eq!(replay.url, "http://example.test:8080/resource");
        assert_eq!(replay.body, b"patch-body");
        assert!(
            replay
                .headers
                .iter()
                .any(|header| header == &("x-replay".to_owned(), "yes".to_owned()))
        );
    }

    #[test]
    fn filter_is_case_insensitive_across_summary_fields() {
        let summary = ExchangeSummary {
            id: 1,
            connection_id: 1,
            started_at: String::new(),
            method: "GET".to_owned(),
            url: "https://Example.Test/widgets".to_owned(),
            endpoint: "Example.Test".to_owned(),
            protocol: "HTTPS".to_owned(),
            user_agent: Some("Rama Browser".to_owned()),
            user_agent_kind: None,
            status: Some(200),
            active: false,
            request_bytes: 0,
            response_bytes: 0,
            request_truncated: false,
            response_truncated: false,
            ja3: None,
            ja4: None,
            peetprint: None,
            has_emulation_profile: false,
        };
        assert!(
            CaptureFilter {
                search: "widgets".to_owned(),
                connection_id: "#1".to_owned(),
                user_agent: "rama".to_owned(),
                endpoint: "example".to_owned(),
                method: "get".to_owned(),
                status: "2xx".to_owned(),
                protocol: "https".to_owned(),
            }
            .matches_dimensions(&summary)
        );
        assert!(
            CaptureFilter {
                protocol: "http".to_owned(),
                ..Default::default()
            }
            .matches_dimensions(&ExchangeSummary {
                protocol: "http".to_owned(),
                ..summary.clone()
            })
        );
        assert!(
            !CaptureFilter {
                protocol: "http".to_owned(),
                ..Default::default()
            }
            .matches_dimensions(&summary),
            "HTTP must not accidentally match HTTPS"
        );
        assert!(
            CaptureFilter {
                protocol: "wss".to_owned(),
                ..Default::default()
            }
            .matches_dimensions(&ExchangeSummary {
                protocol: "wss".to_owned(),
                ..summary.clone()
            })
        );
        assert!(
            CaptureFilter {
                search: "widgets".to_owned(),
                ..Default::default()
            }
            .search_matches_summary(&summary)
        );

        for status in ["200", "2xx"] {
            assert!(matches_status(&summary, status), "status filter {status}");
        }
        for status in ["pending", "3xx", "4xx", "5xx", "404", "invalid"] {
            assert!(!matches_status(&summary, status), "status filter {status}");
        }
        assert!(matches_status(
            &ExchangeSummary {
                status: None,
                active: true,
                ..summary
            },
            "pending"
        ));
        assert!(matches_connection_id(1, "  #1 "));
        assert!(!matches_connection_id(1, "2"));
        assert!(!matches_connection_id(1, "not-a-number"));
        assert!(matches_protocol("ws", "ws"));
        assert!(matches_protocol("wss", "wss"));
        assert!(matches_protocol("grpc", "other"));
        assert!(!matches_protocol("https", "other"));
    }

    #[tokio::test]
    async fn search_reads_encrypted_headers_and_payload_from_disk() {
        let store = test_store();
        let request = Request::builder()
            .method("POST")
            .uri("http://example.test/upload")
            .header("x-private-marker", "header-needle")
            .body(Body::from("payload-needle"))
            .unwrap();
        let service = CaptureHttpLayer::new(Some(store.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        service
            .serve(request)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        for search in ["HEADER-NEEDLE", "payload-needle"] {
            let snapshot = store
                .snapshot(&CaptureFilter {
                    search: search.to_owned(),
                    ..Default::default()
                })
                .await;
            assert_eq!(snapshot.exchanges.len(), 1, "search {search:?}");
        }
        let snapshot = store
            .snapshot(&CaptureFilter {
                search: "absent-private-value".to_owned(),
                ..Default::default()
            })
            .await;
        assert_eq!(snapshot.total_requests, 0);
        assert!(snapshot.exchanges.is_empty());
        assert!(snapshot.connections.is_empty());
    }

    #[tokio::test]
    async fn export_profiles_returns_only_captures_with_known_profiles() {
        const PROFILE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1";
        let store = test_store();
        let service =
            CaptureHttpLayer::new(Some(store.clone())).into_layer(rama::service::service_fn(
                async |_request: Request| Ok::<_, Infallible>(Response::new(Body::empty())),
            ));
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/")
                    .header("user-agent", PROFILE_UA)
                    .extension(ConnectionId(7))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/no-user-agent")
                    .extension(ConnectionId(7))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/latest-profile")
                    .header("user-agent", PROFILE_UA)
                    .extension(ConnectionId(7))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        let export = store
            .export_profiles(&BTreeSet::from([1, 2, 999]), &BTreeSet::new())
            .await
            .unwrap();
        let profiles = export["profiles"].as_array().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["request_id"], 1);
        assert_eq!(profiles[0]["profile"]["user_agent"], PROFILE_UA);

        let connection_export = store
            .export_profiles(&BTreeSet::new(), &BTreeSet::from([7]))
            .await
            .unwrap();
        assert_eq!(connection_export["profiles"].as_array().unwrap().len(), 1);
        assert_eq!(connection_export["profiles"][0]["request_id"], 3);

        let combined = store
            .export_profiles(&BTreeSet::from([1]), &BTreeSet::from([7]))
            .await
            .unwrap();
        assert_eq!(combined["profiles"].as_array().unwrap().len(), 1);
    }
}
