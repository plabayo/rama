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
        fingerprint::{AkamaiH2, Ja4H},
        proto::h2::{PseudoHeaderOrder, frame::EarlyFrameCapture},
        ws::handshake::mitm::{
            WebSocketBridge, WebSocketRelayDirection, WebSocketRelayInjector, WebSocketRelayMessage,
        },
    },
    net::stream::SocketInfo,
    tls::{
        SecureTransport,
        boring::core::{rand::rand_bytes, symm},
        client::{ClientHello, NegotiatedTlsParameters},
        fingerprint::{Ja3, Ja4, PeetPrint},
    },
    ua::{
        UserAgent,
        profile::{
            Http1Settings, Http2Settings, RequestInitiator, UserAgentDatabase,
            UserAgentProfileInput,
        },
    },
    utils::fs::{TempDir, TempPath, TempPathCleanup},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _},
    sync::{Mutex, watch},
};

use super::inspection::InspectionState;

const FILE_MAGIC: &[u8; 8] = b"RMCAP\0\x01\0";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

mod model;

use model::contains_folded;
pub(super) use model::{
    CaptureDetails, CaptureFilter, CaptureSnapshot, CapturedBody, CapturedTlsParameters,
    ConnectionId, ConnectionSummary, ExchangeId, ExchangeSummary, IngressProtocol,
    InspectorDetails, ReplayRequest, StoredRecord, WebSocketReplayError,
};
#[cfg(test)]
use model::{matches_connection_id, matches_protocol, matches_status};

struct CapturedConnection {
    summary_template: ConnectionSummary,
    display_id: OnceLock<u64>,
    ingress_protocol: RwLock<String>,
    confirmed: AtomicBool,
    transport_finished: AtomicBool,
    active: AtomicBool,
    ended_at: OnceLock<String>,
    request_count: AtomicUsize,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

#[derive(Default)]
struct ConnectionExchangeState {
    active: bool,
    completed_at: Option<String>,
}

fn reconcile_connection_summary(
    summary: &mut ConnectionSummary,
    exchange_state: Option<&ConnectionExchangeState>,
) {
    let Some(exchange_state) = exchange_state else {
        return;
    };
    if exchange_state.active {
        summary.active = true;
        summary.ended_at = None;
    } else if !summary.active
        && let Some(completed_at) = &exchange_state.completed_at
    {
        summary.ended_at = Some(match summary.ended_at.take() {
            Some(ended_at) => std::cmp::max(ended_at, completed_at.clone()),
            None => completed_at.clone(),
        });
    }
}

impl CapturedConnection {
    fn snapshot(&self) -> ConnectionSummary {
        let mut summary = self.summary_template.clone();
        summary.display_id = self.display_id.get().copied().unwrap_or_default();
        summary
            .ingress_protocol
            .clone_from(&self.ingress_protocol.read());
        summary.active = self.active.load(Ordering::Relaxed);
        summary.ended_at.clone_from(&self.ended_at.get().cloned());
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
    response_started_at: OnceLock<String>,
    completed_at: OnceLock<String>,
    egress_socket: OnceLock<(String, String)>,
    request_bytes: AtomicU64,
    response_bytes: AtomicU64,
    request_truncated: AtomicBool,
    response_truncated: AtomicBool,
    websocket_injector: RwLock<Option<WebSocketRelayInjector>>,
    file: Mutex<EncryptedCaptureFile>,
    path: TempPath,
    metadata_records: RwLock<Vec<RecordLocation>>,
    request_body_records: RwLock<Vec<RecordLocation>>,
    response_body_records: RwLock<Vec<RecordLocation>>,
    websocket_records: RwLock<Vec<RecordLocation>>,
    request_stored: AtomicU64,
    response_stored: AtomicU64,
}

struct EncryptedCaptureFile {
    file: File,
    len: u64,
}

#[derive(Debug, Clone, Copy)]
struct RecordLocation {
    offset: u64,
    len: u64,
}

impl CapturedExchange {
    fn snapshot(&self) -> ExchangeSummary {
        let mut summary = self.summary_template.clone();
        if let Some(connection) = &self.connection {
            summary.connection_display_id =
                connection.display_id.get().copied().unwrap_or_default();
        }
        let status = self.status.load(Ordering::Relaxed);
        summary.status = (status != 0).then_some(status);
        summary.active = self.active.load(Ordering::Relaxed);
        summary
            .response_started_at
            .clone_from(&self.response_started_at.get().cloned());
        summary
            .completed_at
            .clone_from(&self.completed_at.get().cloned());
        if let Some((local, peer)) = self.egress_socket.get() {
            summary.egress_local_address = Some(local.clone());
            summary.egress_peer_address = Some(peer.clone());
        }
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

fn captured_tls_parameters(parameters: &NegotiatedTlsParameters) -> CapturedTlsParameters {
    CapturedTlsParameters {
        protocol_version: parameters.protocol_version,
        application_layer_protocol: parameters.application_layer_protocol.clone(),
        peer_certificate_count: parameters.peer_certificate_chain.as_ref().map(Vec::len),
    }
}

fn http_version_label(version: rama::http::Version) -> &'static str {
    match version {
        rama::http::Version::HTTP_09 => "HTTP/0.9",
        rama::http::Version::HTTP_10 => "HTTP/1.0",
        rama::http::Version::HTTP_11 => "HTTP/1.1",
        rama::http::Version::HTTP_2 => "HTTP/2",
        rama::http::Version::HTTP_3 => "HTTP/3",
    }
}

pub(super) fn captured_http_version(value: &str) -> Result<rama::http::Version, BoxError> {
    match value {
        "HTTP/0.9" => Ok(rama::http::Version::HTTP_09),
        "HTTP/1.0" => Ok(rama::http::Version::HTTP_10),
        "HTTP/1.1" => Ok(rama::http::Version::HTTP_11),
        "HTTP/2" | "HTTP/2.0" => Ok(rama::http::Version::HTTP_2),
        "HTTP/3" | "HTTP/3.0" => Ok(rama::http::Version::HTTP_3),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported captured HTTP version: {value}"),
        )
        .into()),
    }
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
    inspection: InspectionState,
    key: [u8; 32],
    temp_cleanup: TempPathCleanup,
    next_connection_id: AtomicU64,
    next_display_connection_id: AtomicU64,
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

pub(in crate::cmd::serve::proxy) struct CaptureConnectionGuard {
    store: CaptureStore,
    id: u64,
}

impl Drop for CaptureConnectionGuard {
    fn drop(&mut self) {
        self.store.finish_connection(self.id);
    }
}

pub(in crate::cmd::serve::proxy) struct CaptureWebSocketExchangeGuard {
    store: CaptureStore,
    id: u64,
}

impl Drop for CaptureWebSocketExchangeGuard {
    fn drop(&mut self) {
        self.store.finish_websocket_exchange(self.id);
    }
}

impl fmt::Debug for CaptureStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CaptureStore")
            .field("directory", &self.0.temp_dir.path())
            .field("inspection", &self.0.inspection)
            .field("max_connections", &self.0.max_connections)
            .field("max_exchanges", &self.0.max_exchanges)
            .field("body_limit", &self.0.body_limit)
            .finish_non_exhaustive()
    }
}

impl CaptureStore {
    #[cfg(test)]
    pub(super) fn new(
        max_connections: usize,
        max_exchanges: usize,
        body_limit: u64,
        ua_db: Arc<UserAgentDatabase>,
    ) -> Result<Self, BoxError> {
        Self::new_with_inspection(
            max_connections,
            max_exchanges,
            body_limit,
            ua_db,
            InspectionState::default(),
        )
    }

    pub(super) fn new_with_inspection(
        max_connections: usize,
        max_exchanges: usize,
        body_limit: u64,
        ua_db: Arc<UserAgentDatabase>,
        inspection: InspectionState,
    ) -> Result<Self, BoxError> {
        let temp_dir = TempDir::with_prefix("rama-proxy-mitm-")
            .context("create encrypted MITM capture directory")?;
        let mut key = [0_u8; 32];
        rand_bytes(&mut key).context("generate in-memory MITM capture key")?;
        let (temp_cleanup, temp_cleanup_worker) = TempPathCleanup::new();
        tokio::spawn(temp_cleanup_worker.run());
        let (changes, _) = watch::channel(0);
        Ok(Self(Arc::new(CaptureStoreInner {
            inspection,
            key,
            temp_cleanup,
            next_connection_id: AtomicU64::new(1),
            next_display_connection_id: AtomicU64::new(1),
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

    pub(super) fn inspection_state(&self) -> InspectionState {
        self.0.inspection.clone()
    }

    pub(super) fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }

    fn changed(&self) {
        self.0
            .changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    #[cfg(test)]
    pub(super) fn begin_connection(&self, socket: Option<SocketInfo>, ingress: &str) -> u64 {
        self.begin_connection_labeled(socket, ingress, None)
    }

    pub(super) fn begin_connection_if_enabled(
        &self,
        socket: Option<SocketInfo>,
        ingress: &str,
        label: Option<String>,
    ) -> Option<u64> {
        let _permit = self.0.inspection.try_capture()?;
        Some(self.begin_connection_labeled(socket, ingress, label))
    }

    pub(super) fn begin_connection_labeled(
        &self,
        socket: Option<SocketInfo>,
        ingress: &str,
        label: Option<String>,
    ) -> u64 {
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
                display_id: 0,
                label,
                started_at: jiff::Timestamp::now().to_string(),
                local_address,
                peer_address,
                ingress_protocol: ingress.to_owned(),
                active: true,
                ended_at: None,
                request_count: 0,
                bytes_in: 0,
                bytes_out: 0,
            },
            display_id: OnceLock::new(),
            ingress_protocol: RwLock::new(ingress.to_owned()),
            confirmed: AtomicBool::new(false),
            transport_finished: AtomicBool::new(false),
            active: AtomicBool::new(true),
            ended_at: OnceLock::new(),
            request_count: AtomicUsize::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        });
        {
            let mut connections = self.0.connections.write();
            connections.entries.insert(id, connection);
            connections.order.push_back(id);
        }
        id
    }

    pub(super) fn connection_guard(&self, id: u64) -> CaptureConnectionGuard {
        CaptureConnectionGuard {
            store: self.clone(),
            id,
        }
    }

    fn websocket_exchange_guard(&self, id: u64) -> CaptureWebSocketExchangeGuard {
        CaptureWebSocketExchangeGuard {
            store: self.clone(),
            id,
        }
    }

    pub(super) async fn clear(&self) {
        let capture_paths = self
            .0
            .exchanges
            .read()
            .entries
            .values()
            .map(|exchange| exchange.path.as_ref().to_owned())
            .collect::<Vec<_>>();
        let exchanges = {
            let mut registry = self.0.exchanges.write();
            std::mem::take(&mut *registry)
        };
        let connections = {
            let mut registry = self.0.connections.write();
            std::mem::take(&mut *registry)
        };
        drop(exchanges);
        drop(connections);
        // Unlink eagerly where the platform permits it. A capture operation
        // that was already in flight can briefly retain its entry after the
        // registries are cleared; TempPath remains the eventual fallback for
        // platforms that do not unlink open files.
        for path in capture_paths {
            if let Err(error) = tokio::fs::remove_file(&path).await
                && error.kind() != std::io::ErrorKind::NotFound
            {
                rama::telemetry::tracing::debug!(
                    ?path,
                    "failed to unlink cleared capture: {error}"
                );
            }
        }
        self.0.temp_cleanup.flush().await;
        self.changed();
    }

    /// Publish a provisionally accepted socket once it is known to carry
    /// proxy traffic rather than the inspector's own shared-port HTTP traffic.
    pub(super) fn confirm_connection(&self, id: u64) {
        let connection = self.0.connections.read().entries.get(&id).cloned();
        if let Some(connection) = connection
            && self.confirm_connection_entry(&connection)
        {
            self.trim_connections();
            self.changed();
        }
    }

    pub(super) fn confirm_connection_if_enabled(&self, id: u64) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
        self.confirm_connection(id);
    }

    fn confirm_connection_entry(&self, connection: &CapturedConnection) -> bool {
        connection.display_id.get_or_init(|| {
            self.0
                .next_display_connection_id
                .fetch_add(1, Ordering::Relaxed)
        });
        !connection.confirmed.swap(true, Ordering::Release)
    }

    pub(super) fn set_connection_protocol(&self, id: u64, protocol: &str) {
        if let Some(connection) = self.0.connections.read().entries.get(&id).cloned() {
            *connection.ingress_protocol.write() = protocol.to_owned();
            if connection.confirmed.load(Ordering::Relaxed) {
                self.changed();
            }
        }
    }

    pub(super) fn set_connection_protocol_if_enabled(&self, id: u64, protocol: &str) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
        self.set_connection_protocol(id, protocol);
    }

    pub(super) fn finish_connection(&self, id: u64) {
        let Some(connection) = self.0.connections.read().entries.get(&id).cloned() else {
            return;
        };
        let confirmed = connection.confirmed.load(Ordering::Relaxed);
        if !confirmed {
            let mut connections = self.0.connections.write();
            connections.entries.remove(&id);
            connections.order.retain(|candidate| *candidate != id);
            return;
        }
        connection.transport_finished.store(true, Ordering::Relaxed);
        if self.has_active_websocket_exchange(id) {
            return;
        }
        self.finish_upgraded_connection(&connection);
    }

    fn has_active_websocket_exchange(&self, connection_id: u64) -> bool {
        self.0.exchanges.read().entries.values().any(|entry| {
            entry.summary_template.connection_id == connection_id
                && matches!(entry.summary_template.protocol.as_str(), "ws" | "wss")
                && entry.active.load(Ordering::Relaxed)
        })
    }

    fn finish_upgraded_connection(&self, connection: &CapturedConnection) {
        if connection.transport_finished.load(Ordering::Relaxed)
            && connection.active.swap(false, Ordering::Relaxed)
        {
            _ = connection.ended_at.set(jiff::Timestamp::now().to_string());
            self.trim_connections();
            self.changed();
        }
    }

    fn finish_websocket_exchange(&self, id: u64) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        if entry.active.swap(false, Ordering::Relaxed) {
            _ = entry.completed_at.set(jiff::Timestamp::now().to_string());
            if let Some(connection) = &entry.connection {
                self.finish_upgraded_connection(connection);
            }
            self.trim_exchanges();
            self.changed();
        }
    }

    /// Forget a connection that has only served the inspector itself.
    ///
    /// A shared proxy/UI listener cannot distinguish the two at accept time.
    /// The first parsed origin-form dashboard request can, and is allowed to
    /// remove the provisional entry as long as no proxied exchange has been
    /// associated with it.
    pub(super) fn discard_connection_if_empty(&self, id: u64) -> bool {
        {
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
        }
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

    async fn begin_exchange(
        &self,
        parts: &rama::http::request::Parts,
    ) -> Result<Option<u64>, BoxError> {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return Ok(None);
        };
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
        let websocket = is_websocket_handshake(parts);
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
        let ja3 = Ja3::compute(&parts.extensions).ok().map(|fp| fp.hash());
        let ja4 = Ja4::compute(&parts.extensions)
            .ok()
            .map(|fp| fp.to_string());
        let peetprint = PeetPrint::compute(&parts.extensions)
            .ok()
            .map(|fp| fp.to_string());
        let ja4h = Ja4H::compute(parts).ok().map(|fp| fp.to_string());
        let akamai_h2 = AkamaiH2::compute(&parts.extensions)
            .ok()
            .map(|fp| fp.to_string());
        let known_fingerprint = known_fingerprint_label(
            &self.0.ua_db,
            user_agent.as_deref(),
            parts,
            ja3.as_deref(),
            ja4.as_deref(),
            peetprint.as_deref(),
            ja4h.as_deref(),
        );
        let tls_profile_client_hello = parts
            .extensions
            .get_ref::<SecureTransport>()
            .and_then(SecureTransport::client_hello)
            .cloned();
        let tls_client_hello = tls_profile_client_hello.clone();
        let ingress_tls = parts
            .extensions
            .get_ref::<NegotiatedTlsParameters>()
            .map(captured_tls_parameters);
        let h2_settings = (parts.version == rama::http::Version::HTTP_2).then(|| Http2Settings {
            http_pseudo_headers: parts.extensions.get_ref::<PseudoHeaderOrder>().cloned(),
            early_frames: parts.extensions.get_ref::<EarlyFrameCapture>().cloned(),
        });
        let profile = captured_profile(
            parts,
            user_agent.as_deref(),
            tls_profile_client_hello,
            h2_settings,
            websocket,
        );
        let has_emulation_profile = profile.is_some();
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
        let (ingress_local_address, ingress_peer_address) = connection
            .as_ref()
            .map(|connection| {
                (
                    Some(connection.summary_template.local_address.clone()),
                    Some(connection.summary_template.peer_address.clone()),
                )
            })
            .unwrap_or_default();
        let entry = Arc::new(CapturedExchange {
            summary_template: ExchangeSummary {
                id,
                connection_id,
                connection_display_id: connection
                    .as_ref()
                    .and_then(|connection| connection.display_id.get().copied())
                    .unwrap_or_default(),
                started_at: jiff::Timestamp::now().to_string(),
                method: parts.method.to_string(),
                http_version: http_version_label(parts.version).to_owned(),
                url: parts.uri.to_string(),
                endpoint,
                protocol,
                ingress_local_address,
                ingress_peer_address,
                user_agent,
                user_agent_kind,
                status: None,
                active: true,
                response_started_at: None,
                completed_at: None,
                egress_local_address: None,
                egress_peer_address: None,
                request_bytes: 0,
                response_bytes: 0,
                request_truncated: false,
                response_truncated: false,
                ja3,
                ja4,
                peetprint,
                ja4h,
                akamai_h2,
                known_fingerprint,
                has_emulation_profile,
            },
            connection,
            status: AtomicU16::new(0),
            active: AtomicBool::new(true),
            response_started_at: OnceLock::new(),
            completed_at: OnceLock::new(),
            egress_socket: OnceLock::new(),
            request_bytes: AtomicU64::new(0),
            response_bytes: AtomicU64::new(0),
            request_truncated: AtomicBool::new(false),
            response_truncated: AtomicBool::new(false),
            websocket_injector: RwLock::new(None),
            file: Mutex::new(EncryptedCaptureFile {
                file,
                len: FILE_MAGIC.len() as u64,
            }),
            path,
            metadata_records: RwLock::new(Vec::new()),
            request_body_records: RwLock::new(Vec::new()),
            response_body_records: RwLock::new(Vec::new()),
            websocket_records: RwLock::new(Vec::new()),
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
                    tls_client_hello,
                    ingress_tls,
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
            self.confirm_connection_entry(connection);
            _ = connection.request_count.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_add(1)),
            );
            self.trim_connections();
        }
        self.trim_exchanges();
        self.changed();
        Ok(Some(id))
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
        let Some(_permit) = self.0.inspection.try_capture() else {
            return Ok(());
        };
        let entry = self.0.exchanges.read().entries.get(&id).cloned();
        if let Some(entry) = entry {
            entry.status.store(parts.status.as_u16(), Ordering::Relaxed);
            _ = entry
                .response_started_at
                .set(jiff::Timestamp::now().to_string());
            if let Some(socket) = parts.extensions.get_ref::<SocketInfo>() {
                _ = entry.egress_socket.set((
                    socket
                        .local_addr()
                        .map(|address| address.to_string())
                        .unwrap_or_else(|| "unknown".to_owned()),
                    socket.peer_addr().to_string(),
                ));
            }
            self.append(
                id,
                &entry,
                &StoredRecord::ResponseHead {
                    status: parts.status.as_u16(),
                    version: format!("{:?}", parts.version),
                    headers: headers_to_vec(&parts.headers),
                    egress_tls: parts
                        .extensions
                        .get_ref::<NegotiatedTlsParameters>()
                        .map(captured_tls_parameters),
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
        let mut capture_file = entry.file.lock().await;
        let location = RecordLocation {
            offset: capture_file.len,
            len: framed.len() as u64,
        };
        capture_file
            .file
            .write_all(&framed)
            .await
            .context("append encrypted MITM capture record")?;
        capture_file.len = capture_file.len.saturating_add(location.len);
        drop(capture_file);
        match record {
            StoredRecord::RequestBody { .. } => entry.request_body_records.write().push(location),
            StoredRecord::ResponseBody { .. } => {
                entry.response_body_records.write().push(location);
            }
            StoredRecord::WebSocketMessage { .. } => {
                entry.websocket_records.write().push(location);
            }
            _ => entry.metadata_records.write().push(location),
        }
        Ok(())
    }

    async fn body_event(&self, id: u64, direction: BodyDirection, event: BodyCaptureEvent) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            if matches!(event, BodyCaptureEvent::Frame(_)) {
                self.mark_capture_gap(id, direction);
            }
            if direction == BodyDirection::Response && matches!(event, BodyCaptureEvent::End(_)) {
                self.finish_http_exchange(id);
            }
            return;
        };
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
                    let websocket_upgrade =
                        matches!(entry.summary_template.protocol.as_str(), "ws" | "wss")
                            && entry.status.load(Ordering::Relaxed) == 101;
                    if !websocket_upgrade {
                        self.finish_http_exchange_entry(&entry);
                    }
                }
            }
        }
        self.changed();
    }

    fn finish_http_exchange(&self, id: u64) {
        if let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() {
            self.finish_http_exchange_entry(&entry);
            self.changed();
        }
    }

    fn finish_http_exchange_entry(&self, entry: &CapturedExchange) {
        if entry.active.swap(false, Ordering::Relaxed) {
            _ = entry.completed_at.set(jiff::Timestamp::now().to_string());
            self.trim_exchanges();
        }
    }

    fn mark_capture_gap(&self, id: u64, direction: BodyDirection) {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return;
        };
        match direction {
            BodyDirection::Request => entry.request_truncated.store(true, Ordering::Relaxed),
            BodyDirection::Response => entry.response_truncated.store(true, Ordering::Relaxed),
        }
    }

    pub(super) async fn record_websocket_message(
        &self,
        id: u64,
        direction: String,
        kind: String,
        data: Vec<u8>,
        close_code: Option<u16>,
    ) {
        self.record_websocket_message_inner(
            id,
            direction,
            kind,
            data,
            close_code,
            WebSocketMessageOrigin::Peer,
        )
        .await;
    }

    async fn record_websocket_message_inner(
        &self,
        id: u64,
        direction: String,
        kind: String,
        mut data: Vec<u8>,
        close_code: Option<u16>,
        origin: WebSocketMessageOrigin,
    ) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            let direction = if direction.eq_ignore_ascii_case("ingress") {
                BodyDirection::Request
            } else {
                BodyDirection::Response
            };
            self.mark_capture_gap(id, direction);
            return;
        };
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
                    replayed: matches!(origin, WebSocketMessageOrigin::Replay),
                    injected: matches!(origin, WebSocketMessageOrigin::Injected),
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
            *current = Some(injector);
        }
        drop(current);
        if replace {
            entry.active.store(true, Ordering::Relaxed);
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
        let location = entry
            .websocket_records
            .read()
            .get(message_index)
            .copied()
            .ok_or(WebSocketReplayError::MessageNotFound)?;
        let mut reader = File::open(entry.path.as_ref())
            .await
            .context("open indexed WebSocket replay capture")
            .map_err(WebSocketReplayError::InvalidCapture)?;
        let record = read_record_at(
            &mut reader,
            location,
            &self.0.key,
            entry.summary_template.id,
        )
        .await
        .map_err(WebSocketReplayError::InvalidCapture)?;
        let StoredRecord::WebSocketMessage {
            direction,
            kind,
            data: encoded,
            ..
        } = record
        else {
            return Err(WebSocketReplayError::MessageNotFound);
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
        self.record_websocket_message_inner(
            id,
            format!("{direction:?}"),
            kind,
            data,
            None,
            WebSocketMessageOrigin::Replay,
        )
        .await;
        Ok(())
    }

    pub(super) async fn send_websocket_message(
        &self,
        id: u64,
        direction: &str,
        kind: &str,
        payload: &str,
    ) -> Result<(), WebSocketReplayError> {
        let Some(entry) = self.0.exchanges.read().entries.get(&id).cloned() else {
            return Err(WebSocketReplayError::CaptureNotFound);
        };
        let direction = match direction {
            "ingress" => WebSocketRelayDirection::Ingress,
            "egress" => WebSocketRelayDirection::Egress,
            _ => {
                return Err(WebSocketReplayError::InvalidMessage(
                    "direction must be ingress or egress".to_owned(),
                ));
            }
        };
        let (kind, data, message) = match kind {
            "text" => {
                let data = payload.as_bytes().to_vec();
                (
                    "text".to_owned(),
                    data,
                    WebSocketRelayMessage::Text(payload.to_owned().into()),
                )
            }
            "binary" => {
                let data = BASE64.decode(payload.trim()).map_err(|error| {
                    WebSocketReplayError::InvalidMessage(format!(
                        "binary payload must be base64: {error}"
                    ))
                })?;
                (
                    "binary".to_owned(),
                    data.clone(),
                    WebSocketRelayMessage::Binary(Bytes::from(data)),
                )
            }
            _ => {
                return Err(WebSocketReplayError::InvalidMessage(
                    "kind must be text or binary".to_owned(),
                ));
            }
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
        self.record_websocket_message_inner(
            id,
            format!("{direction:?}"),
            kind,
            data,
            None,
            WebSocketMessageOrigin::Injected,
        )
        .await;
        Ok(())
    }

    pub(super) async fn record_replay_result(&self, id: u64, result: Result<u16, String>) {
        let Some(_permit) = self.0.inspection.try_capture() else {
            return;
        };
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

    pub(super) fn connection_summary(&self, id: u64) -> Option<ConnectionSummary> {
        let mut summary = self
            .0
            .connections
            .read()
            .entries
            .get(&id)
            .filter(|connection| connection.confirmed.load(Ordering::Relaxed))
            .map(|connection| connection.snapshot())?;
        let states = self.connection_exchange_states();
        reconcile_connection_summary(&mut summary, states.get(&id));
        Some(summary)
    }

    fn connection_exchange_states(&self) -> BTreeMap<u64, ConnectionExchangeState> {
        let exchanges = self.0.exchanges.read();
        let mut states = BTreeMap::<u64, ConnectionExchangeState>::new();
        for exchange in exchanges.entries.values() {
            let state = states
                .entry(exchange.summary_template.connection_id)
                .or_default();
            state.active |= exchange.active.load(Ordering::Relaxed);
            if let Some(completed_at) = exchange.completed_at.get() {
                state.completed_at = Some(match state.completed_at.take() {
                    Some(latest) => std::cmp::max(latest, completed_at.clone()),
                    None => completed_at.clone(),
                });
            }
        }
        states
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

        let connection_exchange_states = self.connection_exchange_states();
        let connections = self.0.connections.read();
        let mut connection_summaries =
            Vec::with_capacity(connection_limit.min(connections.entries.len()));
        let mut total_connections = 0;
        let mut active_connections = 0;
        let mut bytes_in = 0_u64;
        let mut bytes_out = 0_u64;
        for connection in connections.entries.values().rev() {
            if !connection.confirmed.load(Ordering::Relaxed) {
                continue;
            }
            let mut summary = connection.snapshot();
            let connection_id = summary.id;
            reconcile_connection_summary(
                &mut summary,
                connection_exchange_states.get(&connection_id),
            );
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
        let metadata_locations = entry.metadata_records.read().clone();
        let websocket_locations = entry.websocket_records.read().clone();
        let websocket_total = websocket_locations.len();
        let mut reader = File::open(entry.path.as_ref())
            .await
            .context("open indexed encrypted capture")?;
        let mut records =
            Vec::with_capacity(metadata_locations.len() + websocket_page_size.min(websocket_total));
        for location in metadata_locations {
            records.push(
                read_record_at(
                    &mut reader,
                    location,
                    &self.0.key,
                    entry.summary_template.id,
                )
                .await?,
            );
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
        for location in &websocket_locations[start..end] {
            records.push(
                read_record_at(
                    &mut reader,
                    *location,
                    &self.0.key,
                    entry.summary_template.id,
                )
                .await?,
            );
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
        let locations = match body {
            CapturedBody::Request => entry.request_body_records.read().clone(),
            CapturedBody::Response => entry.response_body_records.read().clone(),
        };
        let mut reader = File::open(entry.path.as_ref())
            .await
            .context("open indexed encrypted body capture")?;
        let key = self.0.key;
        Ok(stream_fn(move |mut yielder| async move {
            let _entry = entry;
            let mut emitted = 0_u64;
            for location in locations {
                let record = match read_record_at(&mut reader, location, &key, id).await {
                    Ok(record) => record,
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
        let location = entry.websocket_records.read().get(message_index).copied();
        let mut reader = File::open(entry.path.as_ref())
            .await
            .context("open indexed WebSocket capture")?;
        let key = self.0.key;
        Ok(stream_fn(move |mut yielder| async move {
            let _entry = entry;
            let Some(location) = location else { return };
            let result = async {
                let record = read_record_at(&mut reader, location, &key, id).await?;
                let StoredRecord::WebSocketMessage { data, .. } = record else {
                    return Err::<Bytes, BoxError>(
                        std::io::Error::other("indexed record is not a WebSocket message").into(),
                    );
                };
                Ok(Bytes::from(
                    BASE64
                        .decode(data)
                        .context("decode captured WebSocket message")?,
                ))
            }
            .await;
            yielder.yield_item(result).await;
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
        let mut capture_file = entry.file.lock().await;
        capture_file
            .file
            .flush()
            .await
            .context("flush encrypted capture")?;
        let snapshot_len = capture_file.len;
        drop(capture_file);
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
                    tls_client_hello,
                    ..
                } => head = Some((method, url, version, headers, tls_client_hello)),
                StoredRecord::RequestBody { data } => body.extend(
                    BASE64
                        .decode(data)
                        .context("decode captured request body")?,
                ),
                _ => {}
            }
        }
        let (method, mut url, version, headers, tls_client_hello) =
            head.context("captured request head missing")?;
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
            protocol: details.summary.protocol,
            headers,
            body,
            tls_client_hello,
        })
    }

    pub(super) fn selected_exchange_ids(
        &self,
        request_ids: &BTreeSet<u64>,
        connection_ids: &BTreeSet<u64>,
    ) -> BTreeSet<u64> {
        self.0
            .exchanges
            .read()
            .entries
            .values()
            .filter_map(|entry| {
                let summary = &entry.summary_template;
                (request_ids.contains(&summary.id)
                    || connection_ids.contains(&summary.connection_id))
                .then_some(summary.id)
            })
            .collect()
    }

    pub(super) async fn export_profiles(
        &self,
        request_ids: &BTreeSet<u64>,
        connection_ids: &BTreeSet<u64>,
    ) -> Result<Value, BoxError> {
        let selected_requests = self.selected_exchange_ids(request_ids, connection_ids);

        let mut profiles = BTreeMap::<String, UserAgentProfileInput>::new();
        for request_id in selected_requests {
            let Ok(details) = self.details(request_id).await else {
                continue;
            };
            if let Some(profile) = captured_emulation_profile(&details)? {
                if let Some(existing) = profiles.get_mut(&profile.uastr) {
                    existing.merge_missing(profile)?;
                } else {
                    profiles.insert(profile.uastr.clone(), profile);
                }
            }
        }
        serde_json::to_value(profiles.into_values().collect::<Vec<_>>())
            .context("encode captured user-agent profiles")
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

async fn read_record_at(
    reader: &mut File,
    location: RecordLocation,
    key: &[u8; 32],
    id: u64,
) -> Result<StoredRecord, BoxError> {
    reader
        .seek(std::io::SeekFrom::Start(location.offset))
        .await
        .context("seek encrypted capture record")?;
    let mut remaining = location.len;
    read_record(reader, &mut remaining, key, id)
        .await?
        .context("indexed capture record missing")
}

fn captured_profile(
    parts: &rama::http::request::Parts,
    user_agent: Option<&str>,
    tls_client_hello: Option<ClientHello>,
    h2_settings: Option<Http2Settings>,
    websocket: bool,
) -> Option<Value> {
    let mut profile = UserAgentProfileInput::new(user_agent?);
    profile.tls_client_hello = tls_client_hello;
    let request_initiator = captured_request_initiator(parts, websocket);
    if parts.version == rama::http::Version::HTTP_2 {
        profile.h2_settings = h2_settings;
        match request_initiator {
            Some(RequestInitiator::Navigate) => {
                profile.h2_headers_navigate = Some(parts.headers.clone())
            }
            Some(RequestInitiator::Fetch) => profile.h2_headers_fetch = Some(parts.headers.clone()),
            Some(RequestInitiator::Xhr) => profile.h2_headers_xhr = Some(parts.headers.clone()),
            Some(RequestInitiator::Form) => profile.h2_headers_form = Some(parts.headers.clone()),
            Some(RequestInitiator::Ws) => profile.h2_headers_ws = Some(parts.headers.clone()),
            None => {}
        }
    } else {
        profile.h1_settings = Some(Http1Settings {
            title_case_headers: headers_are_title_case(&parts.headers),
        });
        match request_initiator {
            Some(RequestInitiator::Navigate) => {
                profile.h1_headers_navigate = Some(parts.headers.clone())
            }
            Some(RequestInitiator::Fetch) => profile.h1_headers_fetch = Some(parts.headers.clone()),
            Some(RequestInitiator::Xhr) => profile.h1_headers_xhr = Some(parts.headers.clone()),
            Some(RequestInitiator::Form) => profile.h1_headers_form = Some(parts.headers.clone()),
            Some(RequestInitiator::Ws) => profile.h1_headers_ws = Some(parts.headers.clone()),
            None => {}
        }
    }
    serde_json::to_value(profile).ok()
}

fn is_websocket_handshake(parts: &rama::http::request::Parts) -> bool {
    match parts.version {
        rama::http::Version::HTTP_10 | rama::http::Version::HTTP_11 => parts
            .headers
            .get("upgrade")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket")),
        rama::http::Version::HTTP_2 => {
            parts.method == rama::http::Method::CONNECT
                && parts
                    .extensions
                    .get_ref::<rama::http::proto::h2::ext::Protocol>()
                    .is_some_and(|protocol| {
                        protocol.as_str().trim().eq_ignore_ascii_case("websocket")
                    })
        }
        _ => false,
    }
}

fn captured_request_initiator(
    parts: &rama::http::request::Parts,
    websocket: bool,
) -> Option<RequestInitiator> {
    if websocket {
        return Some(RequestInitiator::Ws);
    }
    if let Some(initiator) = parts.extensions.get_ref::<RequestInitiator>() {
        return Some(*initiator);
    }
    if parts
        .headers
        .get("x-requested-with")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("xmlhttprequest"))
    {
        return Some(RequestInitiator::Xhr);
    }
    if !parts
        .headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("navigate"))
    {
        return None;
    }
    let is_form = parts
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(';').next().is_some_and(|mime| {
                matches!(
                    mime.trim().to_ascii_lowercase().as_str(),
                    "application/x-www-form-urlencoded" | "multipart/form-data"
                )
            })
        });
    Some(if is_form {
        RequestInitiator::Form
    } else {
        RequestInitiator::Navigate
    })
}

fn headers_are_title_case(headers: &HeaderMap) -> bool {
    !headers.is_empty()
        && headers.keys().all(|name| {
            name.as_original_str().split('-').all(|part| {
                part.chars().next().is_none_or(|c| c.is_ascii_uppercase())
                    && part.chars().skip(1).all(|c| c.is_ascii_lowercase())
            })
        })
}

fn known_fingerprint_label(
    database: &UserAgentDatabase,
    user_agent: Option<&str>,
    parts: &rama::http::request::Parts,
    ja3: Option<&str>,
    ja4: Option<&str>,
    peetprint: Option<&str>,
    ja4h: Option<&str>,
) -> Option<String> {
    let profile = database.get_exact_header_str(user_agent?)?;
    let tls_matches = ja3.is_some_and(|actual| {
        profile
            .tls
            .compute_ja3(None)
            .is_ok_and(|expected| expected.hash() == actual)
    }) || ja4.is_some_and(|actual| {
        profile
            .tls
            .compute_ja4(None)
            .is_ok_and(|expected| expected.to_string() == actual)
    }) || peetprint.is_some_and(|actual| {
        profile
            .tls
            .compute_peet()
            .is_ok_and(|expected| expected.to_string() == actual)
    });
    let method = Some(parts.method.clone());
    let http_matches = ja4h.is_some_and(|actual| {
        let fingerprints = if parts.version == rama::http::Version::HTTP_2 {
            [
                Some(profile.http.ja4h_h2_navigate(method.clone())),
                profile.http.ja4h_h2_fetch(method.clone()),
                profile.http.ja4h_h2_xhr(method.clone()),
                profile.http.ja4h_h2_form(method),
            ]
        } else {
            [
                Some(profile.http.ja4h_h1_navigate(method.clone())),
                profile.http.ja4h_h1_fetch(method.clone()),
                profile.http.ja4h_h1_xhr(method.clone()),
                profile.http.ja4h_h1_form(method),
            ]
        };
        fingerprints
            .into_iter()
            .flatten()
            .any(|fingerprint| fingerprint.is_ok_and(|expected| expected.to_string() == actual))
    });
    (tls_matches || http_matches).then(|| {
        profile
            .ua_version
            .map(|version| format!("{} {version}", profile.ua_kind))
            .unwrap_or_else(|| profile.ua_kind.to_string())
    })
}

fn captured_emulation_profile(
    details: &CaptureDetails,
) -> Result<Option<UserAgentProfileInput>, BoxError> {
    details
        .records
        .iter()
        .find_map(|record| match record {
            StoredRecord::RequestHead {
                emulation_profile, ..
            } => emulation_profile.as_ref(),
            _ => None,
        })
        .map(|profile| {
            serde_json::from_value(profile.clone()).context("decode captured user-agent profile")
        })
        .transpose()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebSocketMessageOrigin {
    Peer,
    Replay,
    Injected,
}

mod service;

pub(super) use service::{
    CaptureHttpLayer, CaptureWebSocketLayer, MarkProtocolLayer, ObserveConnectionLayer,
};

#[cfg(test)]
#[path = "capture/tests.rs"]
mod tests;
