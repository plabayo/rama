mod api;
mod controller;
mod downloads;
mod exports;
mod format;
mod live;
mod navigation;
mod recording;
mod render;
mod replay;

#[cfg(test)]
mod tests;

#[cfg(test)]
use std::ops::DerefMut;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    fmt,
    ops::Deref,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use controller::*;
use downloads::*;
use exports::*;
use format::*;
use live::*;
use navigation::*;
use parking_lot::RwLock;
use rama::{
    Layer, Service,
    bytes::Bytes,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef as _,
    futures::async_stream::stream_fn,
    http::{
        Body, Method, Request, Response, StatusCode,
        body::util::BodyExt as _,
        convert::curl,
        headers::{
            CacheControl, ContentDisposition, ContentLength, ContentType, SourceList,
            XContentTypeOptions,
        },
        inspect::capture::{ConnectionQuery, FilterValue, ProtocolQuery, StatusQuery},
        layer::remove_header::{
            RemoveRequestHeaderLayer, remove_hop_by_hop_request_headers,
            remove_proxy_auth_request_headers,
        },
        protocols::html::*,
        service::web::{
            Router,
            extract::{Path, Query, State, datastar::ReadSignals},
            response::{
                Css, DatastarScript, DatastarSourceMap, Headers, IntoResponse, Json, OctetStream,
                Script, Sse, Svg,
            },
        },
        sse::{
            Event,
            datastar::PatchElements,
            server::{KeepAlive, KeepAliveStream},
        },
        ws::{
            handshake::mitm::{WebSocketRelayDirection, WebSocketRelayMessage},
            inspect::{
                WebSocketDetails, WebSocketMessageKind, WebSocketMessageOrigin,
                WebSocketMessagePreview,
            },
        },
    },
    inspect::InspectionState,
    net::{Protocol, socket::SocketOptions},
    rt::Executor,
    service::BoxService,
    stream::io::ReaderStream,
    tls::{
        boring::client::EmulateTlsProfileLayer,
        inspect::{CapturedTlsParameters, TlsObservation},
    },
    ua::{inspect::UserAgentObservation, profile::TlsProfile},
    utils::{
        octets::{kib, kib_u64, mib},
        str::{NonEmptyStr, arcstr::ArcStr},
    },
};
use recording::*;
use render::*;
use replay::*;
use serde::Deserialize;
use tokio::sync::{Mutex, Semaphore, watch};

use super::{
    capture::{
        CaptureDetails, CaptureFilter, CaptureHttpLayer, CaptureSnapshot, CaptureStore,
        CaptureWebSocketExt, CapturedBody, ConnectionId, HttpConnectionSummary,
        HttpExchangeSummary, ReplayRequest, StoredRecord, WebSocketReplayError,
    },
    control::PendingSummary,
    har::{HarController, HarDownload, export_selected},
    mitm_policy::MitmPolicy,
    upstream::UpstreamProxyConfig,
};
use crate::cmd::serve::proxy::{
    control::{Config as ControlConfig, Decision},
    mitm_policy::ScopeMode,
};

const WS_TEXT_PREVIEW_LIMIT: usize = kib(16);
const WS_BINARY_PREVIEW_LIMIT: usize = 256;
const MAX_VISIBLE_WS_MESSAGES: usize = 100;
const MAX_BODY_PREVIEW_LIMIT: u64 = kib_u64(64);
const MAX_UI_SESSIONS: usize = 256;
const MAX_UI_EVENT_STREAMS: usize = MAX_UI_SESSIONS;
const MAX_VISIBLE_CONNECTIONS: usize = 100;
const MAX_VISIBLE_EXCHANGES: usize = 250;
const MAX_DASHBOARD_REQUEST_BODY: usize = mib(1);
const REPLAY_PROTOCOL: Protocol = Protocol::from_static("replay");

#[cfg(not(test))]
const LIVE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const LIVE_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(20);
const RAMA_LOGO_SVG: &str = include_str!("../../../../../../docs/img/rama_logo.svg");
const HAR_JS: &str = include_str!("../dashboard-har.js");
const DETAILS_JS: &str = include_str!("../dashboard-details.js");
const LIVE_JS: &str = include_str!("../dashboard-live.js");
const CONTROL_JS: &str = include_str!("../dashboard-control.js");
const CONTROL_HTML: &str = include_str!("../dashboard-control.html");
const PREFERENCES_JS: &str = include_str!("../dashboard-preferences.js");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum UiFocus {
    #[default]
    Overview,
    Connection(u64),
    Request(u64),
}

#[derive(Debug, Clone, Default)]
struct UiSession {
    created_sequence: u64,
    filter: CaptureFilter,
    selected: BTreeSet<u64>,
    selected_connections: BTreeSet<u64>,
    websocket_pages: BTreeMap<u64, usize>,
    connection_page: usize,
    connection_cursors: Vec<Option<u64>>,
    next_connection_cursor: Option<u64>,
    focus: UiFocus,
}

struct LiveStatus {
    recording: bool,
    pending: Vec<PendingSummary>,
}

impl LiveStatus {
    fn for_exchange(&self, id: u64) -> impl Iterator<Item = &PendingSummary> {
        self.pending
            .iter()
            .filter(move |message| message.exchange == Some(id))
    }
}

#[derive(Debug, Clone)]
pub(super) struct DashboardState {
    #[cfg(test)]
    render_delay: Duration,
    capture: CaptureStore,
    inspection: InspectionState,
    recording_transition: Arc<Mutex<()>>,
    har: HarController,
    sessions: Arc<RwLock<BTreeMap<String, UiSession>>>,
    next_session_sequence: Arc<AtomicU64>,
    event_streams: Arc<Semaphore>,
    export_limit: Option<Arc<Semaphore>>,
    ui_changes: watch::Sender<u64>,
    ca_pem: Arc<Vec<u8>>,
    replay_client: BoxService<Request, Response, BoxError>,
    mitm_policy: MitmPolicy,
}

impl DashboardState {
    pub(super) fn new(
        capture: CaptureStore,
        har: HarController,
        ca_pem: Vec<u8>,
        tcp_options: Arc<SocketOptions>,
        upstream: &UpstreamProxyConfig,
        mitm_policy: MitmPolicy,
    ) -> Result<Self, BoxError> {
        let (ui_changes, _) = watch::channel(0);
        let inspection = capture.inspection_state();
        let replay_client = replay_client(capture.clone(), tcp_options, upstream)?;
        Ok(Self {
            #[cfg(test)]
            render_delay: Duration::ZERO,
            capture,
            inspection,
            recording_transition: Arc::new(Mutex::new(())),
            har,
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            next_session_sequence: Arc::new(AtomicU64::new(1)),
            event_streams: Arc::new(Semaphore::new(MAX_UI_EVENT_STREAMS)),
            export_limit: None,
            ui_changes,
            ca_pem: Arc::new(ca_pem),
            replay_client,
            mitm_policy,
        })
    }

    pub(super) fn with_export_limit(mut self, limit: usize) -> Result<Self, BoxError> {
        if limit > Semaphore::MAX_PERMITS {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "inspector export concurrency exceeds the semaphore capacity",
            )
            .into());
        }
        self.export_limit = (limit != 0).then(|| Arc::new(Semaphore::new(limit)));
        Ok(self)
    }

    fn notify(&self) {
        self.ui_changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    fn ensure_session(&self, id: &str) {
        let mut sessions = self.sessions.write();
        if sessions.contains_key(id) {
            return;
        }
        let mut evicted = false;
        if sessions.len() >= MAX_UI_SESSIONS
            && let Some(oldest) = sessions
                .iter()
                .min_by_key(|(_, session)| session.created_sequence)
                .map(|(id, _)| id.clone())
        {
            sessions.remove(&oldest);
            evicted = true;
        }
        sessions.insert(
            id.to_owned(),
            UiSession {
                created_sequence: self.next_session_sequence.fetch_add(1, Ordering::Relaxed),
                ..UiSession::default()
            },
        );
        drop(sessions);
        if evicted {
            self.notify();
        }
    }

    fn session(&self, id: &str) -> UiSession {
        self.sessions.read().get(id).cloned().unwrap_or_default()
    }

    fn has_session(&self, id: &str) -> bool {
        self.sessions.read().contains_key(id)
    }

    async fn render_live(&self, session_id: &str, heartbeat_sequence: u64) -> String {
        #[cfg(test)]
        tokio::time::sleep(self.render_delay).await;
        let mut session = self.session(session_id);
        let focused_connections = match session.focus {
            UiFocus::Connection(id) => BTreeSet::from([id]),
            UiFocus::Overview | UiFocus::Request(_) => session.selected_connections.clone(),
        };
        let filter = if matches!(session.focus, UiFocus::Connection(_)) {
            CaptureFilter::default()
        } else {
            session.filter.clone()
        };
        let mut snapshot = self
            .capture
            .snapshot_limited_before_connection(
                &filter,
                &focused_connections,
                if matches!(session.focus, UiFocus::Overview) {
                    session
                        .connection_cursors
                        .get(session.connection_page)
                        .copied()
                        .flatten()
                } else {
                    None
                },
                MAX_VISIBLE_CONNECTIONS,
                MAX_VISIBLE_EXCHANGES,
            )
            .await;
        if matches!(session.focus, UiFocus::Overview)
            && snapshot.connections.is_empty()
            && snapshot.total_connections > 0
            && session.connection_page > 0
        {
            session.connection_page = 0;
            session.connection_cursors.clear();
            if let Some(stored) = self.sessions.write().get_mut(session_id) {
                stored.connection_page = 0;
                stored.connection_cursors.clear();
            }
            snapshot = self
                .capture
                .snapshot_limited_before_connection(
                    &filter,
                    &focused_connections,
                    None,
                    MAX_VISIBLE_CONNECTIONS,
                    MAX_VISIBLE_EXCHANGES,
                )
                .await;
        }
        if matches!(session.focus, UiFocus::Overview) {
            session.next_connection_cursor = snapshot.next_connection_cursor;
            if let Some(stored) = self.sessions.write().get_mut(session_id) {
                stored.next_connection_cursor = snapshot.next_connection_cursor;
            }
        }
        if let UiFocus::Connection(id) = session.focus
            && !snapshot
                .connections
                .iter()
                .any(|connection| connection.id == id)
            && let Some(connection) = self.capture.connection_summary(id)
        {
            snapshot.connections.push(connection);
        }
        let har = self.har.status();
        let inspection_enabled = self.inspection.is_enabled();
        let mut details = BTreeMap::new();
        let focused_detail_id = match session.focus {
            UiFocus::Request(id) => Some(id),
            UiFocus::Connection(connection_id) => snapshot
                .exchanges
                .iter()
                .find(|exchange| {
                    exchange.connection_id == connection_id && exchange.protocol.is_secure()
                })
                .map(|exchange| exchange.id),
            UiFocus::Overview => None,
        };
        if let Some(id) = focused_detail_id
            && !details.contains_key(&id)
        {
            let page = session
                .websocket_pages
                .get(&id)
                .copied()
                .unwrap_or_default();
            if let Ok(detail) = self
                .capture
                .inspector_view(id, page, MAX_VISIBLE_WS_MESSAGES)
                .await
            {
                details.insert(id, detail);
            }
        }
        let mut pending = self.capture.control().pending_summaries();
        for message in &mut pending {
            message.connection_display_id = self.capture.connection_display_id(message.connection);
        }
        render_live_panel(
            session_id,
            heartbeat_sequence,
            &snapshot,
            &session,
            &details,
            &har,
            &LiveStatus {
                recording: inspection_enabled,
                pending,
            },
        )
    }
}

#[derive(Clone)]
pub(super) struct DashboardService {
    inner: BoxService<Request, Response, Infallible>,
}

impl fmt::Debug for DashboardService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DashboardService").finish_non_exhaustive()
    }
}

impl Service<Request> for DashboardService {
    type Output = Response;
    type Error = Infallible;

    async fn serve(&self, request: Request) -> Result<Self::Output, Self::Error> {
        self.inner.serve(request).await
    }
}

pub(super) fn service(state: DashboardState) -> DashboardService {
    let router = Router::new_with_state(state)
        .with_get("/api", api::discovery)
        .with_get("/api/help", api::help)
        .with_get("/api/captures", api::captures)
        .with_get("/api/captures/events", api::capture_events)
        .with_get("/", index)
        .with_get("/events", events)
        .with_post("/api/filter", update_filter)
        .with_post("/api/filter/reset", reset_filters)
        .with_post("/api/mitm-policy", update_mitm_policy)
        .with_get("/api/control", control_state)
        .with_get("/api/control/pending/{id}", control_pending)
        .with_get("/api/control/from/{id}", control_from_capture)
        .with_post("/api/control/config", control_config)
        .with_post("/api/control/forward-all", control_forward_all)
        .with_post("/api/control/decision", control_decision)
        .with_post("/api/control/resume/{id}", control_resume)
        .with_post("/api/control/hosts/clear", control_clear_hosts)
        .with_get("/assets/control.js", Script(CONTROL_JS))
        .with_post("/api/inspection/pause", pause_inspection)
        .with_post("/api/inspection/resume", resume_inspection)
        .with_post("/api/captures/clear", clear_captures)
        .with_post("/api/connection/{id}", toggle_connection)
        .with_post("/api/connections/clear", clear_connections)
        .with_post("/api/connections/older", older_connections)
        .with_post("/api/connections/newer", newer_connections)
        .with_post("/api/focus/clear", clear_focus)
        .with_post("/api/focus/connection/{id}", focus_connection)
        .with_post("/api/focus/request/{id}", focus_request)
        .with_post("/api/websocket/{id}/older", older_websocket_messages)
        .with_post("/api/websocket/{id}/newer", newer_websocket_messages)
        .with_post(
            "/api/websocket/{id}/replay/{index}",
            replay_websocket_message,
        )
        .with_post("/api/websocket/{id}/send", send_websocket_message)
        .with_post("/api/select/{id}", toggle_selected)
        .with_post("/api/replay/{id}", replay)
        .with_get("/api/capture/{id}/curl", request_curl)
        .with_get("/api/capture/{id}/body/{direction}", capture_body)
        .with_get(
            "/api/capture/{id}/websocket/{index}",
            capture_websocket_message,
        )
        .with_get("/api/profiles.json", export_profiles)
        .with_get("/api/har/export", export_har)
        .with_get("/ca.pem", download_ca)
        .with_post("/api/har/start", start_har)
        .with_post("/api/har/stop", stop_har)
        .with_get("/assets/style.css", Css(STYLE_CSS))
        .with_get("/assets/har.js", Script(HAR_JS))
        .with_get("/assets/details.js", Script(DETAILS_JS))
        .with_get("/assets/live.js", Script(LIVE_JS))
        .with_get("/assets/preferences.js", Script(PREFERENCES_JS))
        .with_get("/assets/rama-logo.svg", rama_logo)
        .with_get("/assets/datastar.js", DatastarScript::default())
        .with_get("/assets/datastar.js.map", DatastarSourceMap::default());
    let router = rama::http::layer::error_handling::ErrorHandler::new(router);
    // Match AudioPress' Datastar CSP: the same-origin runtime evaluates
    // declarative `data-*` expressions via `Function()`, so it requires
    // `unsafe-eval`; inline and third-party scripts remain forbidden.
    let csp = rama::cli::service::http_security::rama_html_csp()
        .with_script_src(SourceList::self_origin().with_unsafe_eval())
        .with_connect_src(SourceList::self_origin());
    let service = rama::http::layer::body_limit::BodyLimitLayer::new(MAX_DASHBOARD_REQUEST_BODY)
        .into_layer(Arc::new(router));
    let service =
        rama::cli::service::http_security::defence_in_depth_layer(csp).into_layer(service);
    DashboardService {
        inner: BoxService::new(service),
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct UiSignals {
    session: Option<NonEmptyStr>,
    search: ArcStr,
    connection_id: FilterValue<ConnectionQuery>,
    user_agent: ArcStr,
    endpoint: ArcStr,
    method: FilterValue<Method>,
    status: FilterValue<StatusQuery>,
    protocol: FilterValue<ProtocolQuery>,
    websocket_direction: Option<WebSocketRelayDirection>,
    websocket_kind: Option<WebSocketSendKind>,
    websocket_payload: String,
}

/// Application messages the inspector may inject into a WebSocket relay.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WebSocketSendKind {
    Text,
    Binary,
}

#[derive(Debug, Deserialize)]
struct MitmPolicyUpdate {
    #[serde(default)]
    session: Option<NonEmptyStr>,
    allow: Vec<String>,
    deny: Vec<String>,
    #[serde(default)]
    mode: ScopeMode,
}

#[derive(Debug, Deserialize)]
struct StartHarQuery {
    #[serde(default)]
    session: Option<NonEmptyStr>,
    file_name: String,
}

#[derive(Debug, Deserialize)]
struct HarSessionQuery {
    #[serde(default)]
    session: Option<NonEmptyStr>,
}

#[derive(Debug, Deserialize)]
struct IdPath {
    id: u64,
}

#[derive(Debug, Deserialize)]
struct BodyPath {
    id: u64,
    direction: String,
}

#[derive(Debug, Deserialize)]
struct WebSocketMessagePath {
    id: u64,
    index: usize,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BodyQuery {
    limit: Option<u64>,
    download: bool,
}

#[derive(Debug, Deserialize)]
struct ExportQuery {
    session: Option<NonEmptyStr>,
    ids: Option<String>,
    connection_ids: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FocusQuery {
    connection: Option<u64>,
    request: Option<u64>,
}

#[derive(Deserialize)]
struct ControlQuery {
    #[serde(default)]
    session: Option<NonEmptyStr>,
}

#[derive(Deserialize)]
struct ControlConfigUpdate {
    #[serde(default)]
    session: Option<NonEmptyStr>,
    revision: u64,
    config: ControlConfig,
    apply_rule: Option<usize>,
}

#[derive(Deserialize)]
struct ControlDecision {
    #[serde(default)]
    session: Option<NonEmptyStr>,
    ids: Vec<u64>,
    decision: Decision,
}

const STYLE_CSS: &str = include_str!("../dashboard.css");

struct InspectorDetails {
    http: CaptureDetails,
    websocket: WebSocketDetails<WebSocketMessagePreview>,
}

impl Deref for InspectorDetails {
    type Target = CaptureDetails;

    fn deref(&self) -> &Self::Target {
        &self.http
    }
}

#[cfg(test)]
impl DerefMut for InspectorDetails {
    fn deref_mut(&mut self) -> &mut CaptureDetails {
        &mut self.http
    }
}

trait InspectorView {
    async fn inspector_view(
        &self,
        id: u64,
        page: usize,
        page_size: usize,
    ) -> Result<InspectorDetails, BoxError>;
}

impl InspectorView for CaptureStore {
    async fn inspector_view(
        &self,
        id: u64,
        page: usize,
        page_size: usize,
    ) -> Result<InspectorDetails, BoxError> {
        let exchange = self.exchange_capture(id)?;
        let mut http = exchange.inspector_details().await?;
        http.records
            .extend(exchange.message_interceptions(page).await?);
        Ok(InspectorDetails {
            http,
            websocket: rama::http::ws::inspect::read_preview_details(
                &exchange,
                page,
                page_size,
                |metadata| {
                    if matches!(
                        metadata.kind,
                        WebSocketMessageKind::Text | WebSocketMessageKind::Close
                    ) {
                        WS_TEXT_PREVIEW_LIMIT
                    } else {
                        WS_BINARY_PREVIEW_LIMIT
                    }
                },
            )
            .await?,
        })
    }
}

fn optional_display<T: fmt::Display>(value: Option<&T>) -> impl fmt::Display + '_ {
    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| match value {
        Some(value) => write!(f, "{value}"),
        None => f.write_str("unknown"),
    })
}
