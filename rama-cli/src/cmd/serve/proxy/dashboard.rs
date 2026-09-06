use super::{
    capture::{
        CaptureFilter, CaptureHttpLayer, CaptureSnapshot, CaptureStore, CapturedBody,
        CapturedTlsParameters, ConnectionId, ConnectionSummary, ExchangeSummary, InspectorDetails,
        ReplayRequest, StoredRecord, WebSocketReplayError, captured_header_value,
        captured_http_version,
    },
    control::PendingSummary,
    har::{HarController, HarDownload, export_selected},
    inspection::InspectionState,
    mitm_policy::MitmPolicy,
    upstream::UpstreamProxyConfig,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
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
        headers::SourceList,
        layer::remove_header::{
            RemoveRequestHeaderLayer, remove_hop_by_hop_request_headers,
            remove_proxy_auth_request_headers,
        },
        protocols::html::*,
        service::web::{
            Router,
            extract::{Path, Query, State, datastar::ReadSignals},
            response::{
                Css, DatastarScript, DatastarSourceMap, Html, IntoResponse, Json, Script, Sse,
            },
        },
        sse::{
            Event,
            datastar::PatchElements,
            server::{KeepAlive, KeepAliveStream},
        },
    },
    net::socket::SocketOptions,
    rt::Executor,
    service::BoxService,
    stream::io::ReaderStream,
    tls::boring::client::EmulateTlsProfileLayer,
    ua::profile::{TlsProfile, UserAgentDatabase},
    utils::octets::{kib, kib_u64, mib},
    utils::str::NonEmptyStr,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, watch};

const WS_TEXT_PREVIEW_LIMIT: usize = kib(16);
const WS_BINARY_PREVIEW_LIMIT: usize = 256;
const MAX_VISIBLE_WS_MESSAGES: usize = 100;
const MAX_BODY_PREVIEW_LIMIT: u64 = kib_u64(64);
const MAX_UI_SESSIONS: usize = 256;
const MAX_UI_EVENT_STREAMS: usize = MAX_UI_SESSIONS;
const MAX_VISIBLE_CONNECTIONS: usize = 100;
const MAX_VISIBLE_EXCHANGES: usize = 250;
const MAX_DASHBOARD_REQUEST_BODY: usize = mib(1);
#[cfg(not(test))]
const LIVE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const LIVE_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(20);
const RAMA_LOGO_SVG: &str = include_str!("../../../../../docs/img/rama_logo.svg");
const HAR_JS: &str = include_str!("dashboard-har.js");
const DETAILS_JS: &str = include_str!("dashboard-details.js");
const LIVE_JS: &str = include_str!("dashboard-live.js");
const CONTROL_JS: &str = include_str!("dashboard-control.js");
const CONTROL_HTML: &str = include_str!("dashboard-control.html");
const PREFERENCES_JS: &str = include_str!("dashboard-preferences.js");

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
    capture: CaptureStore,
    inspection: InspectionState,
    recording_transition: Arc<tokio::sync::Mutex<()>>,
    har: HarController,
    sessions: Arc<RwLock<BTreeMap<String, UiSession>>>,
    next_session_sequence: Arc<AtomicU64>,
    event_streams: Arc<Semaphore>,
    ui_changes: watch::Sender<u64>,
    ca_pem: Arc<Vec<u8>>,
    tcp_options: Arc<SocketOptions>,
    upstream: UpstreamProxyConfig,
    mitm_policy: MitmPolicy,
}

impl DashboardState {
    pub(super) fn new(
        capture: CaptureStore,
        har: HarController,
        ca_pem: Vec<u8>,
        tcp_options: Arc<SocketOptions>,
        upstream: UpstreamProxyConfig,
        mitm_policy: MitmPolicy,
    ) -> Self {
        let (ui_changes, _) = watch::channel(0);
        let inspection = capture.inspection_state();
        Self {
            capture,
            inspection,
            recording_transition: Arc::new(tokio::sync::Mutex::new(())),
            har,
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            next_session_sequence: Arc::new(AtomicU64::new(1)),
            event_streams: Arc::new(Semaphore::new(MAX_UI_EVENT_STREAMS)),
            ui_changes,
            ca_pem: Arc::new(ca_pem),
            tcp_options,
            upstream,
            mitm_policy,
        }
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
        !id.is_empty() && self.sessions.read().contains_key(id)
    }

    async fn render_live(&self, session_id: &str, heartbeat_sequence: u64) -> String {
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
                    exchange.connection_id == connection_id
                        && matches!(exchange.protocol.as_str(), "https" | "wss")
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
                .inspector_details(id, page, MAX_VISIBLE_WS_MESSAGES)
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

impl std::fmt::Debug for DashboardService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
        .with_get("/api/capture/{id}.json", capture_json)
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
    session: String,
    search: String,
    connection_id: String,
    user_agent: String,
    endpoint: String,
    method: String,
    status: String,
    protocol: String,
    websocket_direction: String,
    websocket_kind: String,
    websocket_payload: String,
}

#[derive(Debug, Deserialize)]
struct MitmPolicyUpdate {
    session: String,
    allow: Vec<String>,
    deny: Vec<String>,
    #[serde(default)]
    mode: super::mitm_policy::ScopeMode,
}

#[derive(Debug, Deserialize)]
struct StartHarQuery {
    session: String,
    file_name: String,
}

#[derive(Debug, Deserialize)]
struct HarSessionQuery {
    session: String,
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
    session: Option<String>,
    ids: Option<String>,
    connection_ids: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct FocusQuery {
    connection: Option<u64>,
    request: Option<u64>,
}

async fn index(State(state): State<DashboardState>, Query(query): Query<FocusQuery>) -> Response {
    let mut token = [0_u8; 16];
    if let Err(error) = rama::tls::boring::core::rand::rand_bytes(&mut token) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, error);
    }
    let session = hex::encode(token);
    state.ensure_session(&session);
    if let Some(ui_session) = state.sessions.write().get_mut(&session) {
        ui_session.focus = query
            .request
            .map(UiFocus::Request)
            .or_else(|| query.connection.map(UiFocus::Connection))
            .unwrap_or_default();
    }
    Html(render_index(&session).into_string()).into_response()
}

async fn events(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    let session = signals.session;
    if !state.has_session(&session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(event_stream_permit) = state.event_streams.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let mut capture_changes = state.capture.subscribe();
    let mut ui_changes = state.ui_changes.subscribe();
    let mut control_changes = state.capture.control().subscribe();
    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream_fn(move |mut yielder| async move {
            let _event_stream_permit = event_stream_permit;
            let mut heartbeat = tokio::time::interval(LIVE_HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` ticks immediately once; consume that tick because the
            // initial full render carries heartbeat sequence zero.
            heartbeat.tick().await;
            let mut render_dashboard = true;
            let mut heartbeat_sequence = 0_u64;
            loop {
                if !state.has_session(&session) {
                    break;
                }
                let html = if render_dashboard {
                    state.render_live(&session, heartbeat_sequence).await
                } else {
                    render_live_heartbeat(heartbeat_sequence).into_string()
                };
                match dashboard_patch(html) {
                    Ok(event) => {
                        yielder.yield_item(Ok(event)).await;
                        heartbeat_sequence = heartbeat_sequence.wrapping_add(1);
                    }
                    Err(error) => {
                        yielder.yield_item(Err(error)).await;
                        break;
                    }
                }
                tokio::select! {
                    result = capture_changes.changed() => {
                        if result.is_err() {
                            break;
                        }
                        render_dashboard = true;
                    }
                    result = control_changes.changed() => {
                        if result.is_err() { break; }
                        render_dashboard = true;
                    }
                    result = ui_changes.changed() => {
                        if result.is_err() {
                            break;
                        }
                        render_dashboard = true;
                    }
                    _ = heartbeat.tick() => {
                        render_dashboard = false;
                    }
                }
            }
        }),
    ))
    .into_response()
}

fn dashboard_patch(html: String) -> Result<Event<PatchElements>, BoxError> {
    let html = NonEmptyStr::try_from(html).context("render non-empty dashboard update")?;
    PatchElements::new(html)
        .try_into_sse_event()
        .context("build dashboard Datastar event")
}

fn render_live_heartbeat(sequence: u64) -> impl IntoHtml {
    span!(
        id = "live-heartbeat",
        hidden = "",
        "data-sequence" = sequence.to_string()
    )
}

async fn update_filter(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    session.filter = CaptureFilter {
        search: signals.search,
        connection_id: signals.connection_id,
        user_agent: signals.user_agent,
        endpoint: signals.endpoint,
        method: signals.method,
        status: signals.status,
        protocol: signals.protocol,
    };
    session.connection_page = 0;
    session.connection_cursors.clear();
    session.next_connection_cursor = None;
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn reset_filters(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    session.filter = CaptureFilter::default();
    session.selected_connections.clear();
    session.connection_page = 0;
    session.connection_cursors.clear();
    session.next_connection_cursor = None;
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn update_mitm_policy(
    State(state): State<DashboardState>,
    Json(update): Json<MitmPolicyUpdate>,
) -> Response {
    if !state.has_session(&update.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Err(error) = state
        .mitm_policy
        .update_scope(update.mode, &update.allow, &update.deny)
    {
        return error_response(StatusCode::BAD_REQUEST, error);
    }
    rama::telemetry::tracing::info!(
        allow_rules = update.allow.len(),
        deny_rules = update.deny.len(),
        "updated runtime MITM domain policy"
    );
    state.notify();
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
struct ControlQuery {
    session: String,
}
#[derive(Deserialize)]
struct ControlConfigUpdate {
    session: String,
    revision: u64,
    config: super::control::Config,
    apply_rule: Option<usize>,
}
#[derive(Deserialize)]
struct ControlDecision {
    session: String,
    ids: Vec<u64>,
    decision: super::control::Decision,
}

async fn control_state(
    State(state): State<DashboardState>,
    Query(query): Query<ControlQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut snapshot = state.capture.control().snapshot();
    for message in &mut snapshot.pending {
        message.connection_display_id = state.capture.connection_display_id(message.connection);
    }
    for connection in &mut snapshot.automatic_connections {
        connection.connection_display_id =
            state.capture.connection_display_id(connection.connection);
    }
    for host in &mut snapshot.hosts {
        host.eligible = rama::net::address::Host::try_from(host.host.as_str())
            .is_ok_and(|host| state.mitm_policy.should_inspect_host(&host));
    }
    Json(serde_json::json!({ "control": snapshot, "scope": state.mitm_policy.snapshot() }))
        .into_response()
}
async fn control_pending(
    State(state): State<DashboardState>,
    Path(id): Path<u64>,
    Query(query): Query<ControlQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.capture.control().pending(id) {
        Some(message) => {
            let mut message = message.as_ref().clone();
            message.connection_display_id = state.capture.connection_display_id(message.connection);
            Json(message).into_response()
        }
        None => StatusCode::CONFLICT.into_response(),
    }
}
async fn control_from_capture(
    State(state): State<DashboardState>,
    Path(id): Path<u64>,
    Query(query): Query<ControlQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Ok(details) = state.capture.inspector_details(id, 0, 0).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let url = &details.summary.url;
    let uri = url.parse::<rama::net::uri::Uri>().ok();
    let host = uri
        .as_ref()
        .and_then(|u| u.authority())
        .map(|a| a.host().to_str().into_owned())
        .unwrap_or_else(|| details.summary.endpoint.clone());
    let path = uri
        .as_ref()
        .and_then(|u| u.path())
        .map(|p| p.as_encoded_str().into_owned())
        .unwrap_or_else(|| "/".into());
    Json(serde_json::json!({"host": host, "path": path, "url": url, "method": details.summary.method, "protocol": details.summary.protocol})).into_response()
}
async fn control_config(
    State(state): State<DashboardState>,
    Json(update): Json<ControlConfigUpdate>,
) -> Response {
    if !state.has_session(&update.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if update
        .apply_rule
        .is_some_and(|index| index >= update.config.rules.len())
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match state
        .capture
        .control()
        .configure(update.revision, update.config)
    {
        Ok(()) => {
            if let Some(index) = update.apply_rule
                && let Err(error) = state
                    .capture
                    .control()
                    .apply_rule(index, update.revision + 1)
            {
                return error_response(StatusCode::CONFLICT, error);
            }
            state.notify();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}
async fn control_decision(
    State(state): State<DashboardState>,
    Json(update): Json<ControlDecision>,
) -> Response {
    if !state.has_session(&update.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if update.ids.is_empty() || update.ids.len() > 256 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let results = update
        .ids
        .into_iter()
        .map(|id| {
            let result = state.capture.control().resolve(id, update.decision.clone());
            serde_json::json!({ "id": id, "error": result.err().map(|e| e.to_string()) })
        })
        .collect::<Vec<_>>();
    Json(results).into_response()
}
async fn control_forward_all(
    State(state): State<DashboardState>,
    Json(query): Json<ControlQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.capture.control().stop_and_forward();
    StatusCode::NO_CONTENT.into_response()
}
async fn control_resume(
    State(state): State<DashboardState>,
    Path(id): Path<u64>,
    Json(query): Json<ControlQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.capture.control().resume_connection(id);
    StatusCode::NO_CONTENT.into_response()
}
async fn control_clear_hosts(
    State(state): State<DashboardState>,
    Json(query): Json<ControlQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    state.capture.control().clear_hosts();
    StatusCode::NO_CONTENT.into_response()
}

async fn pause_inspection(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    if !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND;
    }
    let _transition = state.recording_transition.lock().await;
    state.har.pause().await;
    if state.inspection.pause().await {
        state.capture.control().stop_and_forward();
        rama::telemetry::tracing::info!(
            "proxy inspector paused; MITM sessions closed and new traffic passes through"
        );
        state.notify();
    }
    StatusCode::NO_CONTENT
}

async fn resume_inspection(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    if !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND;
    }
    let _transition = state.recording_transition.lock().await;
    if state.inspection.resume().await {
        rama::telemetry::tracing::info!("proxy inspector resumed");
        state.notify();
    }
    StatusCode::NO_CONTENT
}

async fn clear_captures(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    if !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND;
    }
    state.capture.clear().await;
    for session in state.sessions.write().values_mut() {
        session.selected.clear();
        session.selected_connections.clear();
        session.websocket_pages.clear();
        session.connection_page = 0;
        session.connection_cursors.clear();
        session.next_connection_cursor = None;
        session.focus = UiFocus::Overview;
    }
    state.notify();
    StatusCode::NO_CONTENT
}

async fn toggle_connection(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    if !session.selected_connections.remove(&id) {
        session.selected_connections.insert(id);
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn clear_connections(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    session.selected_connections.clear();
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn older_connections(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_connection_page(&state, &signals.session, true)
}

async fn newer_connections(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_connection_page(&state, &signals.session, false)
}

fn update_connection_page(state: &DashboardState, session_id: &str, older: bool) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(session_id) else {
        return StatusCode::NOT_FOUND;
    };
    if session.focus != UiFocus::Overview {
        return StatusCode::BAD_REQUEST;
    }
    if older {
        let Some(cursor) = session.next_connection_cursor else {
            return StatusCode::NO_CONTENT;
        };
        let next_page = session.connection_page.saturating_add(1);
        session.connection_cursors.truncate(next_page);
        if session.connection_cursors.len() < next_page {
            session.connection_cursors.resize(next_page, None);
        }
        session.connection_cursors.push(Some(cursor));
        session.connection_page = next_page;
        session.next_connection_cursor = None;
    } else {
        session.connection_page = session.connection_page.saturating_sub(1);
        session.next_connection_cursor = None;
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

fn set_focus(state: &DashboardState, signals: &UiSignals, focus: UiFocus) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    session.focus = focus;
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn clear_focus(
    State(state): State<DashboardState>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    set_focus(&state, &signals, UiFocus::Overview)
}

async fn focus_connection(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    set_focus(&state, &signals, UiFocus::Connection(id))
}

async fn focus_request(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    set_focus(&state, &signals, UiFocus::Request(id))
}

async fn older_websocket_messages(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_websocket_page(&state, &signals.session, id, true)
}

async fn newer_websocket_messages(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    update_websocket_page(&state, &signals.session, id, false)
}

fn update_websocket_page(
    state: &DashboardState,
    session_id: &str,
    exchange_id: u64,
    older: bool,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(session_id) else {
        return StatusCode::NOT_FOUND;
    };
    if session.focus != UiFocus::Request(exchange_id) {
        return StatusCode::BAD_REQUEST;
    }
    let page = session.websocket_pages.entry(exchange_id).or_default();
    *page = if older {
        page.saturating_add(1)
    } else {
        page.saturating_sub(1)
    };
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn toggle_selected(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    let selected = &mut session.selected;
    if !selected.remove(&id) {
        selected.insert(id);
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
}

async fn capture_json(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    match state.capture.details(id).await {
        Ok(details) => {
            let mut response = Json(details).into_response();
            if let Ok(value) = format!("attachment; filename=\"rama-capture-{id}.json\"").parse() {
                response.headers_mut().insert("content-disposition", value);
            }
            response
        }
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

async fn capture_body(
    State(state): State<DashboardState>,
    Path(BodyPath { id, direction }): Path<BodyPath>,
    Query(query): Query<BodyQuery>,
) -> Response {
    let body = match direction.as_str() {
        "request" => CapturedBody::Request,
        "response" => CapturedBody::Response,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let limit = query.limit.map(|limit| limit.min(MAX_BODY_PREVIEW_LIMIT));
    match state.capture.body_stream(id, body, limit).await {
        Ok(stream) => {
            let mut response = Response::builder()
                .header("content-type", "application/octet-stream")
                .header("cache-control", "no-store")
                .header("x-content-type-options", "nosniff");
            if query.download {
                response = response.header(
                    "content-disposition",
                    format!("attachment; filename=\"{direction}-{id}.body\""),
                );
            }
            response
                .body(Body::from_stream(stream))
                .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
        }
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

async fn capture_websocket_message(
    State(state): State<DashboardState>,
    Path(WebSocketMessagePath { id, index }): Path<WebSocketMessagePath>,
) -> Response {
    match state.capture.websocket_message_stream(id, index).await {
        Ok(stream) => Response::builder()
            .header("content-type", "application/octet-stream")
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .body(Body::from_stream(stream))
            .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(error) => error_response(StatusCode::NOT_FOUND, error),
    }
}

async fn replay_websocket_message(
    State(state): State<DashboardState>,
    Path(WebSocketMessagePath { id, index }): Path<WebSocketMessagePath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state.capture.replay_websocket_message(id, index).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WebSocketReplayError::CaptureNotFound | WebSocketReplayError::MessageNotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(WebSocketReplayError::ControlFrame | WebSocketReplayError::Truncated) => {
            StatusCode::UNPROCESSABLE_ENTITY.into_response()
        }
        Err(error @ WebSocketReplayError::InvalidMessage(_)) => {
            error_response(StatusCode::BAD_REQUEST, error)
        }
        Err(WebSocketReplayError::ConnectionClosed) => StatusCode::CONFLICT.into_response(),
        Err(error @ WebSocketReplayError::SendFailed(_)) => {
            error_response(StatusCode::BAD_GATEWAY, error)
        }
        Err(error @ WebSocketReplayError::InvalidCapture(_)) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
    }
}

async fn send_websocket_message(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    match state
        .capture
        .send_websocket_message(
            id,
            &signals.websocket_direction,
            &signals.websocket_kind,
            &signals.websocket_payload,
        )
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(WebSocketReplayError::CaptureNotFound | WebSocketReplayError::MessageNotFound) => {
            StatusCode::NOT_FOUND.into_response()
        }
        Err(error @ WebSocketReplayError::InvalidMessage(_)) => {
            error_response(StatusCode::BAD_REQUEST, error)
        }
        Err(WebSocketReplayError::ConnectionClosed) => StatusCode::CONFLICT.into_response(),
        Err(error @ WebSocketReplayError::SendFailed(_)) => {
            error_response(StatusCode::BAD_GATEWAY, error)
        }
        Err(
            error @ (WebSocketReplayError::InvalidCapture(_)
            | WebSocketReplayError::ControlFrame
            | WebSocketReplayError::Truncated),
        ) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn download_ca(State(state): State<DashboardState>) -> Response {
    Response::builder()
        .header("content-type", "application/x-pem-file")
        .header(
            "content-disposition",
            "attachment; filename=\"rama-proxy-ca.pem\"",
        )
        .body(Body::from(state.ca_pem.as_ref().clone()))
        .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
}

async fn rama_logo() -> Response {
    Response::builder()
        .header("content-type", "image/svg+xml")
        .body(Body::from(RAMA_LOGO_SVG))
        .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
}

async fn export_profiles(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let (request_ids, connection_ids) = match export_selection(&state, query) {
        Ok(selection) => selection,
        Err(status) => return status.into_response(),
    };
    match state
        .capture
        .export_profiles(&request_ids, &connection_ids)
        .await
    {
        Ok(profiles) => {
            let Ok(bytes) = serde_json::to_vec(&profiles) else {
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to encode captured user-agent profiles",
                );
            };
            if profiles.as_array().is_none_or(Vec::is_empty) {
                return error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "the selection has no captured user-agent profile observations",
                );
            }
            if let Err(error) = UserAgentDatabase::try_from_json_slice(&bytes) {
                return error_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "the selected observations do not form a complete emulation profile: {error}"
                    ),
                );
            }
            Response::builder()
                .header("content-type", "application/json")
                .header(
                    "content-disposition",
                    "attachment; filename=\"rama-emulation-profiles.json\"",
                )
                .header("cache-control", "no-store")
                .body(Body::from(bytes))
                .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
        }
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn export_har(
    State(state): State<DashboardState>,
    Query(query): Query<ExportQuery>,
) -> Response {
    let (request_ids, connection_ids) = match export_selection(&state, query) {
        Ok(selection) => selection,
        Err(status) => return status.into_response(),
    };
    match export_selected(&state.capture, &request_ids, &connection_ids).await {
        Ok(download) => har_download_response(download),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::WouldBlock) =>
        {
            let mut response = error_response(StatusCode::TOO_MANY_REQUESTS, error);
            response
                .headers_mut()
                .insert("retry-after", rama::http::HeaderValue::from_static("1"));
            response
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

fn export_selection(
    state: &DashboardState,
    query: ExportQuery,
) -> Result<(BTreeSet<u64>, BTreeSet<u64>), StatusCode> {
    if query.ids.is_some() || query.connection_ids.is_some() {
        return Ok((
            parse_export_ids(query.ids.as_deref()),
            parse_export_ids(query.connection_ids.as_deref()),
        ));
    }
    let Some(session_id) = query.session else {
        return Ok((BTreeSet::new(), BTreeSet::new()));
    };
    if !state.has_session(&session_id) {
        return Err(StatusCode::NOT_FOUND);
    }
    let session = state.session(&session_id);
    Ok((session.selected, session.selected_connections))
}

fn parse_export_ids(ids: Option<&str>) -> BTreeSet<u64> {
    ids.into_iter()
        .flat_map(|ids| ids.split(','))
        .filter_map(|id| id.trim().parse().ok())
        .collect()
}

async fn start_har(
    State(state): State<DashboardState>,
    Query(query): Query<StartHarQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let _transition = state.recording_transition.lock().await;
    if !state.inspection.is_enabled() {
        return error_response(
            StatusCode::CONFLICT,
            "Resume inspector before starting a HAR recording",
        );
    }
    match state.har.start_browser(query.file_name).await {
        Ok(_) => {
            state.notify();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

async fn stop_har(
    State(state): State<DashboardState>,
    Query(query): Query<HarSessionQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = state.har.stop_browser().await;
    state.notify();
    match result {
        Ok(download) => har_download_response(download),
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
    }
}

fn har_download_response(download: HarDownload) -> Response {
    Response::builder()
        .header("content-type", "application/json")
        .header("content-length", download.content_length)
        .header("cache-control", "no-store")
        .header(
            "content-disposition",
            format!("attachment; filename=\"{}\"", download.file_name),
        )
        .body(Body::from_stream(ReaderStream::new(download.reader)))
        .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error))
}

async fn request_curl(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    let captured = match state.capture.replay_request(id).await {
        Ok(captured) => captured,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    if matches!(captured.protocol.as_str(), "ws" | "wss") {
        return error_response(
            StatusCode::BAD_REQUEST,
            "WebSocket handshakes cannot be represented as a replayable cURL command",
        );
    }
    let (request, body, _) = match build_captured_request(captured, false) {
        Ok(request) => request,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    let (mut parts, ()) = request.into_parts();
    remove_hop_by_hop_request_headers(&mut parts.headers);
    remove_proxy_auth_request_headers(&mut parts.headers);
    let compatibility = if cfg!(windows) {
        curl::CurlScriptCompatibility::PowerShell
    } else {
        curl::CurlScriptCompatibility::Unix
    };
    match curl::try_cmd_string_for_request_parts_and_payload_with_options(
        &parts,
        &Bytes::from(body),
        curl::CurlExportOptions::default().with_script_compatibility(compatibility),
        &curl::CurlScriptPayloadMode::Inline,
    ) {
        Ok(command) => Response::builder()
            .header("content-type", "text/plain; charset=utf-8")
            .header("cache-control", "no-store")
            .body(Body::from(command))
            .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn replay(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if !state.has_session(&signals.session) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let result = replay_captured(&state, id).await;
    state
        .capture
        .record_replay_result(
            id,
            result
                .as_ref()
                .map(|status| *status)
                .map_err(ToString::to_string),
        )
        .await;
    state.notify();
    match result {
        Ok(status) => Json(serde_json::json!({ "status": status })).into_response(),
        Err(error) => error_response(StatusCode::BAD_GATEWAY, error),
    }
}

async fn replay_captured(state: &DashboardState, id: u64) -> Result<u16, BoxError> {
    let captured = state.capture.replay_request(id).await?;
    let (request, body, tls_client_hello) = build_captured_request(captured, true)?;
    let (parts, ()) = request.into_parts();
    let mut request = Request::from_parts(parts, Body::from(body));
    if let Some(client_hello) = tls_client_hello {
        request.extensions().insert_arc(Arc::new(TlsProfile {
            client_hello,
            ws_client_config_overwrites: None,
        }));
    }
    let replay_connection = state.capture.begin_connection_if_enabled(
        None,
        "replay",
        Some(format!("Replay of request #{id}")),
    );
    if let Some(replay_connection) = replay_connection {
        state
            .capture
            .confirm_connection_if_enabled(replay_connection);
        request.extensions().insert(ConnectionId(replay_connection));
    }
    let _connection_guard = replay_connection
        .map(|replay_connection| state.capture.connection_guard(replay_connection));
    // Scrub the original hop metadata before emulation can normalize the
    // `Connection` field while retaining a header it named.
    remove_hop_by_hop_request_headers(request.headers_mut());
    let tls_config = rama::tls::client::TlsClientConfig::default_http();
    let transport =
        rama::tcp::client::service::TcpConnector::new().with_connector(state.tcp_options.clone());
    let client = rama::http::client::EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(transport)
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(Executor::default())
        .with_default_connection_pool()
        .build_client()
        .with_forward_proxy_auth(state.upstream.forward_proxy_auth())
        .with_tunnel_plaintext_http(state.upstream.tunnel_plaintext_http())
        .with_isolate_forward_proxy_auth_error(true);
    let client = state.upstream.http_service(client);
    let client = RemoveRequestHeaderLayer::hop_by_hop().into_layer(client);
    let client = EmulateTlsProfileLayer::new().into_layer(client);
    let client = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(client);
    let response = client.serve(request).await.context("replay request")?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        frame.context("drain replay response")?;
    }
    Ok(status)
}

fn build_captured_request(
    captured: ReplayRequest,
    strip_transport_headers: bool,
) -> Result<(Request<()>, Vec<u8>, Option<rama::tls::client::ClientHello>), BoxError> {
    let method: Method = captured.method.parse().context("parse captured method")?;
    let mut builder = Request::builder()
        .method(method)
        .version(captured_http_version(&captured.version)?)
        .uri(captured.url.as_str());
    for (name, value) in captured.headers {
        if strip_transport_headers
            && matches!(
                name.to_ascii_lowercase().as_str(),
                "host" | "content-length" | "proxy-authorization"
            )
        {
            continue;
        }
        builder = builder.header(name, captured_header_value(&value)?);
    }
    let request = builder.body(()).context("build captured request")?;
    Ok((request, captured.body, captured.tls_client_hello))
}

fn error_response(status: StatusCode, error: impl std::fmt::Display) -> Response {
    (status, error.to_string()).into_response()
}

fn render_index(session: &str) -> impl IntoHtml {
    let session_signal = format!("'{session}'");
    html!(
        lang = "en",
        head!(
            meta!(charset = "utf-8"),
            meta!(
                name = "viewport",
                content = "width=device-width,initial-scale=1"
            ),
            title!("Rama Proxy Inspector"),
            link!(
                rel = "icon",
                r#type = "image/svg+xml",
                href = "/assets/rama-logo.svg"
            ),
            link!(rel = "stylesheet", href = "/assets/style.css"),
            script!(r#type = "module", src = "/assets/datastar.js"),
            script!(r#type = "module", src = "/assets/har.js"),
            script!(r#type = "module", src = "/assets/details.js"),
            script!(r#type = "module", src = "/assets/live.js"),
            script!(r#type = "module", src = "/assets/preferences.js"),
            script!(r#type = "module", src = "/assets/control.js"),
        ),
        body!(
            "data-inspector-session" = session.to_owned(),
            "data-signals:session" = session_signal,
            "data-signals:search" = "''",
            "data-signals:connection_id" = "''",
            "data-signals:user_agent" = "''",
            "data-signals:endpoint" = "''",
            "data-signals:method" = "''",
            "data-signals:status" = "''",
            "data-signals:protocol" = "''",
            "data-signals:websocket_direction" = "'ingress'",
            "data-signals:websocket_kind" = "'text'",
            "data-signals:websocket_payload" = "''",
            "data-init" = "@get('/events')",
            header!(
                class = "topbar",
                a!(
                    class = "brand",
                    href = "/",
                    "data-inspector-focus" = "overview",
                    img!(
                        class = "mark",
                        src = "/assets/rama-logo.svg",
                        alt = "Rama noodle logo"
                    ),
                    h1!("Rama Proxy Inspector")
                ),
                div!(
                    class = "header-actions",
                    a!(class = "ca-link", href = "/ca.pem", "MITM CA"),
                    div!(
                        class = "inspection-controls",
                        button!(
                            r#type = "button",
                            class = "ghost inspection-pause",
                            "data-indicator:inspection_busy" = "",
                            "data-attr:disabled" = "$inspection_busy",
                            "data-on:click" = "@post('/api/inspection/pause')",
                            span!(class = "button-spinner", "aria-hidden" = "true"),
                            span!(class = "inspection-action-label", "Pause inspector")
                        ),
                        button!(
                            r#type = "button",
                            class = "inspection-resume",
                            "data-indicator:inspection_busy" = "",
                            "data-attr:disabled" = "$inspection_busy",
                            "data-on:click" = "@post('/api/inspection/resume')",
                            span!(class = "button-spinner", "aria-hidden" = "true"),
                            span!(class = "inspection-action-label", "Resume inspector")
                        )
                    ),
                    span!(
                        id = "connection-status",
                        class = "live-pill is-connecting",
                        role = "status",
                        "aria-live" = "polite",
                        span!(class = "pulse"),
                        span!("data-live-label" = "", "connecting")
                    )
                ),
            ),
            div!(
                id = "har-notice",
                class = "notice",
                role = "status",
                "aria-live" = "polite",
                hidden = ""
            ),
            iframe!(
                name = "har-download",
                class = "har-download",
                title = "HAR download"
            ),
            main!(
                section!(
                    class = "filter-panel",
                    div!(
                        class = "filter-head",
                        div!(h2!("Filters"), p!("Narrow this inspector session")),
                        button!(
                            r#type = "button",
                            class = "ghost clear-filters",
                            "data-reset-preferences" = "",
                            "data-on:click" = "$search = ''; $connection_id = ''; $user_agent = ''; $endpoint = ''; $method = ''; $status = ''; $protocol = ''; @post('/api/filter/reset')",
                            "Reset filters"
                        )
                    ),
                    div!(
                        class = "filters",
                        label!(
                            class = "filter-search",
                            span!("Headers & payload"),
                            input!(
                                r#type = "search",
                                placeholder = "Search URL, header, fingerprint or payload…",
                                "data-persist-filter" = "search",
                                "data-bind:search" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-endpoint",
                            span!("Endpoint"),
                            input!(
                                r#type = "search",
                                placeholder = "api.example.com",
                                "data-persist-filter" = "endpoint",
                                "data-bind:endpoint" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-user-agent",
                            span!("User agent"),
                            input!(
                                r#type = "search",
                                placeholder = "Chromium, curl…",
                                "data-persist-filter" = "user_agent",
                                "data-bind:user_agent" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-connection",
                            span!("Connection"),
                            input!(
                                r#type = "search",
                                inputmode = "numeric",
                                placeholder = "#42",
                                "data-persist-filter" = "connection_id",
                                "data-bind:connection_id" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-method",
                            span!("Method"),
                            select!(
                                "data-bind:method" = "",
                                "data-persist-filter" = "method",
                                "data-on:change" = "@post('/api/filter')",
                                option!(value = "", "All methods"),
                                option!(value = "GET", "GET"),
                                option!(value = "POST", "POST"),
                                option!(value = "PUT", "PUT"),
                                option!(value = "PATCH", "PATCH"),
                                option!(value = "DELETE", "DELETE"),
                                option!(value = "CONNECT", "CONNECT"),
                            )
                        ),
                        label!(
                            class = "filter-status",
                            span!("Status"),
                            select!(
                                "data-bind:status" = "",
                                "data-persist-filter" = "status",
                                "data-on:change" = "@post('/api/filter')",
                                option!(value = "", "All statuses"),
                                option!(value = "pending", "Pending"),
                                option!(value = "2xx", "2xx"),
                                option!(value = "3xx", "3xx"),
                                option!(value = "4xx", "4xx"),
                                option!(value = "5xx", "5xx"),
                            )
                        ),
                        label!(
                            class = "filter-protocol",
                            span!("Protocol"),
                            select!(
                                "data-bind:protocol" = "",
                                "data-persist-filter" = "protocol",
                                "data-on:change" = "@post('/api/filter')",
                                option!(value = "", "All protocols"),
                                option!(value = "http", "HTTP"),
                                option!(value = "https", "HTTPS"),
                                option!(value = "ws", "WS"),
                                option!(value = "wss", "WSS"),
                                option!(value = "other", "Other"),
                            )
                        ),
                    ),
                    details!(
                        class = "mitm-scope",
                        summary!(
                            div!(
                                strong!("MITM domain scope"),
                                span!(
                                    "Choose which new connections are inspected; deny always wins"
                                )
                            ),
                            span!(class = "scope-summary", "Shared by all dashboards")
                        ),
                        div!(
                            class = "scope-editor",
                            label!(
                                span!("MITM scope"),
                                select!(
                                    id = "mitm-mode",
                                    option!(value = "all", "All eligible hosts"),
                                    option!(value = "selected", "Selected hosts only"),
                                    option!(value = "none", "No hosts")
                                )
                            ),
                            label!(
                                span!("Allow domains"),
                                textarea!(
                                    id = "mitm-allow",
                                    rows = "2",
                                    placeholder = "example.com, *.internal.test",
                                    "data-mitm-policy" = "allow"
                                ),
                                small!(
                                    "When non-empty, unmatched domains pass through without inspection."
                                )
                            ),
                            label!(
                                span!("Deny domains"),
                                textarea!(
                                    id = "mitm-deny",
                                    rows = "2",
                                    placeholder = "accounts.example.com",
                                    "data-mitm-policy" = "deny"
                                ),
                                small!(
                                    "Plain domains include subdomains; prefix = for an exact host. Deny overrides allow."
                                )
                            ),
                            div!(
                                class = "scope-actions",
                                span!(
                                    id = "mitm-policy-status",
                                    role = "status",
                                    "aria-live" = "polite"
                                ),
                                button!(
                                    r#type = "button",
                                    class = "ghost",
                                    "data-apply-mitm-policy" = "",
                                    "Apply scope"
                                )
                            )
                        )
                    ),
                ),
                PreEscaped(CONTROL_HTML),
                section!(
                    id = "live",
                    class = "live-shell",
                    span!(id = "live-heartbeat", hidden = "", "data-sequence" = ""),
                    p!("Connecting…")
                ),
            ),
            dialog!(
                id = "clear-captures-dialog",
                class = "confirm-dialog",
                h2!("Clear captured traffic?"),
                p!(
                    "This removes every connection, request, response, and encrypted capture file from this inspector process. Active traffic can appear again immediately."
                ),
                div!(
                    class = "dialog-actions",
                    button!(
                        r#type = "button",
                        class = "ghost",
                        "data-close-clear" = "",
                        "Cancel"
                    ),
                    button!(
                        r#type = "button",
                        class = "danger",
                        "data-confirm-clear" = "",
                        "data-on:click" = "@post('/api/captures/clear')",
                        "Clear captured traffic"
                    )
                )
            ),
        ),
    )
}

#[cfg(test)]
fn escape_js_string(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "\\'")
}

fn render_live_panel(
    session_id: &str,
    heartbeat_sequence: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    details: &BTreeMap<u64, InspectorDetails>,
    har: &super::har::HarStatus,
    live: &LiveStatus,
) -> String {
    match session.focus {
        UiFocus::Overview => render_overview_panel(
            session_id,
            heartbeat_sequence,
            snapshot,
            session,
            details,
            har,
            live,
        )
        .into_string(),
        UiFocus::Connection(id) => {
            render_connection_focus(heartbeat_sequence, id, snapshot, session, details, live)
        }
        UiFocus::Request(id) => {
            render_request_focus(heartbeat_sequence, id, snapshot, details, live)
        }
    }
}

fn render_overview_panel(
    session_id: &str,
    heartbeat_sequence: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    _details: &BTreeMap<u64, InspectorDetails>,
    har: &super::har::HarStatus,
    live: &LiveStatus,
) -> impl IntoHtml {
    let inspection_enabled = live.recording;
    let connection_offset = snapshot.connection_offset;
    let connection_start = if snapshot.connections.is_empty() {
        0
    } else {
        connection_offset.saturating_add(1)
    };
    let connection_end = connection_offset.saturating_add(snapshot.connections.len());
    let has_newer_connections = session.connection_page > 0;
    let has_older_connections = snapshot.next_connection_cursor.is_some();
    let connection_rows = snapshot.connections.iter().map(|connection| {
        let selected = session.selected_connections.contains(&connection.id);
        let select_label = if selected { "✓" } else { "+" };
        let state_label = if connection.active { "alive" } else { "closed" };
        let route = if connection.ingress_protocol == "replay" {
            snapshot
                .exchanges
                .iter()
                .find(|exchange| exchange.connection_id == connection.id)
                .map(|exchange| format!("Inspector replay → {}", exchange.endpoint))
                .unwrap_or_else(|| "Inspector replay".to_owned())
        } else {
            format!("{} → {}", connection.peer_address, connection.local_address)
        };
        let class = match (connection.active, selected) {
            (true, true) => "connection active selected",
            (true, false) => "connection active",
            (false, true) => "connection selected",
            (false, false) => "connection",
        };
        article!(
            class = class,
            div!(
                span!(class = "mono", format!("#{}", connection.display_id)),
                div!(
                    class = "connection-tags",
                    span!(class = "tag", connection.ingress_protocol.clone()),
                    span!(
                        class = if connection.active {
                            "connection-state alive"
                        } else {
                            "connection-state closed"
                        },
                        state_label
                    ),
                    button!(
                        r#type = "button",
                        class = if selected {
                            "select connection-select selected"
                        } else {
                            "select connection-select"
                        },
                        title = "Include all requests on this connection in exports",
                        "aria-label" = format!("Select connection #{}", connection.display_id),
                        "aria-pressed" = selected.to_string(),
                        "data-on:click" = format!("@post('/api/connection/{}')", connection.id),
                        select_label
                    )
                )
            ),
            button!(
                r#type = "button",
                class = "connection-open",
                title = format!("Inspect connection #{}", connection.display_id),
                "data-inspector-focus" = "connection",
                "data-focus-id" = connection.id.to_string(),
                strong!(route),
                connection
                    .label
                    .as_ref()
                    .map(|label| span!(class = "connection-label", label.clone())),
                time!(
                    datetime = connection.started_at.to_string(),
                    format!("started {}", display_timestamp(&connection.started_at))
                ),
                small!(format!(
                    "{} req · {} ↓ · {} ↑",
                    connection.request_count,
                    format_bytes(connection.bytes_in),
                    format_bytes(connection.bytes_out)
                ))
            )
        )
    });
    let connection_window = format!(
        "{connection_start}–{connection_end} of {}",
        snapshot.total_connections
    );
    let connection_selection = if session.selected_connections.is_empty() {
        small!(connection_window).into_string()
    } else {
        div!(
            class = "connection-selection",
            span!(connection_window),
            span!(format!("{} selected", session.selected_connections.len())),
            button!(
                r#type = "button",
                class = "ghost compact",
                "data-on:click" = "@post('/api/connections/clear')",
                "Clear"
            )
        )
        .into_string()
    };
    let connection_pager = div!(
        class = "connection-pager",
        button!(
            r#type = "button",
            class = "ghost compact",
            disabled? = (!has_newer_connections).then_some(""),
            "data-connection-page-action" = "newer",
            "data-on:click" = "@post('/api/connections/newer')",
            "Newer"
        ),
        span!(format!(
            "Page {}",
            session.connection_page.saturating_add(1)
        )),
        button!(
            r#type = "button",
            class = "ghost compact",
            disabled? = (!has_older_connections).then_some(""),
            "data-connection-page-action" = "older",
            "data-on:click" = "@post('/api/connections/older')",
            "Older"
        )
    );
    let exchange_rows = snapshot.exchanges.iter().take(250).map(|exchange| {
        let pending = live.for_exchange(exchange.id).next();
        let is_selected = session.selected.contains(&exchange.id);
        let class = if exchange.active {
            "exchange active"
        } else {
            "exchange"
        };
        let select_class = if is_selected {
            "select selected"
        } else {
            "select"
        };
        let select_label = if is_selected { "✓" } else { "+" };
        let method = if matches!(exchange.protocol.as_str(), "ws" | "wss") {
            "WS".to_owned()
        } else {
            exchange.method.clone()
        };
        let replay_action = if matches!(exchange.protocol.as_str(), "ws" | "wss") {
            span!(class = "row-spacer").into_string()
        } else {
            button!(
                class = "ghost compact replay-inline",
                title = "Replay this request using only captured headers and TLS data",
                "data-on:click" = format!("@post('/api/replay/{}')", exchange.id),
                "Replay"
            )
            .into_string()
        };
        let identity = div!(
            class = "row-identity",
            button!(
                class = select_class,
                title = "Select this request for exports and approval actions",
                "data-on:click" = format!("@post('/api/select/{}')", exchange.id),
                select_label
            ),
            div!(
                class = "capture-ref",
                strong!(format!("#{}", exchange.id)),
                span!(format!("conn #{}", exchange.connection_display_id))
            )
        )
        .into_string();
        let target = div!(
            class = "target",
            strong!(exchange.endpoint.clone()),
            small!(exchange.url.clone())
        )
        .into_string();
        let protocol_state = div!(
            class = "exchange-protocol-state",
            PreEscaped(render_protocol_badge(exchange)),
            PreEscaped(
                pending
                    .map(approval_badge)
                    .unwrap_or_else(|| render_exchange_status(exchange))
            )
        )
        .into_string();
        let metrics = div!(
            class = "exchange-metrics",
            span!(class = "bytes", format_bytes(exchange.response_bytes)),
            time!(
                class = "exchange-time",
                datetime = exchange.started_at.to_string(),
                display_timestamp(&exchange.started_at)
            )
        )
        .into_string();
        let actions = div!(
            class = "exchange-actions",
            PreEscaped(replay_action),
            (!matches!(exchange.protocol.as_str(), "ws" | "wss"))
                .then(|| PreEscaped(render_curl_button(exchange.id, "cURL"))),
            button!(
                class = "ghost",
                "data-inspector-focus" = "request",
                "data-focus-id" = exchange.id.to_string(),
                "aria-label" = format!("Open request #{}", exchange.id),
                "Open"
            )
        )
        .into_string();
        article!(
            id = format!("request-{}", exchange.id),
            "data-approval-id"? = pending.map(|message| message.id.to_string()),
            class = class,
            tabindex = "0",
            "aria-label" = format!("Open request #{}", exchange.id),
            "data-inspector-focus" = "request",
            "data-focus-id" = exchange.id.to_string(),
            div!(
                class = "exchange-row",
                PreEscaped(identity),
                span!(class = "method", method),
                PreEscaped(target),
                PreEscaped(protocol_state),
                PreEscaped(metrics),
                PreEscaped(actions)
            ),
            PreEscaped(render_approval_slots(live.for_exchange(exchange.id)))
        )
    });
    let har_control = if har.active {
        form!(
            class = "har-control recording",
            method = "post",
            action = format!("/api/har/stop?session={session_id}"),
            target = "har-download",
            title = har.path.clone().unwrap_or_default(),
            span!(class = "record-dot"),
            span!(
                (if har.suspended {
                    "HAR paused"
                } else {
                    "HAR recording"
                })
                .to_owned()
            ),
            button!(
                r#type = "submit",
                class = "danger compact",
                "Stop & download"
            )
        )
        .into_string()
    } else {
        button!(
            r#type = "button",
            class = "ghost compact har-start",
            "data-har-action" = "start",
            "data-session" = session_id,
            title = "Record now; your browser will choose the save location when you stop",
            "Record HAR"
        )
        .into_string()
    };
    let fallback = render_pending_fallbacks(&live.pending, &snapshot.exchanges, None);
    let requests = div!(
        class = "exchange-list",
        exchange_rows.collect::<Vec<_>>(),
        PreEscaped(fallback),
    )
    .into_string();
    let selection_exports = match (session.selected_connections.len(), session.selected.len()) {
        (0, 0) => div!(
            class = "export",
            span!("Select connections or requests"),
            div!(
                class = "export-actions",
                button!(class = "ghost compact", disabled = true, "Export HAR"),
                button!(class = "ghost compact", disabled = true, "Export profiles")
            )
        )
        .into_string(),
        (connections, requests) => {
            let scope = match (connections, requests) {
                (0, requests) => format!("{requests} request(s)"),
                (connections, 0) => format!("{connections} connection(s)"),
                (connections, requests) => {
                    format!("{connections} connection(s) + {requests} request(s)")
                }
            };
            div!(
                class = "export",
                span!(scope),
                div!(
                    class = "export-actions",
                    a!(
                        class = "ghost link",
                        href = format!("/api/har/export?session={session_id}"),
                        target = "har-download",
                        "data-har-export" = "",
                        "Export HAR"
                    ),
                    a!(
                        class = "ghost link",
                        href = format!("/api/profiles.json?session={session_id}"),
                        target = "har-download",
                        "Export profiles"
                    )
                )
            )
            .into_string()
        }
    };
    section!(
        id = "live",
        class = if inspection_enabled {
            "live-shell"
        } else {
            "live-shell inspection-paused"
        },
        "data-inspection-paused" = (!inspection_enabled).to_string(),
        render_live_heartbeat(heartbeat_sequence),
        inspection_notice(inspection_enabled),
        div!(
            class = "stats",
            stat("Connections", snapshot.total_connections.to_string()),
            stat("Active", snapshot.active_connections.to_string()),
            stat("Requests", snapshot.total_requests.to_string()),
            stat("Ingress", format_bytes(snapshot.bytes_in)),
            stat("Egress", format_bytes(snapshot.bytes_out)),
        ),
        div!(
            class = "workspace",
            aside!(
                div!(
                    class = "section-title",
                    h2!("Connections"),
                    PreEscaped(connection_selection)
                ),
                div!(
                    class = "connections",
                    tabindex = "0",
                    "aria-label" = "Captured connections",
                    "data-connection-page" = session.connection_page.to_string(),
                    "data-has-newer" = has_newer_connections.to_string(),
                    "data-has-older" = has_older_connections.to_string(),
                    connection_rows.collect::<Vec<_>>(),
                    connection_pager
                )
            ),
            section!(
                class = "requests",
                div!(
                    class = "section-title",
                    h2!("Requests"),
                    div!(
                        class = "request-tools",
                        button!(
                            r#type = "button",
                            class = "danger-outline compact",
                            "data-open-clear" = "",
                            "Clear captures…"
                        ),
                        PreEscaped(har_control),
                        PreEscaped(selection_exports)
                    )
                ),
                render_approval_toolbar(),
                PreEscaped(requests),
                p!(
                    "data-request-empty" = "",
                    hidden = "",
                    "Waiting for matching traffic."
                )
            )
        )
    )
}

fn render_focus_header(
    title: String,
    subtitle: String,
    parent_connection: Option<(u64, u64)>,
    state: Option<(&'static str, bool)>,
) -> impl IntoHtml {
    div!(
        class = "focus-header",
        div!(
            class = "focus-heading",
            button!(
                r#type = "button",
                class = "ghost focus-back",
                "data-inspector-back" = "",
                "← Back"
            ),
            div!(
                class = "focus-title",
                nav!(
                    class = "breadcrumbs",
                    "aria-label" = "Inspector location",
                    button!(
                        r#type = "button",
                        "data-inspector-focus" = "overview",
                        "Overview"
                    ),
                    parent_connection.map(|(id, display_id)| span!(
                        class = "breadcrumb-parent",
                        span!("aria-hidden" = "true", "›"),
                        button!(
                            r#type = "button",
                            "data-inspector-focus" = "connection",
                            "data-focus-id" = id.to_string(),
                            format!("Connection #{display_id}")
                        )
                    )),
                    span!("aria-hidden" = "true", "›"),
                    span!("aria-current" = "page", title.clone()),
                ),
                h2!(title),
                p!(subtitle),
            )
        ),
        state.map(|(label, active)| span!(
            class = if active {
                "connection-state alive focus-state"
            } else {
                "connection-state closed focus-state"
            },
            label
        ))
    )
}

fn inspection_notice(enabled: bool) -> Option<impl IntoHtml> {
    (!enabled).then(|| {
        aside!(
            class = "inspection-notice",
            role = "status",
            strong!("Inspector paused"),
            span!(
                "Inspection is paused. New traffic passes through without MITM, recording or traffic rules. Existing inspected connections are closed. Stored captures and completed HAR files are retained."
            )
        )
    })
}

fn render_request_focus(
    heartbeat_sequence: u64,
    id: u64,
    snapshot: &CaptureSnapshot,
    details: &BTreeMap<u64, InspectorDetails>,
    live: &LiveStatus,
) -> String {
    let inspection_enabled = live.recording;
    let Some(detail) = details.get(&id) else {
        return section!(
            id = "live",
            class = if inspection_enabled {
                "live-shell focused inspector-focus"
            } else {
                "live-shell focused inspector-focus inspection-paused"
            },
            "data-inspection-paused" = (!inspection_enabled).to_string(),
            render_live_heartbeat(heartbeat_sequence),
            inspection_notice(inspection_enabled),
            render_focus_header(
                format!("Request #{id}"),
                "This capture is no longer retained.".to_owned(),
                None,
                None,
            ),
            render_approval_toolbar(),
            PreEscaped(render_approval_slots(live.for_exchange(id))),
            div!(
                class = "focus-empty",
                strong!("Request unavailable"),
                p!("It may have been cleared or retired by the capture limit.")
            ),
            render_approval_toolbar(),
            div!(
                class = "exchange-list",
                PreEscaped(render_pending_fallbacks(&live.pending, &[], Some(id)))
            )
        )
        .into_string();
    };
    let websocket = matches!(detail.summary.protocol.as_str(), "ws" | "wss");
    let connection_display_id = snapshot
        .connections
        .iter()
        .find(|connection| connection.id == detail.summary.connection_id)
        .map(|connection| connection.display_id)
        .unwrap_or(detail.summary.connection_display_id);
    let title = if websocket {
        format!(
            "{} exchange #{}",
            detail.summary.protocol.to_ascii_uppercase(),
            id
        )
    } else {
        format!("{} request #{}", detail.summary.method, id)
    };
    section!(
        id = "live",
        class = if websocket {
            if inspection_enabled {
                "live-shell focused inspector-focus request-focus websocket-focus"
            } else {
                "live-shell focused inspector-focus request-focus websocket-focus inspection-paused"
            }
        } else if inspection_enabled {
            "live-shell focused inspector-focus request-focus"
        } else {
            "live-shell focused inspector-focus request-focus inspection-paused"
        },
        "data-inspection-paused" = (!inspection_enabled).to_string(),
        render_live_heartbeat(heartbeat_sequence),
        inspection_notice(inspection_enabled),
        render_focus_header(
            title,
            detail.summary.url.clone(),
            Some((detail.summary.connection_id, connection_display_id)),
            Some((
                if detail.summary.active {
                    "streaming"
                } else {
                    "finished"
                },
                detail.summary.active,
            )),
        ),
        render_approval_toolbar(),
        article!(
            class = "focus-surface",
            PreEscaped(render_approval_slots(live.for_exchange(id))),
            render_details(detail)
        )
    )
    .into_string()
}

fn render_connection_focus(
    heartbeat_sequence: u64,
    id: u64,
    snapshot: &CaptureSnapshot,
    session: &UiSession,
    details: &BTreeMap<u64, InspectorDetails>,
    live: &LiveStatus,
) -> String {
    let inspection_enabled = live.recording;
    let Some(connection) = snapshot
        .connections
        .iter()
        .find(|connection| connection.id == id)
    else {
        return section!(
            id = "live",
            class = if inspection_enabled {
                "live-shell focused inspector-focus"
            } else {
                "live-shell focused inspector-focus inspection-paused"
            },
            "data-inspection-paused" = (!inspection_enabled).to_string(),
            render_live_heartbeat(heartbeat_sequence),
            inspection_notice(inspection_enabled),
            render_focus_header(
                format!("Connection #{id}"),
                "This connection is no longer retained.".to_owned(),
                None,
                None,
            ),
            div!(
                class = "focus-empty",
                strong!("Connection unavailable"),
                p!("It may have been cleared or retired by the capture limit.")
            )
        )
        .into_string();
    };
    let route = connection_route(connection, &snapshot.exchanges);
    let selected = session.selected_connections.contains(&id);
    let select_label = if selected { "✓ Selected" } else { "+ Select" };
    let request_rows = snapshot
        .exchanges
        .iter()
        .filter(|exchange| exchange.connection_id == id)
        .map(|exchange| render_focused_request_row(exchange, live))
        .collect::<Vec<_>>();
    let tls_detail = details
        .values()
        .find(|detail| detail.summary.connection_id == id);
    section!(
        id = "live",
        class = if inspection_enabled {
            "live-shell focused inspector-focus connection-focus"
        } else {
            "live-shell focused inspector-focus connection-focus inspection-paused"
        },
        "data-inspection-paused" = (!inspection_enabled).to_string(),
        render_live_heartbeat(heartbeat_sequence),
        inspection_notice(inspection_enabled),
        render_focus_header(
            format!("Connection #{}", connection.display_id),
            route,
            None,
            Some((
                if connection.active { "alive" } else { "closed" },
                connection.active,
            )),
        ),
        article!(
            class = "focus-surface connection-detail",
            div!(
                class = "focus-actions",
                connection.label.as_ref().map(|label| span!(
                    class = "connection-label focus-connection-label",
                    label.clone()
                )),
                button!(
                    r#type = "button",
                    class = if selected {
                        "select selected"
                    } else {
                        "select"
                    },
                    title = "Include all requests on this connection in exports",
                    "aria-pressed" = selected.to_string(),
                    "data-on:click" = format!("@post('/api/connection/{id}')"),
                    select_label
                ),
                a!(
                    class = "ghost link compact",
                    href = format!("/api/har/export?connection_ids={id}"),
                    target = "har-download",
                    "data-har-export" = "",
                    "Export HAR"
                )
            ),
            section!(
                class = "detail-overview connection-overview",
                overview_item("Protocol", connection.ingress_protocol.clone()),
                overview_item(
                    "State",
                    if connection.active { "Alive" } else { "Closed" }.to_owned()
                ),
                overview_item("Client", connection.peer_address.clone()),
                overview_item("Proxy listener", connection.local_address.clone()),
                overview_item("Requests", connection.request_count.to_string()),
                overview_item(
                    "Traffic",
                    format!(
                        "{} ↓  {} ↑",
                        format_bytes(connection.bytes_in),
                        format_bytes(connection.bytes_out)
                    )
                ),
                overview_item("Started", display_timestamp(&connection.started_at)),
                connection
                    .ended_at
                    .as_ref()
                    .map(|ended| overview_item("Ended", display_timestamp(ended))),
            ),
            tls_detail.map(render_connection_tls).map(PreEscaped),
            PreEscaped(
                section!(
                    class = "connection-requests",
                    div!(
                        class = "section-title",
                        h2!(format!("Requests · {}", request_rows.len())),
                        span!("Updates stream while this connection remains open")
                    ),
                    render_approval_toolbar(),
                    div!(
                        class = "exchange-list",
                        request_rows,
                        PreEscaped(render_pending_fallbacks(
                            &live.pending,
                            &snapshot.exchanges,
                            Some(id)
                        ))
                    ),
                    p!(
                        "data-request-empty" = "",
                        hidden = "",
                        "Waiting for matching traffic."
                    )
                )
                .into_string()
            )
        )
    )
    .into_string()
}

fn connection_route(connection: &ConnectionSummary, exchanges: &[ExchangeSummary]) -> String {
    if connection.ingress_protocol == "replay" {
        exchanges
            .iter()
            .find(|exchange| exchange.connection_id == connection.id)
            .map(|exchange| format!("Inspector replay → {}", exchange.endpoint))
            .unwrap_or_else(|| "Inspector replay".to_owned())
    } else {
        format!("{} → {}", connection.peer_address, connection.local_address)
    }
}

fn render_focused_request_row(exchange: &ExchangeSummary, live: &LiveStatus) -> impl IntoHtml {
    let pending = live.for_exchange(exchange.id).next();
    let method = if matches!(exchange.protocol.as_str(), "ws" | "wss") {
        "WS".to_owned()
    } else {
        exchange.method.clone()
    };
    article!(
        id = format!("request-{}", exchange.id),
        "data-approval-id"? = pending.map(|message| message.id.to_string()),
        class = if exchange.active {
            "exchange active focus-request-row"
        } else {
            "exchange focus-request-row"
        },
        tabindex = "0",
        role = "button",
        "data-inspector-focus" = "request",
        "data-focus-id" = exchange.id.to_string(),
        div!(
            class = "exchange-row",
            div!(
                class = "capture-ref",
                strong!(format!("#{}", exchange.id)),
                span!(format!("conn #{}", exchange.connection_display_id))
            ),
            span!(class = "method", method),
            div!(
                class = "target",
                strong!(exchange.endpoint.clone()),
                small!(exchange.url.clone())
            ),
            PreEscaped(render_protocol_badge(exchange)),
            PreEscaped(
                pending
                    .map(approval_badge)
                    .unwrap_or_else(|| render_exchange_status(exchange))
            ),
            span!(class = "bytes", format_bytes(exchange.response_bytes)),
            time!(
                class = "exchange-time",
                datetime = exchange.started_at.to_string(),
                display_timestamp(&exchange.started_at)
            ),
            span!(class = "focus-open-hint", "Open →")
        ),
        PreEscaped(render_approval_slots(live.for_exchange(exchange.id)))
    )
}

fn approval_badge(message: &PendingSummary) -> String {
    span!(
        class = "approval-badge",
        match message.direction.as_str() {
            "request" => "Awaiting request approval",
            "response" => "Awaiting response approval",
            _ => "Awaiting message approval",
        }
    )
    .into_string()
}

fn render_approval_toolbar() -> impl IntoHtml {
    div!(
        id = "approval-toolbar",
        "data-ignore-morph" = "",
        class = "approval-toolbar",
        hidden = "",
        button!(
            r#type = "button",
            id = "approval-filter",
            class = "ghost compact",
            "aria-pressed" = "false",
            "data-inspector-focus" = "overview",
            "Awaiting approval (0)"
        ),
        div!(
            id = "approval-actions",
            class = "control-actions",
            hidden = "",
            button!(
                r#type = "button",
                class = "ghost compact",
                "data-bulk" = "forward",
                "Forward selected"
            ),
            button!(
                r#type = "button",
                class = "ghost compact",
                "data-bulk" = "block",
                "Block selected"
            ),
            button!(
                r#type = "button",
                id = "forward-all",
                class = "ghost compact",
                "Forward all and turn off"
            )
        ),
        p!(
            id = "approval-view-note",
            hidden = "",
            "Showing all queued traffic, oldest first, including traffic outside capture filters."
        ),
        div!(id = "automatic-connections")
    )
}

fn render_approval_slots<'a>(pending: impl Iterator<Item = &'a PendingSummary>) -> String {
    pending
        .map(|message| {
            div!(
                id = format!("approval-item-{}", message.id),
                class = "approval-item",
                "data-pending-id" = message.id.to_string(),
                div!(
                    class = "approval-message-heading",
                    input!(
                        r#type = "checkbox",
                        id = format!("approval-select-{}", message.id),
                        "data-ignore-morph" = "",
                        "data-pending-select" = "",
                        value = message.id.to_string(),
                        "aria-label" =
                            format!("Select queued {} #{}", message.direction, message.id)
                    ),
                    button!(
                        r#type = "button",
                        class = "approval-open",
                        "data-edit-approval" = message.id.to_string(),
                        format!("Edit {} · approval #{}", message.direction, message.id)
                    ),
                    message
                        .queued_at
                        .map(|at| time!(datetime = at.to_string(), display_timestamp(&at)))
                ),
                div!(
                    id = format!("approval-slot-{}", message.id),
                    "data-ignore-morph" = ""
                )
            )
            .into_string()
        })
        .collect()
}

fn render_pending_fallbacks(
    pending: &[PendingSummary],
    exchanges: &[ExchangeSummary],
    connection: Option<u64>,
) -> String {
    let retained = exchanges
        .iter()
        .map(|exchange| exchange.id)
        .collect::<BTreeSet<_>>();
    let mut groups = BTreeMap::<String, Vec<&PendingSummary>>::new();
    for message in pending.iter().filter(|message| {
        connection.is_none_or(|id| id == message.connection)
            && message.exchange.is_none_or(|id| !retained.contains(&id))
    }) {
        let key = message
            .exchange
            .map(|id| format!("request-{id}"))
            .unwrap_or_else(|| {
                if matches!(message.direction.as_str(), "request" | "response") {
                    format!("unrecorded-{}", message.id)
                } else {
                    format!("unrecorded-connection-{}", message.connection)
                }
            });
        groups.entry(key).or_default().push(message);
    }
    groups
        .into_iter()
        .filter_map(|(key, messages)| {
            let first = messages.first()?;
            Some(
                article!(
                    id = key,
                    class = "exchange active temporary-request",
                    tabindex = "0",
                    "data-inspector-focus" = "request",
                    "data-approval-id" = first.id.to_string(),
                    div!(
                        class = "exchange-row",
                        div!(
                            class = "capture-ref",
                            strong!(
                                first
                                    .exchange
                                    .map(|id| format!("#{id}"))
                                    .unwrap_or_else(|| "Unrecorded".to_owned())
                            ),
                            span!(
                                first
                                    .connection_display_id
                                    .map(|id| format!("conn #{id}"))
                                    .unwrap_or_else(|| format!("connection {}", first.connection))
                            )
                        ),
                        span!(class = "method", first.method.clone()),
                        div!(
                            class = "target",
                            strong!(first.url.clone()),
                            small!("Outside the current captured view")
                        ),
                        div!(
                            class = "exchange-protocol-state",
                            span!(first.protocol.to_uppercase()),
                            PreEscaped(approval_badge(first))
                        )
                    ),
                    PreEscaped(render_approval_slots(messages.into_iter()))
                )
                .into_string(),
            )
        })
        .collect()
}

fn render_connection_tls(details: &InspectorDetails) -> String {
    let (client_hello, ingress_tls) = details
        .records
        .iter()
        .find_map(|record| match record {
            StoredRecord::RequestHead {
                tls_client_hello,
                ingress_tls,
                ..
            } => Some((tls_client_hello.as_ref(), ingress_tls.as_ref())),
            _ => None,
        })
        .unwrap_or_default();
    let egress_tls = details.records.iter().find_map(|record| match record {
        StoredRecord::ResponseHead { egress_tls, .. } => egress_tls.as_ref(),
        _ => None,
    });
    section!(
        class = "connection-tls",
        div!(
            class = "section-title",
            h2!("TLS on this connection"),
            span!(format!("Observed on request #{}", details.summary.id))
        ),
        div!(
            class = "tls-layout",
            client_hello.map(render_client_hello_card).map(PreEscaped),
            ingress_tls
                .map(|parameters| render_negotiated_tls_card("Client ↔ inspector", parameters))
                .map(PreEscaped),
            egress_tls
                .map(|parameters| render_negotiated_tls_card("Inspector ↔ server", parameters))
                .map(PreEscaped),
            render_connection_fingerprint_card(&details.summary).map(PreEscaped),
        )
    )
    .into_string()
}

fn tls_version_label(version: rama::tls::ProtocolVersion) -> String {
    use rama::tls::ProtocolVersion;
    match version {
        ProtocolVersion::SSLv2 => "SSL 2.0".to_owned(),
        ProtocolVersion::SSLv3 => "SSL 3.0".to_owned(),
        ProtocolVersion::TLSv1_0 => "TLS 1.0".to_owned(),
        ProtocolVersion::TLSv1_1 => "TLS 1.1".to_owned(),
        ProtocolVersion::TLSv1_2 => "TLS 1.2".to_owned(),
        ProtocolVersion::TLSv1_3 => "TLS 1.3".to_owned(),
        ProtocolVersion::DTLSv1_0 => "DTLS 1.0".to_owned(),
        ProtocolVersion::DTLSv1_2 => "DTLS 1.2".to_owned(),
        ProtocolVersion::DTLSv1_3 => "DTLS 1.3".to_owned(),
        ProtocolVersion::Unknown(value) => format!("Unknown ({value:#06x})"),
    }
}

fn tls_fact(label: &'static str, value: String) -> impl IntoHtml {
    div!(
        class = "tls-fact",
        span!(label),
        code!(title = value.clone(), value)
    )
}

fn render_tls_offer_list(
    label: &'static str,
    values: impl IntoIterator<Item = String>,
) -> Option<String> {
    let values = values.into_iter().collect::<Vec<_>>();
    (!values.is_empty()).then(|| {
        details!(
            class = "tls-offer",
            summary!(
                span!(class = "tls-offer-title", label),
                span!(
                    class = "tls-offer-count",
                    format!("{} offered", values.len())
                ),
                span!(class = "tls-offer-chevron", "aria-hidden" = "true", "›")
            ),
            ol!(
                class = "tls-offer-list",
                values
                    .into_iter()
                    .map(|value| li!(code!(title = value.clone(), value)))
                    .collect::<Vec<_>>()
            )
        )
        .into_string()
    })
}

fn render_client_hello_card(hello: &rama::tls::client::ClientHello) -> String {
    let versions = hello
        .supported_versions()
        .map(|versions| {
            versions
                .iter()
                .copied()
                .map(tls_version_label)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_else(|| tls_version_label(hello.protocol_version()));
    let alpn = hello
        .ext_alpn()
        .map(|protocols| {
            protocols
                .iter()
                .map(|protocol| protocol.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "Not offered".to_owned());
    section!(
        class = "detail-card tls-card client-hello-card",
        div!(
            class = "card-title",
            h3!("Client hello"),
            span!("offered by client")
        ),
        div!(
            class = "tls-facts",
            hello
                .ext_server_name()
                .map(|name| tls_fact("Server name", name.to_string())),
            tls_fact("Supported TLS", versions),
            tls_fact("ALPN", alpn),
            tls_fact("Cipher suites", hello.cipher_suites().len().to_string()),
            tls_fact("Extensions", hello.extensions().len().to_string()),
            hello
                .ext_supported_groups()
                .map(|groups| tls_fact("Supported groups", groups.len().to_string())),
            hello
                .ext_signature_algorithms()
                .map(|algorithms| tls_fact("Signature algorithms", algorithms.len().to_string())),
            hello
                .has_encrypted_client_hello()
                .then(|| tls_fact("Encrypted ClientHello", "Offered".to_owned())),
        ),
        div!(
            class = "tls-offers",
            render_tls_offer_list(
                "Cipher suites",
                hello.cipher_suites().iter().map(ToString::to_string)
            )
            .map(PreEscaped),
            render_tls_offer_list(
                "Extensions",
                hello
                    .extensions()
                    .iter()
                    .map(|extension| extension.id().to_string())
            )
            .map(PreEscaped),
            hello
                .ext_supported_groups()
                .and_then(|groups| render_tls_offer_list(
                    "Supported groups",
                    groups.iter().map(ToString::to_string)
                ))
                .map(PreEscaped),
            hello
                .ext_signature_algorithms()
                .and_then(|algorithms| render_tls_offer_list(
                    "Signature algorithms",
                    algorithms.iter().map(ToString::to_string)
                ))
                .map(PreEscaped),
        )
    )
    .into_string()
}

fn render_negotiated_tls_card(title: &'static str, parameters: &CapturedTlsParameters) -> String {
    section!(
        class = "detail-card tls-card negotiated-tls-card",
        div!(class = "card-title", h3!(title), span!("negotiated")),
        div!(
            class = "tls-facts",
            tls_fact(
                "TLS version",
                tls_version_label(parameters.protocol_version)
            ),
            tls_fact(
                "Application protocol",
                parameters
                    .application_layer_protocol
                    .as_ref()
                    .map(|protocol| protocol.to_string())
                    .unwrap_or_else(|| "Not negotiated".to_owned())
            ),
            parameters
                .peer_certificate_count
                .map(|count| tls_fact("Peer certificates", count.to_string())),
        )
    )
    .into_string()
}

fn render_protocol_badge(exchange: &ExchangeSummary) -> String {
    let secure = matches!(exchange.protocol.as_str(), "https" | "wss");
    span!(
        class = match secure {
            true => "tag protocol secure",
            false => "tag protocol",
        },
        secure.then(|| span!(class = "protocol-lock", "aria-hidden" = "true", "🔒")),
        span!(exchange.protocol.to_ascii_uppercase()),
        span!(class = "protocol-version", exchange.http_version.clone())
    )
    .into_string()
}

fn stat(label: &'static str, value: String) -> impl IntoHtml {
    div!(class = "stat", span!(label), strong!(value))
}

fn status_class(status: Option<u16>) -> &'static str {
    match status {
        Some(200..=399) => "status ok",
        Some(400..=599) => "status error",
        _ => "status",
    }
}

fn format_response_status(status: u16) -> String {
    rama::http::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| {
            status
                .canonical_reason()
                .map(|reason| format!("{} {reason}", status.as_u16()))
        })
        .unwrap_or_else(|| status.to_string())
}

fn render_exchange_status(exchange: &super::capture::ExchangeSummary) -> String {
    if let Some(decision) = &exchange.decision {
        return span!(
            class = "status",
            title = decision.clone(),
            format!(
                "{} · {}",
                exchange
                    .status
                    .map(format_response_status)
                    .unwrap_or_default(),
                decision
            )
        )
        .into_string();
    }
    let websocket = matches!(exchange.protocol.as_str(), "ws" | "wss");
    let (label, title, class, state, indicator) = match (exchange.status, exchange.active) {
        (None, true) => (
            "Waiting for response".to_owned(),
            "Waiting for response headers".to_owned(),
            "status pending",
            "waiting",
            Some("response-spinner"),
        ),
        (None, false) => (
            "No response".to_owned(),
            "Connection closed before a response was received".to_owned(),
            "status error",
            "no-response",
            None,
        ),
        (Some(status), true) if websocket => {
            let label = format_response_status(status);
            (
                label.clone(),
                format!("{label}, WebSocket connection is live"),
                status_class(Some(status)),
                "live",
                Some("response-live-dot"),
            )
        }
        (Some(status), true) => {
            let label = format_response_status(status);
            (
                label.clone(),
                format!("{label}, response body is still streaming"),
                status_class(Some(status)),
                "streaming",
                Some("response-spinner"),
            )
        }
        (Some(status), false) => {
            let label = format_response_status(status);
            (
                label.clone(),
                label,
                status_class(Some(status)),
                "finished",
                None,
            )
        }
    };
    span!(
        class = class,
        title = title.clone(),
        "aria-label" = title,
        "data-response-state" = state,
        indicator.map(|class| span!(class = class, "aria-hidden" = "true")),
        span!(class = "status-label", label)
    )
    .into_string()
}

fn render_curl_button(exchange_id: u64, label: &'static str) -> String {
    button!(
        r#type = "button",
        class = "ghost compact",
        title = format!("Copy request #{exchange_id} as a cURL command"),
        "data-copy-curl" = format!("/api/capture/{exchange_id}/curl"),
        span!(class = "capture-spinner", "aria-hidden" = "true"),
        span!("data-copy-label" = "", label)
    )
    .into_string()
}

fn overview_item(label: &'static str, value: String) -> impl IntoHtml {
    div!(
        class = "detail-overview-item",
        div!(
            class = "detail-overview-head",
            span!(class = "detail-overview-label", label),
            button!(
                r#type = "button",
                class = "detail-overview-copy",
                title = format!("Copy {label}"),
                "aria-label" = format!("Copy {label}"),
                "data-copy-overview" = "",
                "Copy"
            )
        ),
        strong!(class = "detail-overview-value", value)
    )
}

fn render_details(details: &InspectorDetails) -> impl IntoHtml {
    let request_head = details.records.iter().find_map(|record| match record {
        StoredRecord::RequestHead {
            method,
            url,
            version,
            headers,
            ..
        } => Some((method, url, version, headers)),
        _ => None,
    });
    let response_head = details.records.iter().find_map(|record| match record {
        StoredRecord::ResponseHead {
            status,
            version,
            headers,
            ..
        } => Some((*status, version, headers)),
        _ => None,
    });
    let request_headers = details
        .records
        .iter()
        .rev()
        .find_map(|record| match record {
            StoredRecord::Interception {
                direction,
                forwarded_headers: Some(headers),
                ..
            } if direction == "request" => Some(headers.as_slice()),
            _ => None,
        })
        .or_else(|| request_head.map(|(_, _, _, headers)| headers.as_slice()));
    let response_headers = response_head.map(|(_, _, headers)| headers.as_slice());
    let overview = section!(
        class = "detail-overview",
        overview_item("Request", details.summary.method.clone()),
        overview_item(
            "Protocol",
            format!(
                "{} · {}",
                details.summary.protocol.to_ascii_uppercase(),
                details.summary.http_version
            )
        ),
        overview_item("Endpoint", details.summary.endpoint.clone()),
        overview_item(
            "Status",
            details
                .summary
                .status
                .map(format_response_status)
                .unwrap_or_else(|| "Pending".to_owned())
        ),
        overview_item(
            "Traffic",
            format!(
                "{} ↑  {} ↓",
                format_bytes(details.summary.request_bytes),
                format_bytes(details.summary.response_bytes)
            )
        ),
        details
            .summary
            .ingress_peer_address
            .as_ref()
            .map(|address| overview_item("Ingress client", address.clone())),
        details
            .summary
            .ingress_local_address
            .as_ref()
            .map(|address| overview_item("Ingress proxy", address.clone())),
        details
            .summary
            .egress_local_address
            .as_ref()
            .map(|address| overview_item("Egress proxy", address.clone())),
        details
            .summary
            .egress_peer_address
            .as_ref()
            .map(|address| overview_item("Egress server", address.clone())),
        overview_item(
            "Request started",
            display_timestamp(&details.summary.started_at)
        ),
        details
            .summary
            .response_started_at
            .as_ref()
            .map(|at| overview_item("Response started", display_timestamp(at))),
        details
            .summary
            .completed_at
            .as_ref()
            .map(|at| overview_item("Completed", display_timestamp(at))),
    )
    .into_string();

    div!(
        class = "details",
        div!(
            class = "detail-top",
            div!(
                class = "detail-meta",
                span!(format!(
                    "connection #{}",
                    details.summary.connection_display_id
                )),
                span!(details.summary.protocol.to_ascii_uppercase()),
                span!(display_timestamp(&details.summary.started_at)),
                details
                    .summary
                    .user_agent_kind
                    .as_ref()
                    .map(|kind| span!(kind.clone())),
            ),
            div!(
                class = "detail-actions",
                button!(
                    r#type = "button",
                    class = "ghost compact",
                    "data-create-traffic-rule" = details.summary.id.to_string(),
                    "Create traffic rule…"
                ),
                (!matches!(details.summary.protocol.as_str(), "ws" | "wss"))
                    .then(|| PreEscaped(render_curl_button(details.summary.id, "Copy as cURL"))),
                (!matches!(details.summary.protocol.as_str(), "ws" | "wss")).then(|| button!(
                    r#type = "button",
                    class = "ghost compact replay-focus",
                    "data-on:click" = format!("@post('/api/replay/{}')", details.summary.id),
                    "Replay request"
                )),
                a!(
                    class = "ghost link",
                    href = format!("/api/har/export?ids={}", details.summary.id),
                    target = "har-download",
                    "data-har-export" = "",
                    "Export HAR"
                ),
                a!(
                    class = "ghost link",
                    href = format!("/api/capture/{}.json", details.summary.id),
                    target = "har-download",
                    "Download capture JSON"
                ),
            )
        ),
        PreEscaped(overview),
        request_head.map(|(method, url, version, _)| section!(
            class = "detail-card request-line",
            h3!("HTTP request"),
            code!(format!("{method} {url} {version}"))
        )),
        div!(
            class = "detail-columns",
            request_headers.map(|headers| PreEscaped(render_headers(
                details.summary.id,
                "request",
                "Request headers",
                headers,
            ))),
            response_head.map(|(status, version, headers)| PreEscaped(render_headers(
                details.summary.id,
                "response",
                &format!("Response headers · {status} {version}"),
                headers
            ))),
        ),
        render_websocket_messages(details).map(PreEscaped),
        render_http_fingerprint_card(&details.summary).map(PreEscaped),
        div!(
            class = "detail-columns payload-columns",
            render_payload_card(
                details.summary.id,
                "request",
                details.summary.request_bytes,
                details.summary.request_truncated,
                request_headers,
            )
            .map(PreEscaped),
            render_payload_card(
                details.summary.id,
                "response",
                details.summary.response_bytes,
                details.summary.response_truncated,
                response_headers,
            )
            .map(PreEscaped),
        ),
        details
            .records
            .iter()
            .filter_map(|record| match record {
                StoredRecord::Interception {
                    direction,
                    outcome,
                    original_headers,
                    original_status,
                    original_payload,
                    ..
                } => Some(section!(
                    class = "detail-card",
                    h3!(format!("{direction} · {outcome}")),
                    original_status.map(|status| p!(format!("Original status: {status}"))),
                    details!(
                        summary!("Original headers / message"),
                        pre!(serde_json::to_string_pretty(original_headers).unwrap_or_default()),
                        original_payload
                            .as_ref()
                            .map(|payload| pre!(payload.clone()))
                    )
                )),
                _ => None,
            })
            .collect::<Vec<_>>(),
        render_capture_outcomes(&details.records).map(PreEscaped),
    )
}

fn render_headers(
    exchange_id: u64,
    direction: &str,
    title: &str,
    headers: &[(String, String)],
) -> String {
    const MAX_HEADERS: usize = 128;
    let shown = headers.len().min(MAX_HEADERS);
    let target = format!("headers-{exchange_id}-{direction}");
    section!(
        class = "detail-card header-card",
        div!(
            class = "card-title",
            h3!(title.to_owned()),
            div!(
                class = "header-tools",
                span!(format!("{} header(s)", headers.len())),
                button!(
                    r#type = "button",
                    class = "ghost compact",
                    "data-copy-target" = target.clone(),
                    "Copy all"
                )
            )
        ),
        div!(
            id = target,
            class = "header-lines",
            headers.iter().take(MAX_HEADERS).map(|(name, value)| div!(
                class = "header-line",
                code!(
                    span!(class = "header-name", name.clone()),
                    ": ",
                    span!(preview_text(value, 4096))
                ),
                button!(
                    r#type = "button",
                    class = "copy-header",
                    title = "Copy header as name: value",
                    "aria-label" = format!("Copy {name} header"),
                    "data-copy-header" = "",
                    "Copy"
                )
            ))
        ),
        (shown < headers.len()).then(|| small!(format!(
            "{} additional header(s) omitted from the DOM; download the capture JSON to inspect them.",
            headers.len() - shown
        )))
    )
    .into_string()
}

fn render_payload_card(
    id: u64,
    direction: &str,
    bytes: u64,
    truncated: bool,
    headers: Option<&[(String, String)]>,
) -> Option<String> {
    if bytes == 0 && !truncated {
        return None;
    }
    let content_type = header_value(headers, "content-type").unwrap_or("application/octet-stream");
    let textual = is_textual_content_type(content_type);
    let payload_format = if textual { "text" } else { "binary" };
    let title = if direction == "request" {
        "Request payload"
    } else {
        "Response payload"
    };
    let preview_url = format!("/api/capture/{id}/body/{direction}?limit={MAX_BODY_PREVIEW_LIMIT}");
    Some(
        article!(
            class = "detail-card payload-card",
            "data-capture-container" = "",
            div!(class = "card-title", h3!(title), span!(format_bytes(bytes))),
            code!(content_type.to_owned()),
            truncated.then(|| p!(
                class = "capture-warning",
                "Capture limit reached; the stored body is incomplete."
            )),
            div!(
                class = "payload-actions",
                button!(
                    r#type = "button",
                    class = "ghost",
                    "data-capture-preview" = "",
                    "data-label" = "Preview first 64 KiB",
                    "data-url" = preview_url,
                    "data-payload-format" = payload_format,
                    span!(class = "capture-spinner", "aria-hidden" = "true"),
                    span!("data-capture-label" = "", "Preview first 64 KiB")
                ),
                a!(
                    class = "ghost link",
                    href = format!("/api/capture/{id}/body/{direction}?download=true"),
                    "Stream captured body"
                )
            ),
            pre!(
                "data-capture-output" = "",
                "aria-live" = "polite",
                hidden = ""
            )
        )
        .into_string(),
    )
}

fn render_fingerprint_values(
    title: &'static str,
    values: &[(&'static str, Option<&str>)],
) -> Option<String> {
    let rows = values
        .iter()
        .filter_map(|(label, value)| value.map(|value| (*label, value)))
        .collect::<Vec<_>>();
    (!rows.is_empty()).then(|| {
        section!(
            class = "detail-card fingerprint-card",
            h3!(title),
            div!(
                class = "fingerprint-grid",
                rows.into_iter().map(|(label, value)| div!(
                    class = "fingerprint-row",
                    span!(label),
                    code!(title = value.to_owned(), value.to_owned())
                ))
            )
        )
        .into_string()
    })
}

fn render_connection_fingerprint_card(summary: &super::capture::ExchangeSummary) -> Option<String> {
    render_fingerprint_values(
        "Client identity & TLS fingerprints",
        &[
            ("JA3", summary.ja3.as_deref()),
            ("JA4", summary.ja4.as_deref()),
            ("PeetPrint", summary.peetprint.as_deref()),
            ("Known profile", summary.known_fingerprint.as_deref()),
            ("User agent", summary.user_agent.as_deref()),
        ],
    )
}

fn render_http_fingerprint_card(summary: &super::capture::ExchangeSummary) -> Option<String> {
    render_fingerprint_values(
        "HTTP fingerprints",
        &[
            ("JA4H", summary.ja4h.as_deref()),
            ("Akamai HTTP/2", summary.akamai_h2.as_deref()),
        ],
    )
}

fn render_capture_outcomes(records: &[StoredRecord]) -> Option<String> {
    let outcomes = records
        .iter()
        .filter_map(|record| match record {
            StoredRecord::RequestEnd { outcome } => Some(("Request", outcome.as_str())),
            StoredRecord::ResponseEnd { outcome } => Some(("Response", outcome.as_str())),
            StoredRecord::ReplayResult { status, error } => Some((
                "Last replay",
                error.as_deref().unwrap_or(if status.is_some() {
                    "complete"
                } else {
                    "failed"
                }),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    (!outcomes.is_empty()).then(|| {
        div!(
            class = "capture-outcomes",
            outcomes
                .into_iter()
                .map(|(label, outcome)| span!(format!("{label}: {outcome}")))
        )
        .into_string()
    })
}

fn render_websocket_messages(details: &InspectorDetails) -> Option<String> {
    let messages = details
        .records
        .iter()
        .filter_map(|record| match record {
            StoredRecord::WebSocketMessage {
                at,
                direction,
                kind,
                data,
                close_code,
                replayed,
                injected,
            } => Some((at, direction, kind, data, close_code, replayed, injected)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if details.websocket_total == 0 && !details.websocket_replay_active {
        return None;
    }
    let end = details
        .websocket_total
        .saturating_sub(details.websocket_page * MAX_VISIBLE_WS_MESSAGES);
    let start = end.saturating_sub(messages.len());
    let cards = messages.into_iter().enumerate().map(
        |(page_index, (at, direction, kind, encoded, close_code, replayed, injected))| {
            let message_index = start + page_index;
            let (payload, bytes, preview_truncated) = websocket_payload(kind, encoded);
            let ingress = direction.eq_ignore_ascii_case("ingress");
            let is_control = matches!(kind.as_bytes(), b"ping" | b"pong" | b"close");
            let capture_truncated = if ingress {
                details.summary.request_truncated
            } else {
                details.summary.response_truncated
            };
            let can_replay = !is_control && !capture_truncated && details.websocket_replay_active;
            let direction_label = if ingress {
                "Client → Server"
            } else {
                "Server → Client"
            };
            let mut class = match (ingress, is_control) {
                (true, true) => "ws-message ingress control",
                (true, false) => "ws-message ingress",
                (false, true) => "ws-message egress control",
                (false, false) => "ws-message egress",
            }
            .to_owned();
            if *replayed {
                class.push_str(" replayed");
            }
            if *injected {
                class.push_str(" injected");
            }
            article!(
                class = class,
                "data-capture-container" = "",
                div!(
                    class = "ws-message-head",
                    strong!(direction_label),
                    span!(kind.to_ascii_uppercase()),
                    close_code.map(|code| span!(format!("code {code}"))),
                    span!(format_bytes(bytes as u64)),
                    (*replayed).then(|| span!(class = "ws-replayed", "replayed")),
                    (*injected).then(|| span!(class = "ws-injected", "custom")),
                    is_control.then(|| span!("control · observation only")),
                    can_replay.then(|| button!(
                        r#type = "button",
                        class = "ghost compact ws-replay",
                        "data-on:click" = format!(
                            "@post('/api/websocket/{}/replay/{message_index}')",
                            details.summary.id
                        ),
                        if ingress {
                            "Replay to server"
                        } else {
                            "Replay to client"
                        }
                    )),
                    time!(at.clone()),
                ),
                (!payload.is_empty()).then(|| pre!(payload)),
                preview_truncated.then(|| div!(
                    class = "ws-full-message",
                    small!("Preview truncated."),
                    button!(
                        r#type = "button",
                        class = "ghost compact",
                        "data-capture-preview" = "",
                        "data-label" = "Show full message",
                        "data-url" = format!(
                            "/api/capture/{}/websocket/{}",
                            details.summary.id, message_index
                        ),
                        "data-payload-format" = if kind.eq_ignore_ascii_case("text") {
                            "text"
                        } else {
                            "binary"
                        },
                        span!(class = "capture-spinner", "aria-hidden" = "true"),
                        span!("data-capture-label" = "", "Show full message")
                    ),
                    pre!("data-capture-output" = "", hidden = "")
                ))
            )
        },
    );
    let range = if details.websocket_total == 0 {
        "No messages yet".to_owned()
    } else {
        format!(
            "messages {}–{} of {}",
            start + 1,
            end,
            details.websocket_total
        )
    };
    let replay_state = (!details.websocket_replay_active).then(|| {
        span!(
            class = "ws-replay-state",
            title = "Replay is unavailable because this WebSocket connection is closed",
            "Replay off"
        )
    });
    let truncation_state =
        (details.summary.request_truncated || details.summary.response_truncated).then(|| {
            span!(
                class = "ws-capture-state",
                title = "Replay is unavailable for messages in a truncated capture direction",
                "Capture truncated"
            )
        });
    let composer = details.websocket_replay_active.then(|| {
        div!(
            class = "ws-composer",
            div!(
                class = "ws-composer-fields",
                label!(
                    span!("Destination"),
                    select!(
                        "data-bind:websocket_direction" = "",
                        option!(value = "ingress", "Upstream server"),
                        option!(value = "egress", "Downstream client")
                    )
                ),
                label!(
                    span!("Message type"),
                    select!(
                        "data-bind:websocket_kind" = "",
                        option!(value = "text", "Text"),
                        option!(value = "binary", "Binary (base64)")
                    )
                )
            ),
            label!(
                class = "ws-composer-payload",
                span!("Message payload"),
                textarea!(
                    rows = "3",
                    placeholder = "Text message, or base64 when Binary is selected",
                    "data-bind:websocket_payload" = ""
                )
            ),
            div!(
                class = "ws-composer-actions",
                small!(
                    "Injected application messages are captured and cannot create control frames."
                ),
                button!(
                    r#type = "button",
                    class = "primary compact",
                    "data-on:click" =
                        format!("@post('/api/websocket/{}/send')", details.summary.id),
                    "Send message"
                )
            )
        )
    });
    Some(
        section!(
            class = "ws-messages",
            div!(
                class = "ws-messages-title",
                div!(
                    h3!("WebSocket traffic"),
                    span!(range),
                    replay_state,
                    truncation_state
                ),
                div!(
                    class = "ws-page-actions",
                    (start > 0).then(|| button!(
                        class = "ghost compact",
                        "data-on:click" =
                            format!("@post('/api/websocket/{}/older')", details.summary.id),
                        "Older"
                    )),
                    (details.websocket_page > 0).then(|| button!(
                        class = "ghost compact",
                        "data-on:click" =
                            format!("@post('/api/websocket/{}/newer')", details.summary.id),
                        "Newer"
                    ))
                )
            ),
            composer,
            cards.collect::<Vec<_>>()
        )
        .into_string(),
    )
}

fn header_value<'a>(headers: Option<&'a [(String, String)]>, expected: &str) -> Option<&'a str> {
    headers?.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case(expected)
            .then_some(value.as_str())
    })
}

fn is_textual_content_type(content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    content_type.starts_with("text/")
        || [
            "json",
            "xml",
            "javascript",
            "graphql",
            "x-www-form-urlencoded",
        ]
        .iter()
        .any(|needle| content_type.contains(needle))
}

fn preview_text(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let preview = chars.by_ref().take(max_chars).collect::<String>();
    if chars.next().is_some() {
        format!("{preview}…")
    } else {
        preview
    }
}

fn websocket_payload(kind: &str, encoded: &str) -> (String, usize, bool) {
    let Ok(bytes) = STANDARD.decode(encoded) else {
        return ("Invalid captured base64 payload".to_owned(), 0, false);
    };
    if kind.eq_ignore_ascii_case("text") || kind.eq_ignore_ascii_case("close") {
        let truncated = bytes.len() > WS_TEXT_PREVIEW_LIMIT;
        let preview = &bytes[..bytes.len().min(WS_TEXT_PREVIEW_LIMIT)];
        let mut text = String::from_utf8_lossy(preview).into_owned();
        if truncated {
            text.push('…');
        }
        (text, bytes.len(), truncated)
    } else {
        let truncated = bytes.len() > WS_BINARY_PREVIEW_LIMIT;
        let preview = bytes
            .iter()
            .take(WS_BINARY_PREVIEW_LIMIT)
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        (preview, bytes.len(), truncated)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = kib(1) as f64;
    const MIB: f64 = mib(1) as f64;
    match bytes {
        0..=1023 => format!("{bytes} B"),
        1024..=1_048_575 => format!("{:.1} KiB", bytes as f64 / KIB),
        _ => format!("{:.1} MiB", bytes as f64 / MIB),
    }
}

fn display_timestamp(timestamp: &jiff::Timestamp) -> String {
    let timestamp = timestamp.to_string();
    let Some((date, time)) = timestamp.split_once('T') else {
        return timestamp;
    };
    let time = time.strip_suffix('Z').unwrap_or(time);
    let time = match time.split_once('.') {
        Some((whole, fraction)) => {
            let milliseconds = fraction.get(..fraction.len().min(3)).unwrap_or(fraction);
            format!("{whole}.{milliseconds}")
        }
        None => time.to_owned(),
    };
    format!("{date} {time} UTC")
}

const STYLE_CSS: &str = include_str!("dashboard.css");

#[cfg(test)]
mod tests {
    use super::super::capture::{CaptureHttpLayer, StoredRecord};
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use rama::ua::profile::UserAgentDatabase;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn test_state_with_limits(connections: usize, exchanges: usize) -> DashboardState {
        test_state_with_upstream(
            connections,
            exchanges,
            UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        )
    }

    fn test_state_with_upstream(
        connections: usize,
        exchanges: usize,
        upstream: UpstreamProxyConfig,
    ) -> DashboardState {
        let ua_db = Arc::new(UserAgentDatabase::try_embedded().unwrap());
        DashboardState::new(
            CaptureStore::new(connections, exchanges, 1024, ua_db).unwrap(),
            HarController::default(),
            Vec::new(),
            Arc::new(SocketOptions::default_tcp()),
            upstream,
            MitmPolicy::try_new(&[], &[]).unwrap(),
        )
    }

    fn test_state() -> DashboardState {
        test_state_with_limits(8, 8)
    }

    async fn capture_request_for_replay(state: &DashboardState, uri: &str) {
        let capture = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        capture
            .serve(
                Request::builder()
                    .uri(uri)
                    .header("proxy-authorization", "Basic captured-secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
    }

    async fn read_http_head(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            assert_ne!(read, 0, "HTTP request ended before its headers");
            request.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8(request).unwrap()
    }

    #[test]
    fn captured_request_transport_header_policy_is_explicit() {
        let captured = ReplayRequest {
            method: "POST".to_owned(),
            url: "https://example.test/upload".to_owned(),
            version: "HTTP/2".to_owned(),
            protocol: "https".to_owned(),
            headers: vec![
                ("host".to_owned(), "example.test".to_owned()),
                ("content-length".to_owned(), "4".to_owned()),
                ("proxy-authorization".to_owned(), "Basic secret".to_owned()),
                ("x-captured".to_owned(), "yes".to_owned()),
            ],
            body: b"body".to_vec(),
            tls_client_hello: None,
        };

        let (preserved, body, _) = build_captured_request(captured.clone(), false).unwrap();
        assert_eq!(preserved.version(), rama::http::Version::HTTP_2);
        assert_eq!(preserved.headers().len(), 4);
        assert_eq!(body, b"body");

        let (stripped, _, _) = build_captured_request(captured, true).unwrap();
        assert_eq!(stripped.headers().len(), 1);
        assert_eq!(stripped.headers()["x-captured"], "yes");
    }

    fn test_details(records: Vec<StoredRecord>) -> InspectorDetails {
        let websocket_total = records
            .iter()
            .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
            .count();
        InspectorDetails {
            summary: super::super::capture::ExchangeSummary {
                decision: None,
                id: 1,
                connection_id: 1,
                connection_display_id: 1,
                started_at: "1970-01-01T00:00:00Z".parse().unwrap(),
                method: "GET".to_owned(),
                http_version: "HTTP/1.1".to_owned(),
                url: "http://example.test".to_owned(),
                endpoint: "example.test".to_owned(),
                protocol: "http".to_owned(),
                ingress_local_address: None,
                ingress_peer_address: None,
                user_agent: None,
                user_agent_kind: None,
                status: Some(200),
                active: false,
                response_started_at: None,
                completed_at: None,
                egress_local_address: None,
                egress_peer_address: None,
                request_bytes: 0,
                response_bytes: 0,
                request_truncated: false,
                response_truncated: false,
                ja3: None,
                ja4: None,
                peetprint: None,
                ja4h: None,
                akamai_h2: None,
                known_fingerprint: None,
                has_emulation_profile: false,
            },
            records,
            websocket_page: 0,
            websocket_total,
            websocket_replay_active: false,
        }
    }

    #[test]
    fn index_uses_one_persistent_datastar_endpoint_and_external_assets() {
        let rendered = render_index("abc123").into_string();
        assert!(rendered.contains("data-init=\"@get('/events')\""));
        assert_eq!(rendered.matches("@get('/events')").count(), 1);
        assert!(rendered.contains("/assets/datastar.js"));
        assert!(rendered.contains("/assets/har.js"));
        assert!(rendered.contains("/assets/details.js"));
        assert!(rendered.contains("/assets/live.js"));
        assert!(rendered.contains("/assets/preferences.js"));
        assert!(rendered.contains("data-inspector-session=\"abc123\""));
        assert!(LIVE_JS.contains("history.pushState"));
        assert!(LIVE_JS.contains("popstate"));
        assert!(LIVE_JS.contains("/api/focus/"));
        assert!(rendered.contains("/assets/style.css"));
        assert!(rendered.contains("/assets/rama-logo.svg"));
        assert!(rendered.contains("rel=\"icon\""));
        assert!(rendered.contains("type=\"image/svg+xml\""));
        assert!(!rendered.contains("ラマ"));
        assert!(rendered.contains("Rama Proxy Inspector"));
        assert!(rendered.contains("class=\"brand\" href=\"/\" data-inspector-focus=\"overview\""));
        assert!(rendered.contains("id=\"connection-status\""));
        assert!(rendered.contains(">connecting</span>"));
        assert!(rendered.contains("@post('/api/inspection/pause')"));
        assert!(rendered.contains("@post('/api/inspection/resume')"));
        assert!(rendered.contains("data-indicator:inspection_busy"));
        assert!(rendered.contains("id=\"live-heartbeat\""));
        assert!(!rendered.contains("encrypted-at-rest capture"));
        for signal in [
            "connection_id",
            "endpoint",
            "user_agent",
            "method",
            "status",
            "protocol",
        ] {
            assert!(rendered.contains(&format!("data-bind:{signal}")));
        }
        assert!(rendered.contains("Reset filters"));
        assert!(rendered.contains("MITM domain scope"));
        assert!(rendered.contains("data-mitm-policy=\"allow\""));
        assert!(rendered.contains("data-mitm-policy=\"deny\""));
        assert!(PREFERENCES_JS.contains("window.localStorage"));
        assert!(PREFERENCES_JS.contains("/api/mitm-policy"));
        assert!(LIVE_JS.contains("data-connection-page-action"));
        assert!(rendered.contains("id=\"clear-captures-dialog\""));
        assert!(rendered.contains("Clear captured traffic?"));
        assert!(rendered.contains("@post('/api/captures/clear')"));
        for signal in ["websocket_direction", "websocket_kind", "websocket_payload"] {
            assert!(rendered.contains(&format!("data-signals:{signal}")));
        }
        assert!(!rendered.contains("data-signals:har_path"));
        assert!(!rendered.contains("HAR output file"));
        assert!(rendered.contains("name=\"har-download\""));
        assert!(!HAR_JS.contains("showSaveFilePicker"));
        assert!(HAR_JS.contains("browser-download"));
        assert!(!rendered.contains("<style>"));
        for protocol in ["HTTP", "HTTPS", "WS", "WSS", "Other"] {
            assert!(rendered.contains(&format!(">{protocol}</option>")));
        }
        assert!(!rendered.contains(">SOCKS5</option>"));
    }

    #[tokio::test]
    async fn pending_traffic_uses_request_rows_without_creating_captures() {
        use super::super::control::{Config, ControlConnection, Message};
        let state = test_state();
        state.ensure_session("known");
        let control = state.capture.control();
        control
            .configure(
                0,
                Config {
                    enabled: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let mut changes = control.subscribe();
        let task = tokio::spawn({
            let control = control.clone();
            async move {
                control
                    .decide(
                        &ControlConnection::new(91),
                        Message {
                            exchange: Some(71),
                            connection: 91,
                            protocol: "https".into(),
                            direction: "request".into(),
                            method: "GET".into(),
                            url: "https://example.test/<script>".into(),
                            ..Default::default()
                        },
                    )
                    .await
            }
        });
        changes.changed().await.unwrap();
        let pending = control.pending_summaries();
        let rendered = state.render_live("known", 1).await;
        assert_eq!(rendered.matches("id=\"request-71\"").count(), 1);
        assert!(rendered.contains("Awaiting request approval"));
        assert!(rendered.contains("id=\"approval-slot-1\" data-ignore-morph"));
        assert!(!rendered.contains("https://example.test/<script>"));
        assert!(rendered.contains("<span>Requests</span><strong>0</strong>"));
        let fixture = test_state();
        capture_request_for_replay(&fixture, "http://example.test/").await;
        let mut exchange = fixture
            .capture
            .snapshot_limited_for_connections(&CaptureFilter::default(), &BTreeSet::new(), 0, 8, 8)
            .await
            .exchanges
            .pop()
            .unwrap();
        exchange.id = 71;
        let live = LiveStatus {
            recording: true,
            pending,
        };
        assert!(render_pending_fallbacks(&live.pending, &[exchange.clone()], None).is_empty());
        let row = render_focused_request_row(&exchange, &live).into_string();
        assert!(row.contains("id=\"request-71\""));
        assert!(row.contains("id=\"approval-slot-1\""));
        control.stop_and_forward();
        task.await.unwrap();
        assert!(
            !state
                .render_live("known", 2)
                .await
                .contains("id=\"request-71\"")
        );
    }

    #[tokio::test]
    async fn inspection_pause_and_resume_are_global_but_session_authenticated() {
        let state = test_state();
        state.ensure_session("known");
        let signals = |session: &str| {
            ReadSignals(UiSignals {
                session: session.to_owned(),
                ..Default::default()
            })
        };

        assert_eq!(
            pause_inspection(State(state.clone()), signals("unknown")).await,
            StatusCode::NOT_FOUND
        );
        assert!(state.inspection.is_enabled());
        assert_eq!(
            pause_inspection(State(state.clone()), signals("known")).await,
            StatusCode::NO_CONTENT
        );
        assert!(!state.inspection.is_enabled());
        let paused = state.render_live("known", 1).await;
        assert!(paused.contains("data-inspection-paused=\"true\""));
        assert!(paused.contains("Inspector paused"));
        assert_eq!(
            resume_inspection(State(state.clone()), signals("known")).await,
            StatusCode::NO_CONTENT
        );
        assert!(state.inspection.is_enabled());
        let resumed = state.render_live("known", 2).await;
        assert!(resumed.contains("data-inspection-paused=\"false\""));
        assert!(!resumed.contains("Inspector paused"));
    }

    #[tokio::test]
    async fn connection_history_is_windowed_to_one_hundred_rows() {
        fn pager_button<'a>(html: &'a str, action: &str) -> &'a str {
            let marker = format!("data-connection-page-action=\"{action}\"");
            let marker_index = html.find(&marker).unwrap();
            let start = html[..marker_index].rfind("<button").unwrap();
            let end = marker_index + html[marker_index..].find('>').unwrap();
            &html[start..=end]
        }

        let state = test_state_with_limits(256, 8);
        for _ in 0..105 {
            let id = state.capture.begin_connection(None, "http");
            state.capture.confirm_connection(id);
        }
        state.ensure_session("known");

        let newest = state.render_live("known", 0).await;
        assert_eq!(newest.matches("<article class=\"connection").count(), 100);
        assert!(newest.contains("1–100 of 105"));
        assert!(newest.contains("data-connection-page=\"0\""));
        assert!(newest.contains("data-has-older=\"true\""));
        assert!(!pager_button(&newest, "older").contains(" disabled"));
        assert!(pager_button(&newest, "newer").contains(" disabled"));
        assert!(!newest.contains("disabled=\"false\""));

        assert_eq!(
            older_connections(
                State(state.clone()),
                ReadSignals(UiSignals {
                    session: "known".to_owned(),
                    ..Default::default()
                }),
            )
            .await,
            StatusCode::NO_CONTENT
        );
        let older = state.render_live("known", 1).await;
        assert_eq!(older.matches("<article class=\"connection").count(), 5);
        assert!(older.contains("101–105 of 105"));
        assert!(older.contains("data-connection-page=\"1\""));
        assert!(older.contains("data-has-newer=\"true\""));
        assert!(!pager_button(&older, "newer").contains(" disabled"));
        assert!(pager_button(&older, "older").contains(" disabled"));

        let cursor = state.session("known").connection_cursors[1];
        let before_insert = state
            .capture
            .snapshot_limited_before_connection(
                &CaptureFilter::default(),
                &BTreeSet::new(),
                cursor,
                MAX_VISIBLE_CONNECTIONS,
                MAX_VISIBLE_EXCHANGES,
            )
            .await
            .connections
            .into_iter()
            .map(|connection| connection.id)
            .collect::<Vec<_>>();
        let new_id = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(new_id);
        let after_insert = state
            .capture
            .snapshot_limited_before_connection(
                &CaptureFilter::default(),
                &BTreeSet::new(),
                cursor,
                MAX_VISIBLE_CONNECTIONS,
                MAX_VISIBLE_EXCHANGES,
            )
            .await
            .connections
            .into_iter()
            .map(|connection| connection.id)
            .collect::<Vec<_>>();
        assert_eq!(after_insert, before_insert);
        let refreshed_older = state.render_live("known", 2).await;
        assert_eq!(
            refreshed_older
                .matches("<article class=\"connection")
                .count(),
            5
        );

        assert_eq!(
            newer_connections(
                State(state.clone()),
                ReadSignals(UiSignals {
                    session: "known".to_owned(),
                    ..Default::default()
                }),
            )
            .await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").connection_page, 0);
    }

    #[tokio::test]
    async fn dashboard_mitm_policy_is_session_authenticated_and_deny_wins() {
        let state = test_state();
        state.ensure_session("known");
        let update = |session: &str| {
            Json(MitmPolicyUpdate {
                session: session.to_owned(),
                allow: vec!["example.test".to_owned()],
                deny: vec!["private.example.test".to_owned()],
                mode: super::super::mitm_policy::ScopeMode::All,
            })
        };
        assert_eq!(
            update_mitm_policy(State(state.clone()), update("unknown"))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            update_mitm_policy(State(state.clone()), update("known"))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert!(
            state.mitm_policy.should_inspect_host(
                &rama::net::address::Host::try_from("api.example.test").unwrap()
            )
        );
        assert!(!state.mitm_policy.should_inspect_host(
            &rama::net::address::Host::try_from("private.example.test").unwrap()
        ));
        assert!(
            !state
                .mitm_policy
                .should_inspect_host(&rama::net::address::Host::try_from("other.test").unwrap())
        );
    }

    #[test]
    fn details_are_escaped_by_rama_html() {
        let mut details = test_details(vec![StoredRecord::RequestBody {
            data: BASE64.encode("<script>alert(1)</script>"),
        }]);
        details.summary.user_agent = Some("</pre><script>alert(1)</script>".to_owned());
        let rendered = render_details(&details).into_string();
        assert!(!rendered.contains("<script>alert(1)</script>"));
        assert!(!rendered.contains("</pre>"));
    }

    #[test]
    fn unicode_header_values_are_bounded_on_a_character_boundary() {
        let details = test_details(vec![StoredRecord::RequestHead {
            method: "GET".to_owned(),
            url: "http://example.test".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![("x-unicode".to_owned(), "é".repeat(5_000))],
            emulation_profile: None,
            tls_client_hello: None,
            ingress_tls: None,
        }]);

        let rendered = render_details(&details).into_string();
        assert!(rendered.contains(&format!("{}…", "é".repeat(4_096))));
        assert!(!rendered.contains(&"é".repeat(4_097)));
    }

    #[test]
    fn request_details_keep_tls_on_connection_and_render_lazy_http_data() {
        let client_hello = rama::tls::client::ClientHello::new(
            rama::tls::ProtocolVersion::TLSv1_2,
            vec![
                rama::tls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rama::tls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            Vec::new(),
            vec![
                rama::tls::client::ClientHelloExtension::SupportedGroups(vec![
                    rama::tls::SupportedGroup::X25519,
                    rama::tls::SupportedGroup::SECP256R1,
                ]),
                rama::tls::client::ClientHelloExtension::SignatureAlgorithms(vec![
                    rama::tls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rama::tls::SignatureScheme::RSA_PSS_SHA256,
                ]),
                rama::tls::client::ClientHelloExtension::Opaque {
                    id: rama::tls::ExtensionId::SESSION_TICKET,
                    data: Vec::new(),
                },
            ],
        );
        let mut details = test_details(vec![
            StoredRecord::RequestHead {
                method: "POST".to_owned(),
                url: "https://example.test/upload".to_owned(),
                version: "HTTP/2.0".to_owned(),
                headers: vec![
                    ("content-type".to_owned(), "application/json".to_owned()),
                    ("x-request".to_owned(), "yes".to_owned()),
                ],
                emulation_profile: Some(serde_json::json!({ "user_agent": "Chromium" })),
                tls_client_hello: Some(client_hello),
                ingress_tls: Some(CapturedTlsParameters {
                    protocol_version: rama::tls::ProtocolVersion::TLSv1_3,
                    application_layer_protocol: Some(rama::net::tls::ApplicationProtocol::HTTP_2),
                    peer_certificate_count: Some(1),
                }),
            },
            StoredRecord::ResponseHead {
                status: 201,
                version: "HTTP/2.0".to_owned(),
                headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
                egress_tls: Some(CapturedTlsParameters {
                    protocol_version: rama::tls::ProtocolVersion::TLSv1_3,
                    application_layer_protocol: Some(rama::net::tls::ApplicationProtocol::HTTP_2),
                    peer_certificate_count: Some(2),
                }),
            },
        ]);
        details.summary.method = "POST".to_owned();
        details.summary.protocol = "https".to_owned();
        details.summary.http_version = "HTTP/2".to_owned();
        details.summary.request_bytes = 128;
        details.summary.response_bytes = 64;
        details.summary.egress_peer_address = Some("[2606:4700:10::6814:17aa]:443".to_owned());
        details.summary.ja3 = Some("ja3-value".to_owned());
        details.summary.has_emulation_profile = true;

        let rendered = render_details(&details).into_string();
        for expected in [
            "Request headers",
            "Response headers · 201 HTTP/2.0",
            "Request payload",
            "Response payload",
            "data-capture-preview",
            "capture-spinner",
            "/api/capture/1/body/request?limit=65536",
            "Stream captured body",
            "header-name\">x-request",
            ">yes</span>",
            "data-copy-header",
            "data-copy-target",
            "data-copy-overview",
            "data-copy-curl=\"/api/capture/1/curl\"",
            "/api/har/export?ids=1",
            "[2606:4700:10::6814:17aa]:443",
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
        assert!(!rendered.contains("Handshake &amp; capture metadata"));
        assert!(!rendered.contains("Emulation profile"));
        assert!(!rendered.contains("Chromium"));
        assert!(!rendered.contains("RequestBody"));
        assert!(!rendered.contains("Client hello"));
        assert!(!rendered.contains("Client ↔ inspector"));
        assert!(!rendered.contains("ja3-value"));

        let connection_tls = render_connection_tls(&details);
        for expected in [
            "Client hello",
            "Client ↔ inspector",
            "Inspector ↔ server",
            "TLS 1.3",
            "h2",
            "Client identity &amp; TLS fingerprints",
            "ja3-value",
            "tls-offer",
            "2 offered",
            "TLS13_AES_128_GCM_SHA256 (0x1301)",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)",
            "SUPPORTED_GROUPS (0x000a)",
            "SESSION_TICKET (0x0023)",
            "X25519 (0x001d)",
            "SECP256R1 (0x0017)",
            "ECDSA_NISTP256_SHA256 (0x0403)",
            "RSA_PSS_SHA256 (0x0804)",
        ] {
            assert!(connection_tls.contains(expected), "missing {expected}");
        }
        assert!(!connection_tls.contains("<details open"));
        assert!(!connection_tls.contains("protocol_version"));
    }

    #[test]
    fn websocket_details_decode_directional_text_and_binary_cards() {
        let mut details = test_details(vec![
            StoredRecord::WebSocketMessage {
                at: "2026-08-22T20:00:00Z".to_owned(),
                direction: "Ingress".to_owned(),
                kind: "text".to_owned(),
                data: BASE64.encode("hello over websocket"),
                close_code: None,
                replayed: false,
                injected: false,
            },
            StoredRecord::WebSocketMessage {
                at: "2026-08-22T20:00:01Z".to_owned(),
                direction: "Egress".to_owned(),
                kind: "binary".to_owned(),
                data: BASE64.encode([0, 1, 254, 255]),
                close_code: None,
                replayed: true,
                injected: false,
            },
            StoredRecord::RequestHead {
                method: "GET".to_owned(),
                url: "https://example.test/socket".to_owned(),
                version: "HTTP/1.1".to_owned(),
                headers: vec![("upgrade".to_owned(), "websocket".to_owned())],
                emulation_profile: None,
                tls_client_hello: None,
                ingress_tls: None,
            },
            StoredRecord::ResponseHead {
                status: 101,
                version: "HTTP/1.1".to_owned(),
                headers: vec![("upgrade".to_owned(), "websocket".to_owned())],
                egress_tls: None,
            },
        ]);
        details.summary.protocol = "wss".to_owned();
        details.websocket_replay_active = true;

        let rendered = render_details(&details).into_string();
        assert!(!rendered.contains("data-copy-curl"));
        assert!(rendered.contains("WebSocket traffic"));
        assert!(rendered.contains("Upstream server"));
        assert!(rendered.contains("Downstream client"));
        assert!(rendered.contains("Binary (base64)"));
        assert!(rendered.contains("/api/websocket/1/send"));
        assert!(rendered.contains("Client → Server"));
        assert!(rendered.contains("Server → Client"));
        assert!(rendered.contains("hello over websocket"));
        assert!(rendered.contains("00 01 fe ff"));
        assert!(rendered.contains("Replay to server"));
        assert!(rendered.contains("Replay to client"));
        assert!(rendered.contains("/api/websocket/1/replay/0"));
        assert!(rendered.contains("/api/websocket/1/replay/1"));
        assert!(rendered.contains("ws-message egress replayed"));
        assert!(!rendered.contains("Replay off"));
        let headers = rendered.find("Request headers").unwrap();
        let messages = rendered.find("WebSocket traffic").unwrap();
        assert!(
            headers < messages,
            "WebSocket messages should follow headers"
        );
        assert!(!rendered.contains("TLS client hello"));
        assert!(!rendered.contains(&BASE64.encode("hello over websocket")));
        assert!(!rendered.contains("Handshake &amp; capture metadata"));
    }

    #[test]
    fn websocket_previews_are_bounded_and_paginated() {
        assert!(render_websocket_messages(&test_details(Vec::new())).is_none());

        let invalid = websocket_payload("text", "not base64!");
        assert_eq!(
            invalid,
            ("Invalid captured base64 payload".to_owned(), 0, false)
        );

        let text_limit = vec![b'a'; WS_TEXT_PREVIEW_LIMIT];
        let exact_text = websocket_payload("text", &BASE64.encode(&text_limit));
        assert_eq!(exact_text.1, WS_TEXT_PREVIEW_LIMIT);
        assert!(!exact_text.2);
        let long_text =
            websocket_payload("text", &BASE64.encode([text_limit, vec![b'b']].concat()));
        assert_eq!(long_text.1, WS_TEXT_PREVIEW_LIMIT + 1);
        assert!(long_text.2);
        assert!(long_text.0.ends_with('…'));

        let exact_binary =
            websocket_payload("binary", &BASE64.encode([0; WS_BINARY_PREVIEW_LIMIT]));
        assert!(!exact_binary.2);
        let long_binary =
            websocket_payload("binary", &BASE64.encode([0; WS_BINARY_PREVIEW_LIMIT + 1]));
        assert_eq!(long_binary.1, WS_BINARY_PREVIEW_LIMIT + 1);
        assert!(long_binary.2);

        let record = StoredRecord::WebSocketMessage {
            at: "now".to_owned(),
            direction: "Ingress".to_owned(),
            kind: "text".to_owned(),
            data: BASE64.encode(vec![b'm'; WS_TEXT_PREVIEW_LIMIT + 1]),
            close_code: None,
            replayed: false,
            injected: false,
        };
        let mut details = test_details(vec![record; MAX_VISIBLE_WS_MESSAGES]);
        details.websocket_total = MAX_VISIBLE_WS_MESSAGES + 1;
        let rendered =
            render_websocket_messages(&details).expect("messages render a WebSocket section");
        assert!(rendered.contains("messages 2–101 of 101"));
        assert!(rendered.contains("Older"));
        assert!(!rendered.contains("Newer"));
        assert!(rendered.contains("Show full message"));
        assert!(rendered.contains("/api/capture/1/websocket/1"));
        assert_eq!(
            rendered.matches("class=\"ws-message ingress\"").count(),
            100
        );
        assert_eq!(rendered.matches("Replay off").count(), 1);
        assert!(!rendered.contains("connection closed · replay unavailable"));

        details.summary.request_truncated = true;
        let rendered = render_websocket_messages(&details).unwrap();
        assert_eq!(rendered.matches("Capture truncated").count(), 1);
        assert!(!rendered.contains("capture truncated · replay unavailable"));

        details.records.truncate(1);
        details.websocket_page = 1;
        let rendered = render_websocket_messages(&details).unwrap();
        assert!(rendered.contains("messages 1–1 of 101"));
        assert!(!rendered.contains("Older"));
        assert!(rendered.contains("Newer"));
    }

    #[test]
    fn websocket_control_events_are_visible_but_not_replayable() {
        let mut details = test_details(vec![StoredRecord::WebSocketMessage {
            at: "now".to_owned(),
            direction: "Egress".to_owned(),
            kind: "close".to_owned(),
            data: BASE64.encode("going away"),
            close_code: Some(1001),
            replayed: false,
            injected: false,
        }]);
        details.summary.protocol = "wss".to_owned();
        details.websocket_replay_active = true;

        let rendered = render_details(&details).into_string();
        assert!(rendered.contains("CLOSE"));
        assert!(rendered.contains("code 1001"));
        assert!(rendered.contains("control · observation only"));
        assert!(rendered.contains("going away"));
        assert!(!rendered.contains("Replay with profile"));
        assert!(!rendered.contains("/api/websocket/1/replay/"));
    }

    #[test]
    fn presentation_helpers_cover_boundaries() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1_048_575), "1024.0 KiB");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
        assert_eq!(status_class(Some(199)), "status");
        assert_eq!(status_class(Some(200)), "status ok");
        assert_eq!(status_class(Some(399)), "status ok");
        assert_eq!(status_class(Some(400)), "status error");
        assert_eq!(status_class(Some(599)), "status error");
        assert_eq!(status_class(None), "status");
        assert_eq!(format_response_status(200), "200 OK");
        assert_eq!(format_response_status(404), "404 Not Found");
        assert_eq!(
            tls_version_label(rama::tls::ProtocolVersion::TLSv1_3),
            "TLS 1.3"
        );
        assert_eq!(
            display_timestamp(&"2026-08-23T19:19:35.568646Z".parse().unwrap()),
            "2026-08-23 19:19:35.568 UTC"
        );

        let mut summary = test_details(Vec::new()).summary;
        summary.protocol = "https".to_owned();
        let protocol = render_protocol_badge(&summary);
        assert!(protocol.contains("protocol-lock"));
        assert!(protocol.contains("HTTPS"));
        assert!(protocol.contains("HTTP/1.1"));
        summary.status = None;
        summary.active = true;
        let waiting = render_exchange_status(&summary);
        assert!(waiting.contains("data-response-state=\"waiting\""));
        assert!(waiting.contains("response-spinner"));
        assert!(waiting.contains("Waiting for response"));

        summary.status = Some(200);
        let streaming = render_exchange_status(&summary);
        assert!(streaming.contains("data-response-state=\"streaming\""));
        assert!(streaming.contains("response-spinner"));
        assert!(streaming.contains("200 OK"));
        assert!(!streaming.contains("complete"));

        summary.protocol = "wss".to_owned();
        summary.status = Some(101);
        let live_websocket = render_exchange_status(&summary);
        assert!(live_websocket.contains("data-response-state=\"live\""));
        assert!(live_websocket.contains("response-live-dot"));
        assert!(live_websocket.contains("101 Switching Protocols"));

        summary.active = false;
        let finished = render_exchange_status(&summary);
        assert!(finished.contains("data-response-state=\"finished\""));
        assert!(!finished.contains("response-live-dot"));
        assert!(!finished.contains("complete"));

        summary.status = None;
        let no_response = render_exchange_status(&summary);
        assert!(no_response.contains("data-response-state=\"no-response\""));
        assert!(no_response.contains("No response"));
        assert_eq!(escape_js_string(r"a\b'c"), r"a\\b\'c");
        assert!(is_textual_content_type("application/problem+json"));
        assert!(is_textual_content_type("text/event-stream; charset=utf-8"));
        assert!(!is_textual_content_type("application/octet-stream"));
    }

    #[tokio::test]
    async fn connection_rows_support_session_local_multi_selection() {
        let state = test_state();
        let first = state.capture.begin_connection(None, "http");
        let second = state.capture.begin_connection(None, "https");
        state.capture.confirm_connection(first);
        state.capture.confirm_connection(second);
        state.capture.finish_connection(first);
        state.ensure_session("known");
        state
            .sessions
            .write()
            .get_mut("known")
            .unwrap()
            .selected_connections
            .insert(first);

        let rendered = state.render_live("known", 0).await;
        assert!(rendered.contains(&format!("/api/connection/{first}")));
        assert!(rendered.contains(&format!("/api/connection/{second}")));
        assert!(rendered.contains("aria-pressed=\"true\""));
        assert!(rendered.contains("connection-state closed"));
        assert!(rendered.contains("connection-state alive"));
        assert!(rendered.contains("started "));
        assert!(rendered.contains("unknown → unknown"));
        assert!(rendered.contains("1 selected"));
        assert!(rendered.contains("1 connection(s)"));
        assert!(rendered.contains("/api/profiles.json?session=known"));
        assert!(rendered.contains("/api/connections/clear"));
    }

    #[tokio::test]
    async fn overview_numbers_only_confirmed_proxy_connections() {
        let state = test_state();
        let dashboard = state.capture.begin_connection(None, "classifying");
        assert!(state.capture.discard_connection_if_empty(dashboard));
        let proxy = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(proxy);
        state.ensure_session("known");
        let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        service
            .serve(
                Request::builder()
                    .uri("http://example.test/")
                    .extension(ConnectionId(proxy))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        let rendered = state.render_live("known", 0).await;
        assert!(rendered.contains("aria-label=\"Select connection #1\""));
        assert!(!rendered.contains("aria-label=\"Select connection #2\""));
        assert!(rendered.contains("conn #1"));
        assert!(rendered.contains(&format!("/api/connection/{proxy}")));
    }

    #[tokio::test]
    async fn request_rows_distinguish_response_lifecycle_and_offer_inline_replay() {
        let state = test_state();
        let connection_id = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(connection_id);
        state.ensure_session("known");
        let success = super::super::capture::CaptureHttpLayer::new(Some(state.capture.clone()))
            .into_layer(rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(Response::new(Body::from("response")))
            }));
        let request = Request::builder()
            .uri("http://example.test/streaming")
            .extension(super::super::capture::ConnectionId(connection_id))
            .body(Body::empty())
            .unwrap();
        let response = success.serve(request).await.unwrap();

        let streaming = state.render_live("known", 0).await;
        assert!(streaming.contains("data-response-state=\"streaming\""));
        assert!(streaming.contains("200 OK"));
        assert!(streaming.contains("response-spinner"));
        assert!(streaming.contains("/api/replay/1"));
        assert!(streaming.contains("replay-inline"));
        assert!(streaming.contains(">Replay</button>"));

        response.into_body().collect().await.unwrap();
        let failed = super::super::capture::CaptureHttpLayer::new(Some(state.capture.clone()))
            .into_layer(rama::service::service_fn(async |_request: Request| {
                Err::<Response<Body>, _>("origin failed")
            }));
        let request = Request::builder()
            .uri("http://example.test/failed")
            .extension(super::super::capture::ConnectionId(connection_id))
            .body(Body::empty())
            .unwrap();
        failed.serve(request).await.unwrap_err();

        let completed = state.render_live("known", 1).await;
        assert!(completed.contains("data-response-state=\"finished\""));
        assert!(completed.contains("200 OK"));
        assert!(completed.contains("data-response-state=\"no-response\""));
        assert!(completed.contains("No response"));
        assert!(!completed.contains("· complete"));
    }

    #[tokio::test]
    async fn focused_connection_and_request_views_are_session_local_and_live() {
        let state = test_state();
        let connection_id = state.capture.begin_connection(None, "https");
        state.capture.confirm_connection(connection_id);
        state.ensure_session("known");
        let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(Response::new(Body::from("focused response")))
            }),
        );
        service
            .serve(
                Request::builder()
                    .uri("https://example.test/focused")
                    .extension(ConnectionId(connection_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        let signals = || {
            ReadSignals(UiSignals {
                session: "known".to_owned(),
                ..Default::default()
            })
        };

        assert_eq!(
            focus_connection(
                State(state.clone()),
                Path(IdPath { id: connection_id }),
                signals(),
            )
            .await,
            StatusCode::NO_CONTENT
        );
        let connection = state.render_live("known", 0).await;
        assert!(connection.contains("connection-focus"));
        assert!(connection.contains("Connection #1"));
        assert!(connection.contains("Requests · 1"));
        assert!(
            connection.contains("data-inspector-focus=\"request\""),
            "{connection}"
        );
        assert!(connection.contains("https://example.test/focused"));

        assert_eq!(
            focus_request(State(state.clone()), Path(IdPath { id: 1 }), signals(),).await,
            StatusCode::NO_CONTENT
        );
        let request = state.render_live("known", 1).await;
        assert!(request.contains("request-focus"));
        assert!(request.contains("GET request #1"));
        assert!(request.contains("data-inspector-back"));
        assert!(request.contains("class=\"breadcrumbs\""));
        assert!(request.contains("data-inspector-focus=\"overview\""));
        assert!(request.contains("data-inspector-focus=\"connection\""));
        assert!(request.contains("Request headers"));
        assert_eq!(
            older_websocket_messages(State(state.clone()), Path(IdPath { id: 1 }), signals(),)
                .await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").websocket_pages.get(&1), Some(&1));

        assert_eq!(
            clear_focus(State(state.clone()), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").focus, UiFocus::Overview);
        assert!(
            state
                .render_live("known", 2)
                .await
                .contains("class=\"workspace\"")
        );
    }

    #[tokio::test]
    async fn direct_focus_query_initializes_the_new_dashboard_session() {
        let state = test_state();
        let response = index(
            State(state.clone()),
            Query(FocusQuery {
                connection: Some(3),
                request: Some(9),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.sessions.read().len(), 1);
        assert!(
            state
                .sessions
                .read()
                .values()
                .all(|session| session.focus == UiFocus::Request(9))
        );
    }

    #[tokio::test]
    async fn focused_connection_is_not_retired_by_the_overview_display_limit() {
        let state = test_state();
        let oldest = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(oldest);
        for _ in 0..MAX_VISIBLE_CONNECTIONS {
            let id = state.capture.begin_connection(None, "http");
            state.capture.confirm_connection(id);
        }
        state.ensure_session("known");
        assert_eq!(
            focus_connection(
                State(state.clone()),
                Path(IdPath { id: oldest }),
                ReadSignals(UiSignals {
                    session: "known".to_owned(),
                    ..Default::default()
                }),
            )
            .await,
            StatusCode::NO_CONTENT
        );

        let rendered = state.render_live("known", 0).await;
        assert!(rendered.contains(&format!("Connection #{oldest}")));
        assert!(!rendered.contains("Connection unavailable"));
    }

    #[tokio::test]
    async fn har_control_is_compact_and_streams_a_cross_browser_download() {
        let state = test_state();
        state.ensure_session("known");

        let inactive = state.render_live("known", 0).await;
        assert!(inactive.contains("class=\"request-tools\""));
        assert!(inactive.contains("data-har-action=\"start\""));
        assert!(inactive.contains("Record HAR"));
        assert!(!inactive.contains("HAR output file"));

        let response = start_har(
            State(state.clone()),
            Query(StartHarQuery {
                session: "known".to_owned(),
                file_name: "picked.har".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let active = state.render_live("known", 0).await;
        assert!(active.contains("HAR recording"));
        assert!(active.contains("method=\"post\""));
        assert!(active.contains("action=\"/api/har/stop?session=known\""));
        assert!(active.contains("target=\"har-download\""));
        assert!(active.contains("Stop &amp; download"));

        let response = stop_har(
            State(state.clone()),
            Query(HarSessionQuery {
                session: "known".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(
            response.headers()["content-disposition"],
            "attachment; filename=\"picked.har\""
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value.get("log").is_some());
        assert!(!state.har.status().active);

        let response = start_har(
            State(state),
            Query(StartHarQuery {
                session: "unknown".to_owned(),
                file_name: "ignored.har".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn selected_connections_and_requests_export_har_and_copy_as_curl() {
        let state = test_state();
        state.ensure_session("known");
        let first_connection = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(first_connection);
        let second_connection = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(second_connection);
        let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::CREATED)
                        .header("content-type", "text/plain")
                        .body(Body::from("response-body"))
                        .unwrap(),
                )
            }),
        );
        for (connection, url, body) in [
            (
                first_connection,
                "http://first.example.test/path?q=one",
                "first-body",
            ),
            (
                second_connection,
                "http://second.example.test/submit",
                "second-body",
            ),
        ] {
            service
                .serve(
                    Request::builder()
                        .method(Method::POST)
                        .uri(url)
                        .header("content-type", "text/plain")
                        .header("x-captured", "yes")
                        .header("proxy-connection", "keep-alive")
                        .header("proxy-authorization", "Basic c2VjcmV0")
                        .extension(ConnectionId(connection))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap();
        }
        let web_socket_connection = state.capture.begin_connection(None, "http");
        state.capture.confirm_connection(web_socket_connection);
        let web_socket_service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "websocket")
                        .body(Body::empty())
                        .unwrap(),
                )
            }),
        );
        web_socket_service
            .serve(
                Request::builder()
                    .uri("http://socket.example.test/chat")
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .extension(ConnectionId(web_socket_connection))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        state
            .capture
            .record_websocket_message(
                3,
                "Ingress".to_owned(),
                "text".to_owned(),
                b"hello websocket".to_vec(),
                None,
            )
            .await;
        state
            .capture
            .record_websocket_message(
                3,
                "Egress".to_owned(),
                "binary".to_owned(),
                vec![0, 1, 255],
                None,
            )
            .await;
        state
            .capture
            .record_websocket_message(
                3,
                "Ingress".to_owned(),
                "ping".to_owned(),
                b"control".to_vec(),
                None,
            )
            .await;
        {
            let mut sessions = state.sessions.write();
            let session = sessions.get_mut("known").unwrap();
            session.selected_connections.insert(first_connection);
            session.selected.insert(2);
            session.selected.insert(3);
        }

        let rendered = state.render_live("known", 0).await;
        assert!(rendered.contains("/api/har/export?session=known"));
        assert!(rendered.contains("data-har-export"));
        assert!(rendered.contains("data-copy-curl=\"/api/capture/1/curl\""));

        let response = export_har(
            State(state.clone()),
            Query(ExportQuery {
                session: Some("known".to_owned()),
                ids: None,
                connection_ids: None,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(
            response.headers()["content-disposition"]
                .to_str()
                .unwrap()
                .starts_with("attachment; filename=\"rama-proxy-selection-")
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json = std::str::from_utf8(&body).unwrap();
        assert!(json.contains("\"send\":0"), "{json}");
        assert!(json.contains("\"wait\":"), "{json}");
        assert!(json.contains("\"receive\":"), "{json}");
        let log: rama::http::layer::har::spec::LogFile = serde_json::from_slice(&body).unwrap();
        assert_eq!(log.log.entries.len(), 3);
        assert_eq!(
            log.log.entries[0].request.url,
            "http://first.example.test/path?q=one"
        );
        assert_eq!(
            log.log.entries[0]
                .request
                .post_data
                .as_ref()
                .and_then(|data| data.text.as_deref()),
            Some("first-body")
        );
        assert_eq!(log.log.entries[0].response.status, 201);
        assert_eq!(
            log.log.entries[0].response.content.text.as_deref(),
            Some("response-body")
        );
        assert_eq!(log.log.entries[0].connection.as_deref(), Some("1"));
        assert_eq!(log.log.entries[1].connection.as_deref(), Some("2"));
        assert_eq!(
            log.log.entries[2].resource_type.as_deref(),
            Some("websocket")
        );
        let web_socket_messages = log.log.entries[2].web_socket_messages.as_ref().unwrap();
        assert_eq!(web_socket_messages.len(), 2);
        assert_eq!(
            web_socket_messages[0].r#type,
            rama::http::layer::har::spec::WebSocketMessageType::Send
        );
        assert_eq!(web_socket_messages[0].data, "hello websocket");
        assert_eq!(
            web_socket_messages[1].opcode,
            rama::http::layer::har::spec::WebSocketMessageOpcode::BINARY
        );
        assert_eq!(web_socket_messages[1].data, "AAH/");

        let response = export_har(
            State(state.clone()),
            Query(ExportQuery {
                session: None,
                ids: Some("2, invalid, 2".to_owned()),
                connection_ids: Some(format!(" {first_connection} ")),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let log: rama::http::layer::har::spec::LogFile = serde_json::from_slice(&body).unwrap();
        assert_eq!(log.log.entries.len(), 2);
        assert_eq!(log.log.entries[0].connection.as_deref(), Some("1"));
        assert_eq!(log.log.entries[1].connection.as_deref(), Some("2"));

        let response = request_curl(State(state), Path(IdPath { id: 1 })).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
        let command = String::from_utf8(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        let command_prefix = if cfg!(windows) {
            "& (Get-Command curl -CommandType Application).Source"
        } else {
            "curl"
        };
        assert!(command.starts_with(command_prefix), "{command}");
        assert!(
            command.contains("http://first.example.test/path?q=one"),
            "{command}"
        );
        assert!(command.contains("x-captured: yes"), "{command}");
        assert!(command.contains("first-body"), "{command}");
        assert!(!command.to_ascii_lowercase().contains("proxy-connection"));
        assert!(!command.to_ascii_lowercase().contains("proxy-authorization"));
    }

    #[tokio::test]
    async fn capture_body_handler_streams_only_the_requested_bounded_direction() {
        let state = test_state();
        let service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::from("response-body")))
            }),
        );
        service
            .serve(Request::new(Body::from("request-body")))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        let response = capture_body(
            State(state.clone()),
            Path(BodyPath {
                id: 1,
                direction: "request".to_owned(),
            }),
            Query(BodyQuery {
                limit: Some(4),
                download: false,
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "requ"
        );

        let response = capture_body(
            State(state),
            Path(BodyPath {
                id: 1,
                direction: "response".to_owned(),
            }),
            Query(BodyQuery {
                limit: None,
                download: true,
            }),
        )
        .await;
        assert_eq!(
            response.headers()["content-disposition"],
            "attachment; filename=\"response-1.body\""
        );
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "response-body"
        );
    }

    #[tokio::test]
    async fn dashboard_state_isolated_by_server_issued_session() {
        let state = test_state();
        state.ensure_session("known");
        let mut ui_changes = state.ui_changes.subscribe();

        let unknown = UiSignals {
            session: "unknown".to_owned(),
            search: "must-not-be-stored".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            update_filter(State(state.clone()), ReadSignals(unknown)).await,
            StatusCode::NOT_FOUND
        );
        assert_eq!(state.sessions.read().len(), 1);

        let known = UiSignals {
            session: "known".to_owned(),
            search: "payload".to_owned(),
            method: "POST".to_owned(),
            status: "2xx".to_owned(),
            ..Default::default()
        };
        assert_eq!(
            update_filter(State(state.clone()), ReadSignals(known)).await,
            StatusCode::NO_CONTENT
        );
        let session = state.session("known");
        assert_eq!(session.filter.search, "payload");
        assert_eq!(session.filter.method, "POST");
        assert_eq!(session.filter.status, "2xx");
        tokio::time::timeout(Duration::from_secs(1), ui_changes.changed())
            .await
            .expect("dashboard change notification timed out")
            .unwrap();

        let signals = || {
            ReadSignals(UiSignals {
                session: "known".to_owned(),
                ..Default::default()
            })
        };
        assert_eq!(
            focus_request(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").focus, UiFocus::Request(7));
        assert_eq!(
            older_websocket_messages(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").websocket_pages.get(&7), Some(&1));
        assert_eq!(
            newer_websocket_messages(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").websocket_pages.get(&7), Some(&0));
        assert_eq!(
            clear_focus(State(state.clone()), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(state.session("known").focus, UiFocus::Overview);
        assert_eq!(
            older_websocket_messages(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            toggle_selected(State(state.clone()), Path(IdPath { id: 9 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert!(state.session("known").selected.contains(&9));
        assert_eq!(
            toggle_connection(State(state.clone()), Path(IdPath { id: 3 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            toggle_connection(State(state.clone()), Path(IdPath { id: 5 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            state.session("known").selected_connections,
            BTreeSet::from([3, 5])
        );
        assert_eq!(
            clear_connections(State(state.clone()), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert!(state.session("known").selected_connections.is_empty());

        toggle_connection(State(state.clone()), Path(IdPath { id: 7 }), signals()).await;
        assert_eq!(
            reset_filters(State(state.clone()), signals()).await,
            StatusCode::NO_CONTENT
        );
        let session = state.session("known");
        assert!(session.filter.search.is_empty());
        assert!(session.filter.method.is_empty());
        assert!(session.selected_connections.is_empty());

        let response = replay(
            State(state),
            Path(IdPath { id: 1 }),
            ReadSignals(UiSignals {
                session: "unknown".to_owned(),
                ..Default::default()
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn websocket_replay_handler_enforces_session_and_maps_capture_state() {
        let state = test_state();
        state.ensure_session("known");
        let request = Request::builder()
            .uri("http://example.test/socket")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .unwrap();
        let capture_service = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |_request: Request| {
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        capture_service
            .serve(request)
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();
        let exchange_id = 1;
        state
            .capture
            .record_websocket_message(
                exchange_id,
                "Ingress".to_owned(),
                "text".to_owned(),
                b"replay me".to_vec(),
                None,
            )
            .await;
        state
            .capture
            .record_websocket_message(
                exchange_id,
                "Ingress".to_owned(),
                "ping".to_owned(),
                b"control".to_vec(),
                None,
            )
            .await;
        let signals = |session: &str| {
            ReadSignals(UiSignals {
                session: session.to_owned(),
                ..Default::default()
            })
        };
        let path = |id, index| Path(WebSocketMessagePath { id, index });

        assert_eq!(
            replay_websocket_message(
                State(state.clone()),
                path(exchange_id, 0),
                signals("unknown")
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            replay_websocket_message(State(state.clone()), path(exchange_id, 0), signals("known"))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            replay_websocket_message(State(state.clone()), path(exchange_id, 1), signals("known"))
                .await
                .status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            replay_websocket_message(
                State(state.clone()),
                path(exchange_id, 99),
                signals("known")
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            replay_websocket_message(State(state), path(999, 0), signals("known"))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn dashboard_session_storage_is_bounded() {
        let state = test_state();
        state.ensure_session("z-first");
        for id in 1..MAX_UI_SESSIONS {
            state.ensure_session(&format!("session-{id:03}"));
        }
        state.ensure_session("a-newest");
        assert_eq!(state.sessions.read().len(), MAX_UI_SESSIONS);
        assert!(!state.has_session("z-first"));
        assert!(state.has_session("a-newest"));
    }

    #[tokio::test]
    async fn events_streams_are_bounded_and_evicted_sessions_end() {
        let state = test_state();
        state.ensure_session("z-first");
        for id in 1..MAX_UI_SESSIONS {
            state.ensure_session(&format!("session-{id:03}"));
        }
        let dashboard = service(state.clone());
        let event_request = |session: &str| {
            Request::builder()
                .uri(format!(
                    "/events?datastar=%7B%22session%22%3A%22{session}%22%7D"
                ))
                .body(Body::empty())
                .unwrap()
        };

        let evicted_stream = dashboard
            .serve(event_request("z-first"))
            .await
            .unwrap()
            .into_body();
        let mut streams = Vec::with_capacity(MAX_UI_EVENT_STREAMS - 1);
        for _ in 1..MAX_UI_EVENT_STREAMS {
            let response = dashboard.serve(event_request("session-001")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            streams.push(response.into_body());
        }
        let response = dashboard.serve(event_request("session-001")).await.unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

        state.ensure_session("a-newest");
        let mut evicted_stream = evicted_stream;
        assert!(
            tokio::time::timeout(Duration::from_secs(1), evicted_stream.frame())
                .await
                .expect("revoked session stream did not terminate")
                .is_none()
        );
        drop(streams);
    }

    #[tokio::test]
    async fn events_stream_emits_an_initial_datastar_patch_for_known_session() {
        let state = test_state();
        state.ensure_session("stream-session");
        let dashboard = service(state);
        let request = Request::builder()
            .uri("/events?datastar=%7B%22session%22%3A%22stream-session%22%7D")
            .body(Body::empty())
            .unwrap();
        let response = dashboard.serve(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");

        let mut body = response.into_body();
        let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("initial dashboard event timed out")
            .expect("dashboard event stream ended")
            .expect("dashboard event stream failed");
        let data = frame.into_data().expect("SSE frame is data");
        let event = String::from_utf8_lossy(&data);
        assert!(event.contains("event: datastar-patch-elements"));
        assert!(event.contains("id=\"live\""));

        let frame = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .expect("live heartbeat timed out")
            .expect("dashboard event stream ended")
            .expect("dashboard event stream failed");
        let data = frame.into_data().expect("heartbeat SSE frame is data");
        let event = String::from_utf8_lossy(&data);
        assert!(event.contains("event: datastar-patch-elements"));
        assert!(event.contains("id=\"live-heartbeat\""));
        assert!(event.contains("data-sequence=\"1\""));

        let response = dashboard
            .serve(
                Request::builder()
                    .uri("/events?datastar=%7B%22session%22%3A%22unknown%22%7D")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_honors_disabled_forward_proxy_auth() {
        assert_replay_forward_proxy_auth(Some("upstream:secret"), false, None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_uses_configured_forward_proxy_auth() {
        assert_replay_forward_proxy_auth(
            Some("upstream:secret"),
            true,
            Some("Basic dXBzdHJlYW06c2VjcmV0"),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_without_configured_forward_proxy_auth_does_not_reuse_captured_auth() {
        assert_replay_forward_proxy_auth(None, true, None).await;
    }

    async fn assert_replay_forward_proxy_auth(
        configured_credential: Option<&str>,
        forward_proxy_auth: bool,
        expected_authorization: Option<&str>,
    ) {
        let listener = rama::tcp::server::TcpListener::bind_address(
            rama::net::address::SocketAddress::local_ipv4(0),
            Executor::default(),
        )
        .await
        .unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(1);
        let proxy_task = tokio::spawn(listener.serve(
            rama::http::server::HttpServer::auto(Executor::default()).service(
                rama::service::service_fn(move |request: Request| {
                    let observed_tx = observed_tx.clone();
                    async move {
                        observed_tx
                            .send((
                                request.uri().to_string(),
                                request
                                    .headers()
                                    .get_all(rama::http::header::PROXY_AUTHORIZATION)
                                    .iter()
                                    .map(|value| value.to_str().unwrap().to_owned())
                                    .collect::<Vec<_>>(),
                            ))
                            .await
                            .unwrap();
                        Ok::<_, Infallible>(Response::new(Body::from("replayed")))
                    }
                }),
            ),
        ));
        let mut proxy: rama::net::address::ProxyAddress =
            format!("http://{proxy_address}").parse().unwrap();
        proxy.credential = configured_credential.map(|credential| {
            rama::net::user::ProxyCredential::Basic(
                rama::net::user::Basic::try_from(credential).unwrap(),
            )
        });
        let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
            .unwrap()
            .with_forward_proxy_auth(forward_proxy_auth);
        let state = test_state_with_upstream(8, 8, upstream);
        capture_request_for_replay(&state, "http://origin.example/replay").await;

        assert_eq!(replay_captured(&state, 1).await.unwrap(), 200);
        assert_eq!(
            observed_rx.recv().await.unwrap(),
            (
                "http://origin.example/replay".to_owned(),
                expected_authorization
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            )
        );
        proxy_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_honors_plaintext_proxy_tunnel_without_leaking_auth() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let connect = read_http_head(&mut stream).await;
            assert!(connect.starts_with("CONNECT origin.example:80 HTTP/1.1\r\n"));
            assert!(
                connect
                    .to_ascii_lowercase()
                    .contains("proxy-authorization: basic dxbzdhjlyw06c2vjcmv0")
            );
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();

            let origin = read_http_head(&mut stream).await;
            assert!(origin.starts_with("GET /replay HTTP/1.1\r\n"));
            assert!(!origin.to_ascii_lowercase().contains("proxy-authorization:"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let mut proxy: rama::net::address::ProxyAddress =
            format!("http://{proxy_address}").parse().unwrap();
        proxy.credential = Some(rama::net::user::ProxyCredential::Basic(
            rama::net::user::Basic::try_from("upstream:secret").unwrap(),
        ));
        let upstream = UpstreamProxyConfig::new(Some(proxy), false, &[])
            .unwrap()
            .with_tunnel_plaintext_http(true);
        let state = test_state_with_upstream(8, 8, upstream);
        capture_request_for_replay(&state, "http://origin.example/replay").await;

        assert_eq!(replay_captured(&state, 1).await.unwrap(), 200);
        tokio::time::timeout(Duration::from_secs(5), proxy_task)
            .await
            .expect("proxy task timed out")
            .expect("proxy task failed");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_isolates_forward_proxy_auth_challenge() {
        let listener = rama::tcp::server::TcpListener::bind_address(
            rama::net::address::SocketAddress::local_ipv4(0),
            Executor::default(),
        )
        .await
        .unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(listener.serve(
            rama::http::server::HttpServer::auto(Executor::default()).service(
                rama::service::service_fn(|_: Request| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                            .header("proxy-authenticate", "Basic realm=upstream-secret")
                            .body(Body::from("upstream-secret-body"))
                            .unwrap(),
                    )
                }),
            ),
        ));
        let upstream = UpstreamProxyConfig::new(
            Some(format!("http://{proxy_address}").parse().unwrap()),
            false,
            &[],
        )
        .unwrap();
        let state = test_state_with_upstream(8, 8, upstream);
        capture_request_for_replay(&state, "http://origin.example/replay").await;

        let error = replay_captured(&state, 1).await.unwrap_err();
        assert!(!error.to_string().contains("upstream-secret"), "{error}");
        proxy_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_sends_captured_body_without_hop_by_hop_or_proxy_credentials() {
        let origin = rama::tcp::server::TcpListener::bind_address(
            rama::net::address::SocketAddress::local_ipv4(0),
            Executor::default(),
        )
        .await
        .unwrap();
        let origin_address = origin.local_addr().unwrap();
        let (observed_tx, mut observed_rx) = tokio::sync::mpsc::channel(1);
        let origin_task = tokio::spawn(origin.serve(
            rama::http::server::HttpServer::auto(Executor::default()).service(
                rama::service::service_fn(move |request: Request| {
                    let observed_tx = observed_tx.clone();
                    async move {
                        let leaked_headers = ["connection", "x-remove", "proxy-authorization"]
                            .into_iter()
                            .filter(|name| request.headers().contains_key(*name))
                            .collect::<Vec<_>>();
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        observed_tx.send((leaked_headers, body)).await.unwrap();
                        Ok::<_, Infallible>(Response::new(Body::from("replayed")))
                    }
                }),
            ),
        ));

        let state = test_state();
        let capture = CaptureHttpLayer::new(Some(state.capture.clone())).into_layer(
            rama::service::service_fn(async |request: Request| {
                request.into_body().collect().await.unwrap();
                Ok::<_, Infallible>(Response::new(Body::empty()))
            }),
        );
        capture
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{origin_address}/replay"))
                    .header("connection", "x-remove")
                    .header("x-remove", "secret")
                    .header("proxy-authorization", "Basic c2VjcmV0")
                    .body(Body::from("captured-body"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap();

        assert_eq!(replay_captured(&state, 1).await.unwrap(), 200);
        let (leaked, body) = observed_rx.recv().await.unwrap();
        assert!(leaked.is_empty(), "leaked replay headers: {leaked:?}");
        assert_eq!(body, "captured-body");
        let snapshot = state
            .capture
            .snapshot_limited_for_connections(
                &CaptureFilter::default(),
                &BTreeSet::new(),
                0,
                usize::MAX,
                usize::MAX,
            )
            .await;
        assert_eq!(snapshot.exchanges.len(), 2);
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(
            snapshot.connections[0].label.as_deref(),
            Some("Replay of request #1")
        );
        assert!(!snapshot.connections[0].active);
        assert_eq!(snapshot.exchanges[1].status, Some(200));
        state.ensure_session("known");
        let rendered = state.render_live("known", 0).await;
        assert!(rendered.contains(&format!("Inspector replay → {origin_address}")));
        assert!(!rendered.contains("unknown → unknown"));
        origin_task.abort();
    }

    #[tokio::test]
    async fn dashboard_request_bodies_have_an_application_limit() {
        let dashboard = service(test_state());
        let response = dashboard
            .serve(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/mitm-policy")
                    .header("content-type", "application/json")
                    .body(Body::from(vec![b'a'; MAX_DASHBOARD_REQUEST_BODY + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[tokio::test]
    async fn traffic_policy_requires_a_live_dashboard_session_and_rejects_stale_writes() {
        let state = test_state();
        state.ensure_session("known");
        let config = || super::super::control::Config {
            enabled: true,
            ..Default::default()
        };
        let request = |session: &str, revision| {
            Json(ControlConfigUpdate {
                session: session.into(),
                revision,
                config: config(),
                apply_rule: None,
            })
        };
        assert_eq!(
            control_config(State(state.clone()), request("unknown", 0))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
        assert!(!state.capture.control().snapshot().config.enabled);
        assert_eq!(
            control_config(State(state.clone()), request("known", 0))
                .await
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            control_config(State(state.clone()), request("known", 0))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(state.capture.control().snapshot().revision, 1);
    }
}
