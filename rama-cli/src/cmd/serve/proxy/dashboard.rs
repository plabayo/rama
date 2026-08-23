use super::{
    capture::{
        CaptureFilter, CaptureSnapshot, CaptureStore, CapturedBody, InspectorDetails, StoredRecord,
        WebSocketReplayError,
    },
    har::HarController,
    upstream::UpstreamProxyConfig,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use parking_lot::RwLock;
use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef as _,
    futures::async_stream::stream_fn,
    http::{
        Body, Method, Request, Response, StatusCode, Version,
        body::util::BodyExt as _,
        headers::SourceList,
        layer::remove_header::{RemoveRequestHeaderLayer, remove_hop_by_hop_request_headers},
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
    ua::profile::TlsProfile,
    utils::octets::{kib, kib_u64, mib},
    utils::str::NonEmptyStr,
};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    convert::Infallible,
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

const WS_TEXT_PREVIEW_LIMIT: usize = kib(16);
const WS_BINARY_PREVIEW_LIMIT: usize = 256;
const MAX_VISIBLE_WS_MESSAGES: usize = 100;
const MAX_BODY_PREVIEW_LIMIT: u64 = kib_u64(64);
const MAX_UI_SESSIONS: usize = 256;
const MAX_VISIBLE_CONNECTIONS: usize = 24;
const MAX_VISIBLE_EXCHANGES: usize = 250;
#[cfg(not(test))]
const LIVE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(test)]
const LIVE_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(20);
const RAMA_LOGO_SVG: &str = include_str!("../../../../../docs/img/rama_logo.svg");
const HAR_JS: &str = include_str!("dashboard-har.js");
const DETAILS_JS: &str = include_str!("dashboard-details.js");
const LIVE_JS: &str = include_str!("dashboard-live.js");

#[derive(Debug, Clone, Default)]
struct UiSession {
    filter: CaptureFilter,
    expanded: BTreeSet<u64>,
    selected: BTreeSet<u64>,
    selected_connections: BTreeSet<u64>,
    websocket_pages: BTreeMap<u64, usize>,
}

#[derive(Debug, Clone)]
pub(super) struct DashboardState {
    capture: CaptureStore,
    har: HarController,
    sessions: Arc<RwLock<BTreeMap<String, UiSession>>>,
    ui_changes: watch::Sender<u64>,
    ca_pem: Arc<Vec<u8>>,
    tcp_options: Arc<SocketOptions>,
    upstream: UpstreamProxyConfig,
}

impl DashboardState {
    pub(super) fn new(
        capture: CaptureStore,
        har: HarController,
        ca_pem: Vec<u8>,
        tcp_options: Arc<SocketOptions>,
        upstream: UpstreamProxyConfig,
    ) -> Self {
        let (ui_changes, _) = watch::channel(0);
        Self {
            capture,
            har,
            sessions: Arc::new(RwLock::new(BTreeMap::new())),
            ui_changes,
            ca_pem: Arc::new(ca_pem),
            tcp_options,
            upstream,
        }
    }

    fn notify(&self) {
        self.ui_changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    fn ensure_session(&self, id: &str) {
        let mut sessions = self.sessions.write();
        if !sessions.contains_key(id)
            && sessions.len() >= MAX_UI_SESSIONS
            && let Some(oldest) = sessions.keys().next().cloned()
        {
            sessions.remove(&oldest);
        }
        sessions.entry(id.to_owned()).or_default();
    }

    fn session(&self, id: &str) -> UiSession {
        self.sessions.read().get(id).cloned().unwrap_or_default()
    }

    fn has_session(&self, id: &str) -> bool {
        !id.is_empty() && self.sessions.read().contains_key(id)
    }

    async fn render_live(&self, session_id: &str, heartbeat_sequence: u64) -> String {
        let session = self.session(session_id);
        let snapshot = self
            .capture
            .snapshot_limited_for_connections(
                &session.filter,
                &session.selected_connections,
                MAX_VISIBLE_CONNECTIONS,
                MAX_VISIBLE_EXCHANGES,
            )
            .await;
        let har = self.har.status();
        let mut details = BTreeMap::new();
        for id in &session.expanded {
            let page = session.websocket_pages.get(id).copied().unwrap_or_default();
            if let Ok(detail) = self
                .capture
                .inspector_details(*id, page, MAX_VISIBLE_WS_MESSAGES)
                .await
            {
                details.insert(*id, detail);
            }
        }
        render_live_panel(
            session_id,
            heartbeat_sequence,
            &snapshot,
            &session,
            &details,
            &har,
        )
        .into_string()
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
        .with_post("/api/connection/{id}", toggle_connection)
        .with_post("/api/connections/clear", clear_connections)
        .with_post("/api/details/{id}", toggle_details)
        .with_post("/api/websocket/{id}/older", older_websocket_messages)
        .with_post("/api/websocket/{id}/newer", newer_websocket_messages)
        .with_post(
            "/api/websocket/{id}/replay/{index}",
            replay_websocket_message,
        )
        .with_post("/api/select/{id}", toggle_selected)
        .with_post("/api/replay/{id}", replay)
        .with_get("/api/capture/{id}.json", capture_json)
        .with_get("/api/capture/{id}/body/{direction}", capture_body)
        .with_get(
            "/api/capture/{id}/websocket/{index}",
            capture_websocket_message,
        )
        .with_get("/api/profiles.json", export_profiles)
        .with_get("/ca.pem", download_ca)
        .with_post("/api/har/start", start_har)
        .with_post("/api/har/stop", stop_har)
        .with_get("/assets/style.css", Css(STYLE_CSS))
        .with_get("/assets/har.js", Script(HAR_JS))
        .with_get("/assets/details.js", Script(DETAILS_JS))
        .with_get("/assets/live.js", Script(LIVE_JS))
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
    let service =
        rama::cli::service::http_security::defence_in_depth_layer(csp).into_layer(Arc::new(router));
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
}

async fn index(State(state): State<DashboardState>) -> Response {
    let mut token = [0_u8; 16];
    if let Err(error) = rama::tls::boring::core::rand::rand_bytes(&mut token) {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, error);
    }
    let session = hex::encode(token);
    state.ensure_session(&session);
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
    let mut capture_changes = state.capture.subscribe();
    let mut ui_changes = state.ui_changes.subscribe();
    Sse::new(KeepAliveStream::new(
        KeepAlive::new(),
        stream_fn(move |mut yielder| async move {
            let mut heartbeat = tokio::time::interval(LIVE_HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `interval` ticks immediately once; consume that tick because the
            // initial full render carries heartbeat sequence zero.
            heartbeat.tick().await;
            let mut render_dashboard = true;
            let mut heartbeat_sequence = 0_u64;
            loop {
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
    drop(sessions);
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

async fn toggle_details(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> StatusCode {
    let mut sessions = state.sessions.write();
    let Some(session) = sessions.get_mut(&signals.session) else {
        return StatusCode::NOT_FOUND;
    };
    if session.expanded.remove(&id) {
        session.websocket_pages.remove(&id);
    } else {
        session.expanded.insert(id);
        session.websocket_pages.insert(id, 0);
    }
    drop(sessions);
    state.notify();
    StatusCode::NO_CONTENT
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
    if !session.expanded.contains(&exchange_id) {
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
        Ok(details) => Json(details).into_response(),
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
        Err(WebSocketReplayError::ConnectionClosed) => StatusCode::CONFLICT.into_response(),
        Err(error @ WebSocketReplayError::SendFailed(_)) => {
            error_response(StatusCode::BAD_GATEWAY, error)
        }
        Err(error @ WebSocketReplayError::InvalidCapture(_)) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, error)
        }
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
    let (request_ids, connection_ids) = match query.ids {
        Some(ids) => (
            ids.split(',')
                .filter_map(|id| id.trim().parse().ok())
                .collect::<BTreeSet<_>>(),
            BTreeSet::new(),
        ),
        None => match query.session {
            Some(session_id) => {
                let session = state.session(&session_id);
                (session.selected, session.selected_connections)
            }
            None => (BTreeSet::new(), BTreeSet::new()),
        },
    };
    match state
        .capture
        .export_profiles(&request_ids, &connection_ids)
        .await
    {
        Ok(profiles) => Json(profiles).into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

async fn start_har(
    State(state): State<DashboardState>,
    Query(query): Query<StartHarQuery>,
) -> Response {
    if !state.has_session(&query.session) {
        return StatusCode::NOT_FOUND.into_response();
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
        Ok(download) => Response::builder()
            .header("content-type", "application/json")
            .header("content-length", download.content_length)
            .body(Body::from_stream(ReaderStream::new(download.reader)))
            .unwrap_or_else(|error| error_response(StatusCode::INTERNAL_SERVER_ERROR, error)),
        Err(error) => error_response(StatusCode::BAD_REQUEST, error),
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
    let method: Method = captured.method.parse().context("parse captured method")?;
    let version = match captured.version.as_str() {
        "HTTP/0.9" => Version::HTTP_09,
        "HTTP/1.0" => Version::HTTP_10,
        "HTTP/2.0" => Version::HTTP_2,
        "HTTP/3.0" => Version::HTTP_3,
        _ => Version::HTTP_11,
    };
    let mut request = Request::builder()
        .method(method)
        .version(version)
        .uri(captured.url.as_str());
    for (name, value) in captured.headers {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "host" | "content-length" | "proxy-authorization"
        ) {
            continue;
        }
        request = request.header(name, value);
    }
    let mut request = request
        .body(Body::from(captured.body))
        .context("build replay request")?;
    if let Some(client_hello) = captured.tls_client_hello {
        request.extensions().insert_arc(Arc::new(TlsProfile {
            client_hello,
            ws_client_config_overwrites: None,
        }));
    }
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
        .build_client();
    let client = state.upstream.http_service(client);
    let client = RemoveRequestHeaderLayer::hop_by_hop().into_layer(client);
    let client = EmulateTlsProfileLayer::new().into_layer(client);
    let response = client.serve(request).await.context("replay request")?;
    let status = response.status().as_u16();
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        frame.context("drain replay response")?;
    }
    Ok(status)
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
        ),
        body!(
            "data-signals:session" = session_signal,
            "data-signals:search" = "''",
            "data-signals:connection_id" = "''",
            "data-signals:user_agent" = "''",
            "data-signals:endpoint" = "''",
            "data-signals:method" = "''",
            "data-signals:status" = "''",
            "data-signals:protocol" = "''",
            "data-init" = "@get('/events')",
            header!(
                class = "topbar",
                div!(
                    class = "brand",
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
            main!(
                section!(
                    class = "filter-panel",
                    div!(
                        class = "filter-head",
                        div!(h2!("Filters"), p!("Narrow this inspector session")),
                        button!(
                            r#type = "button",
                            class = "ghost clear-filters",
                            "data-on:click" = "$search = ''; $connection_id = ''; $user_agent = ''; $endpoint = ''; $method = ''; $status = ''; $protocol = ''; @post('/api/filter/reset')",
                            "Clear all"
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
                                "data-bind:connection_id" = "",
                                "data-on:input__debounce.250ms" = "@post('/api/filter')",
                            )
                        ),
                        label!(
                            class = "filter-method",
                            span!("Method"),
                            select!(
                                "data-bind:method" = "",
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
                ),
                section!(
                    id = "live",
                    class = "live-shell",
                    span!(id = "live-heartbeat", hidden = "", "data-sequence" = ""),
                    p!("Connecting…")
                ),
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
) -> impl IntoHtml {
    let connection_rows = snapshot.connections.iter().take(24).map(|connection| {
        let selected = session.selected_connections.contains(&connection.id);
        let state_label = if connection.active { "alive" } else { "closed" };
        let class = match (connection.active, selected) {
            (true, true) => "connection active selected",
            (true, false) => "connection active",
            (false, true) => "connection selected",
            (false, false) => "connection",
        };
        button!(
            r#type = "button",
            class = class,
            title = "Filter requests and export one representative profile for this connection",
            "aria-pressed" = selected.to_string(),
            "data-on:click" = format!("@post('/api/connection/{}')", connection.id),
            div!(
                span!(class = "mono", format!("#{}", connection.id)),
                div!(
                    class = "connection-tags",
                    selected.then(|| span!(class = "connection-check", "✓")),
                    span!(class = "tag", connection.ingress_protocol.clone()),
                    span!(
                        class = if connection.active {
                            "connection-state alive"
                        } else {
                            "connection-state closed"
                        },
                        state_label
                    ),
                )
            ),
            strong!(format!(
                "{} → {}",
                connection.peer_address, connection.local_address
            )),
            time!(
                datetime = connection.started_at.clone(),
                format!("started {}", connection.started_at)
            ),
            small!(format!(
                "{} req · {} ↓ · {} ↑",
                connection.request_count,
                format_bytes(connection.bytes_in),
                format_bytes(connection.bytes_out)
            ))
        )
    });
    let connection_selection = if session.selected_connections.is_empty() {
        small!("latest 24").into_string()
    } else {
        div!(
            class = "connection-selection",
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
    let exchange_rows = snapshot.exchanges.iter().take(250).map(|exchange| {
        let is_expanded = session.expanded.contains(&exchange.id);
        let is_selected = session.selected.contains(&exchange.id);
        let detail = details.get(&exchange.id).map(render_details);
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
        let detail_label = if is_expanded { "Less" } else { "Details" };
        let method = if matches!(exchange.protocol.as_str(), "ws" | "wss") {
            exchange.protocol.to_ascii_uppercase()
        } else {
            exchange.method.clone()
        };
        let response_state = match (exchange.status, exchange.active) {
            (None, true) => "request only · waiting".to_owned(),
            (None, false) => "request only · closed".to_owned(),
            (Some(status), true) => format!("response {status} · streaming"),
            (Some(status), false) => format!("response {status} · complete"),
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
        article!(
            class = class,
            div!(
                class = "exchange-row",
                button!(
                    class = select_class,
                    title = "Include in profile export",
                    "data-on:click" = format!("@post('/api/select/{}')", exchange.id),
                    select_label
                ),
                span!(class = "method", method),
                div!(
                    class = "target",
                    strong!(exchange.endpoint.clone()),
                    small!(exchange.url.clone())
                ),
                span!(class = "tag", exchange.protocol.clone()),
                span!(class = status_class(exchange.status), response_state),
                span!(class = "bytes", format_bytes(exchange.response_bytes)),
                time!(
                    class = "exchange-time",
                    datetime = exchange.started_at.clone(),
                    exchange.started_at.clone()
                ),
                PreEscaped(replay_action),
                button!(
                    class = "ghost",
                    "data-on:click" = format!("@post('/api/details/{}')", exchange.id),
                    detail_label
                )
            ),
            detail,
        )
    });
    let har_control = if har.active {
        div!(
            class = "har-control recording",
            title = har.path.clone().unwrap_or_default(),
            span!(class = "record-dot"),
            span!("HAR recording"),
            button!(
                r#type = "button",
                class = "danger compact",
                "data-har-action" = "stop",
                "data-session" = session_id,
                "data-file-name" = har.path.clone().unwrap_or_default(),
                "Stop & save"
            )
        )
        .into_string()
    } else {
        button!(
            r#type = "button",
            class = "ghost compact har-start",
            "data-har-action" = "start",
            "data-session" = session_id,
            "Record HAR"
        )
        .into_string()
    };
    let requests = if snapshot.exchanges.is_empty() {
        let (title, description) = if session.selected_connections.is_empty() {
            (
                "Waiting for matching traffic",
                "Point a client at the proxy; updates appear here immediately.",
            )
        } else {
            (
                "No requests for the selected connections",
                "Select another connection or clear the connection selection.",
            )
        };
        div!(class = "empty", strong!(title), p!(description)).into_string()
    } else {
        div!(class = "exchange-list", exchange_rows.collect::<Vec<_>>()).into_string()
    };
    let profile_export = match (session.selected_connections.len(), session.selected.len()) {
        (0, 0) => div!(
            class = "export",
            span!("Select connections or requests"),
            button!(class = "ghost compact", disabled = true, "Export profiles")
        )
        .into_string(),
        (connections, requests) => {
            let scope = match (connections, requests) {
                (0, requests) => format!("{requests} request(s)"),
                (connections, 0) => format!("{connections} connection profile(s)"),
                (connections, requests) => {
                    format!("{connections} connection profile(s) + {requests} request(s)")
                }
            };
            div!(
                class = "export",
                span!(scope),
                a!(
                    class = "ghost link",
                    href = format!("/api/profiles.json?session={session_id}"),
                    "Export profiles"
                )
            )
            .into_string()
        }
    };
    section!(
        id = "live",
        class = "live-shell",
        render_live_heartbeat(heartbeat_sequence),
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
                div!(class = "connections", connection_rows.collect::<Vec<_>>())
            ),
            section!(
                class = "requests",
                div!(
                    class = "section-title",
                    h2!("Requests"),
                    div!(
                        class = "request-tools",
                        PreEscaped(har_control),
                        PreEscaped(profile_export)
                    )
                ),
                PreEscaped(requests)
            )
        )
    )
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

fn render_details(details: &InspectorDetails) -> impl IntoHtml {
    let request_head = details.records.iter().find_map(|record| match record {
        StoredRecord::RequestHead {
            method,
            url,
            version,
            headers,
            tls_client_hello,
            ..
        } => Some((method, url, version, headers, tls_client_hello.as_ref())),
        _ => None,
    });
    let response_head = details.records.iter().find_map(|record| match record {
        StoredRecord::ResponseHead {
            status,
            version,
            headers,
        } => Some((*status, version, headers)),
        _ => None,
    });
    let request_headers = request_head.map(|(_, _, _, headers, _)| headers.as_slice());
    let response_headers = response_head.map(|(_, _, headers)| headers.as_slice());
    let is_websocket = matches!(details.summary.protocol.as_str(), "ws" | "wss");
    let overview = section!(
        class = "detail-overview",
        div!(span!("Request"), strong!(details.summary.method.clone())),
        div!(span!("Endpoint"), strong!(details.summary.endpoint.clone())),
        div!(
            span!("Status"),
            strong!(
                details
                    .summary
                    .status
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "Pending".to_owned())
            )
        ),
        div!(
            span!("Traffic"),
            strong!(format!(
                "{} ↑  {} ↓",
                format_bytes(details.summary.request_bytes),
                format_bytes(details.summary.response_bytes)
            ))
        ),
        details
            .summary
            .ingress_peer_address
            .as_ref()
            .map(|address| div!(span!("Ingress client"), strong!(address.clone()))),
        details
            .summary
            .ingress_local_address
            .as_ref()
            .map(|address| div!(span!("Ingress proxy"), strong!(address.clone()))),
        details
            .summary
            .egress_local_address
            .as_ref()
            .map(|address| div!(span!("Egress proxy"), strong!(address.clone()))),
        details
            .summary
            .egress_peer_address
            .as_ref()
            .map(|address| div!(span!("Egress server"), strong!(address.clone()))),
        div!(
            span!("Request started"),
            strong!(details.summary.started_at.clone())
        ),
        details
            .summary
            .response_started_at
            .as_ref()
            .map(|at| div!(span!("Response started"), strong!(at.clone()))),
        details
            .summary
            .completed_at
            .as_ref()
            .map(|at| div!(span!("Completed"), strong!(at.clone()))),
    )
    .into_string();

    div!(
        class = "details",
        div!(
            class = "detail-top",
            div!(
                class = "detail-meta",
                span!(format!("connection #{}", details.summary.connection_id)),
                span!(details.summary.protocol.to_ascii_uppercase()),
                span!(details.summary.started_at.clone()),
                details
                    .summary
                    .user_agent_kind
                    .as_ref()
                    .map(|kind| span!(kind.clone())),
            ),
            div!(
                class = "detail-actions",
                (!is_websocket).then(|| button!(
                    class = "primary",
                    "data-on:click" = format!("@post('/api/replay/{}')", details.summary.id),
                    "Replay captured request"
                )),
                a!(
                    class = "ghost link",
                    href = format!("/api/capture/{}.json", details.summary.id),
                    "Download capture JSON"
                ),
                details.summary.has_emulation_profile.then(|| a!(
                    class = "ghost link",
                    href = format!("/api/profiles.json?ids={}", details.summary.id),
                    "Export profile"
                )),
            )
        ),
        PreEscaped(overview),
        render_websocket_messages(details).map(PreEscaped),
        request_head
            .and_then(|(_, _, _, _, tls)| tls)
            .and_then(|tls| render_json_card("TLS client hello", tls, 18))
            .map(PreEscaped),
        render_fingerprint_card(&details.summary).map(PreEscaped),
        request_head.map(|(method, url, version, _, _)| section!(
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

fn render_fingerprint_card(summary: &super::capture::ExchangeSummary) -> Option<String> {
    let values = [
        ("JA3", summary.ja3.as_deref()),
        ("JA4", summary.ja4.as_deref()),
        ("PeetPrint", summary.peetprint.as_deref()),
        ("JA4H", summary.ja4h.as_deref()),
        ("Akamai HTTP/2", summary.akamai_h2.as_deref()),
        ("Known profile", summary.known_fingerprint.as_deref()),
        ("User agent", summary.user_agent.as_deref()),
    ];
    let rows = values
        .into_iter()
        .filter_map(|(label, value)| value.map(|value| (label, value)))
        .collect::<Vec<_>>();
    (!rows.is_empty()).then(|| {
        section!(
            class = "detail-card",
            h3!("Client identity & fingerprints"),
            div!(
                class = "kv-grid",
                rows.into_iter()
                    .map(|(label, value)| div!(span!(label), code!(preview_text(value, 4096))))
            )
        )
        .into_string()
    })
}

fn render_json_card(title: &str, value: &serde_json::Value, max_rows: usize) -> Option<String> {
    let mut rows = Vec::new();
    flatten_json("", value, &mut rows, max_rows, 0);
    (!rows.is_empty()).then(|| {
        section!(
            class = "detail-card",
            div!(
                class = "card-title",
                h3!(title.to_owned()),
                span!("compact view")
            ),
            div!(
                class = "kv-grid",
                rows.into_iter()
                    .map(|(label, value)| div!(span!(label), code!(value)))
            )
        )
        .into_string()
    })
}

fn flatten_json(
    prefix: &str,
    value: &serde_json::Value,
    rows: &mut Vec<(String, String)>,
    max_rows: usize,
    depth: usize,
) {
    if rows.len() >= max_rows {
        return;
    }
    if let serde_json::Value::Object(object) = value
        && depth < 2
    {
        for (key, value) in object {
            let label = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            flatten_json(&label, value, rows, max_rows, depth + 1);
            if rows.len() >= max_rows {
                break;
            }
        }
        return;
    }
    let label = if prefix.is_empty() { "value" } else { prefix };
    let value = match value {
        serde_json::Value::String(value) => value.clone(),
        value => value.to_string(),
    };
    rows.push((label.to_owned(), preview_text(&value, 2048)));
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
            } => Some((at, direction, kind, data, close_code, replayed)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if details.websocket_total == 0 {
        return None;
    }
    let end = details
        .websocket_total
        .saturating_sub(details.websocket_page * MAX_VISIBLE_WS_MESSAGES);
    let start = end.saturating_sub(messages.len());
    let cards = messages.into_iter().enumerate().map(
        |(page_index, (at, direction, kind, encoded, close_code, replayed))| {
            let message_index = start + page_index;
            let (payload, bytes, preview_truncated) = websocket_payload(kind, encoded);
            let ingress = direction.eq_ignore_ascii_case("ingress");
            let is_control = matches!(kind.as_str(), "ping" | "pong" | "close");
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
                    (!is_control && capture_truncated).then(|| span!(
                        class = "ws-replay-unavailable",
                        "capture truncated · replay unavailable"
                    )),
                    (!is_control && !capture_truncated && !details.websocket_replay_active).then(
                        || span!(
                            class = "ws-replay-unavailable",
                            "connection closed · replay unavailable"
                        )
                    ),
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
    Some(
        section!(
            class = "ws-messages",
            div!(
                class = "ws-messages-title",
                div!(
                    h3!("WebSocket traffic"),
                    span!(format!(
                        "messages {}–{} of {}",
                        start + 1,
                        end,
                        details.websocket_total
                    ))
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

const STYLE_CSS: &str = include_str!("dashboard.css");

#[cfg(test)]
mod tests {
    use super::super::capture::{CaptureHttpLayer, StoredRecord};
    use super::*;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use rama::ua::profile::UserAgentDatabase;
    use std::time::Duration;

    fn test_state() -> DashboardState {
        let ua_db = Arc::new(UserAgentDatabase::try_embedded().unwrap());
        DashboardState::new(
            CaptureStore::new(8, 8, 1024, ua_db).unwrap(),
            HarController::default(),
            Vec::new(),
            Arc::new(SocketOptions::default_tcp()),
            UpstreamProxyConfig::new(None, false, &[]).unwrap(),
        )
    }

    fn test_details(records: Vec<StoredRecord>) -> InspectorDetails {
        let websocket_total = records
            .iter()
            .filter(|record| matches!(record, StoredRecord::WebSocketMessage { .. }))
            .count();
        InspectorDetails {
            summary: super::super::capture::ExchangeSummary {
                id: 1,
                connection_id: 1,
                started_at: String::new(),
                method: "GET".to_owned(),
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
        assert!(rendered.contains("/assets/style.css"));
        assert!(rendered.contains("/assets/rama-logo.svg"));
        assert!(rendered.contains("rel=\"icon\""));
        assert!(rendered.contains("type=\"image/svg+xml\""));
        assert!(!rendered.contains("ラマ"));
        assert!(rendered.contains("Rama Proxy Inspector"));
        assert!(rendered.contains("id=\"connection-status\""));
        assert!(rendered.contains(">connecting</span>"));
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
        assert!(rendered.contains("Clear all"));
        assert!(!rendered.contains("data-signals:har_path"));
        assert!(!rendered.contains("HAR output file"));
        assert!(!rendered.contains("<style>"));
        for protocol in ["HTTP", "HTTPS", "WS", "WSS", "Other"] {
            assert!(rendered.contains(&format!(">{protocol}</option>")));
        }
        assert!(!rendered.contains(">SOCKS5</option>"));
    }

    #[test]
    fn details_are_escaped_by_rama_html() {
        let mut details = test_details(vec![StoredRecord::RequestBody {
            data: BASE64.encode("<script>alert(1)</script>"),
        }]);
        details.summary.user_agent = Some("</pre><script>alert(1)</script>".to_owned());
        let rendered = render_details(&details).into_string();
        assert!(!rendered.contains("<script>alert(1)</script>"));
        assert!(rendered.contains("&lt;/pre&gt;&lt;script&gt;"));
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
        }]);

        let rendered = render_details(&details).into_string();
        assert!(rendered.contains(&format!("{}…", "é".repeat(4_096))));
        assert!(!rendered.contains(&"é".repeat(4_097)));
    }

    #[test]
    fn details_render_structured_tls_headers_fingerprints_and_lazy_payloads() {
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
                tls_client_hello: Some(serde_json::json!({
                    "protocol_version": "TLS1.3",
                    "server_name": "example.test"
                })),
            },
            StoredRecord::ResponseHead {
                status: 201,
                version: "HTTP/2.0".to_owned(),
                headers: vec![("content-type".to_owned(), "text/plain".to_owned())],
            },
        ]);
        details.summary.method = "POST".to_owned();
        details.summary.protocol = "https".to_owned();
        details.summary.request_bytes = 128;
        details.summary.response_bytes = 64;
        details.summary.ja3 = Some("ja3-value".to_owned());
        details.summary.has_emulation_profile = true;

        let rendered = render_details(&details).into_string();
        for expected in [
            "TLS client hello",
            "protocol_version",
            "Client identity &amp; fingerprints",
            "ja3-value",
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
        ] {
            assert!(rendered.contains(expected), "missing {expected}");
        }
        assert!(!rendered.contains("Handshake &amp; capture metadata"));
        assert!(!rendered.contains("Emulation profile"));
        assert!(!rendered.contains("Chromium"));
        assert!(!rendered.contains("RequestBody"));
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
            },
            StoredRecord::WebSocketMessage {
                at: "2026-08-22T20:00:01Z".to_owned(),
                direction: "Egress".to_owned(),
                kind: "binary".to_owned(),
                data: BASE64.encode([0, 1, 254, 255]),
                close_code: None,
                replayed: true,
            },
        ]);
        details.websocket_replay_active = true;

        let rendered = render_details(&details).into_string();
        assert!(rendered.contains("WebSocket traffic"));
        assert!(rendered.contains("Client → Server"));
        assert!(rendered.contains("Server → Client"));
        assert!(rendered.contains("hello over websocket"));
        assert!(rendered.contains("00 01 fe ff"));
        assert!(rendered.contains("Replay to server"));
        assert!(rendered.contains("Replay to client"));
        assert!(rendered.contains("/api/websocket/1/replay/0"));
        assert!(rendered.contains("/api/websocket/1/replay/1"));
        assert!(rendered.contains("ws-message egress replayed"));
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
        assert!(rendered.contains("1 connection profile(s)"));
        assert!(rendered.contains("/api/profiles.json?session=known"));
        assert!(rendered.contains("/api/connections/clear"));
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
        assert!(streaming.contains("response 200 · streaming"));
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
        assert!(completed.contains("response 200 · complete"));
        assert!(completed.contains("request only · closed"));
    }

    #[tokio::test]
    async fn har_control_is_compact_and_streams_picker_backed_output() {
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
        assert!(active.contains("data-har-action=\"stop\""));
        assert!(active.contains("data-file-name=\"picked.har\""));
        assert!(active.contains("Stop &amp; save"));

        let response = stop_har(
            State(state.clone()),
            Query(HarSessionQuery {
                session: "known".to_owned(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
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
            toggle_details(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert!(state.session("known").expanded.contains(&7));
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
            toggle_details(State(state.clone()), Path(IdPath { id: 7 }), signals()).await,
            StatusCode::NO_CONTENT
        );
        assert!(!state.session("known").expanded.contains(&7));
        assert!(!state.session("known").websocket_pages.contains_key(&7));
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
        for id in 0..=MAX_UI_SESSIONS {
            state.ensure_session(&format!("session-{id:03}"));
        }
        assert_eq!(state.sessions.read().len(), MAX_UI_SESSIONS);
        assert!(state.has_session("session-256"));
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
        origin_task.abort();
    }
}
