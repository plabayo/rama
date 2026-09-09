use std::fmt;

use rama::{
    extensions::Extension,
    http::{
        client::{
            BindBodyToConnLayer, EasyHttpWebClient, HttpConnId, HttpConnIdentifier,
            HttpConnectRequestAdapter, HttpPooledConnectorConfig,
        },
        layer::version_adapter::RequestVersionAdapter,
    },
    net::{
        Protocol,
        client::{
            ConnectRequest, ProxyRoutesConnector,
            pool::{ConnID, MultiplexPool, ReqToConnID},
        },
    },
    tcp::client::service::TcpConnector,
    tls::client::{ClientHello, TlsClientConfig},
};
use tokio::io::AsyncReadExt as _;

use super::*;

/// Captured connections may have different TLS profiles even for the same route.
/// Reuse connections only within one source; untracked exchanges stay isolated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Extension)]
enum ReplaySource {
    Connection(u64),
    Exchange(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplayPoolId {
    http: HttpConnId,
    source: ReplaySource,
}

impl ConnID for ReplayPoolId {}

fn replay_pool_id(input: &ConnectRequest) -> Result<ReplayPoolId, BoxError> {
    Ok(ReplayPoolId {
        http: HttpConnIdentifier::new().id(input)?,
        source: input
            .extensions()
            .get_ref::<ReplaySource>()
            .copied()
            .context("missing replay source")?,
    })
}

pub(super) fn replay_client(
    capture: CaptureStore,
    tcp_options: Arc<SocketOptions>,
    upstream: &UpstreamProxyConfig,
) -> Result<BoxService<Request, Response, BoxError>, BoxError> {
    let tls_config = TlsClientConfig::default_http();
    let transport = TcpConnector::new().with_connector(tcp_options);
    let config = HttpPooledConnectorConfig::default();
    let pool = MultiplexPool::try_new(config.max_concurrent_streams, config.max_total)?
        .with_selection(config.selection)
        .maybe_with_idle_timeout(config.idle_timeout);
    let client = EasyHttpWebClient::connector_builder()
        .with_custom_transport_connector(transport)
        .with_default_dns_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(tls_config)
        .with_default_http_connector(Executor::default())
        .with_custom_connection_pool(pool, replay_pool_id, config.wait_for_pool_timeout)
        .map_connector(|connector| {
            let connector = BindBodyToConnLayer::new().into_layer(connector);
            let connector = ProxyRoutesConnector::new(connector);
            let connector = HttpConnectRequestAdapter::new(connector);
            RequestVersionAdapter::new(connector)
        })
        .build_client()
        .with_forward_proxy_auth(upstream.forward_proxy_auth())
        .with_tunnel_plaintext_http(upstream.tunnel_plaintext_http())
        .with_isolate_forward_proxy_auth_error(true);
    let client = upstream.http_service(client);
    let client = RemoveRequestHeaderLayer::hop_by_hop().into_layer(client);
    let client = EmulateTlsProfileLayer::new().into_layer(client);
    let client = CaptureHttpLayer::new(Some(capture)).into_layer(client);
    Ok(client.boxed())
}

pub(super) async fn request_curl(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
) -> Response {
    let captured = match state.capture.replay_request(id).await {
        Ok(captured) => captured,
        Err(error) => return error_response(StatusCode::BAD_REQUEST, error),
    };
    if matches!(captured.protocol, Protocol::WS | Protocol::WSS) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "WebSocket handshakes cannot be represented as a replayable cURL command",
        );
    }
    let (request, body, _) = match build_captured_request(captured, false) {
        Ok(request) => request,
        Err(error) => return error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    };
    // A cURL command embeds its payload as one shell argument. Bound this
    // convenience representation; replay and body downloads stream without it.
    let mut payload = Vec::new();
    if let Err(error) = body
        .reader()
        .take(MAX_BODY_PREVIEW_LIMIT + 1)
        .read_to_end(&mut payload)
        .await
    {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, error);
    }
    if payload.len() as u64 > MAX_BODY_PREVIEW_LIMIT {
        return error_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Request body exceeds the inline cURL limit; use replay or download the body",
        );
    }
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
        &Bytes::from(payload),
        curl::CurlExportOptions::default().with_script_compatibility(compatibility),
        &curl::CurlScriptPayloadMode::Inline,
    ) {
        Ok(command) => (
            Headers::single(CacheControl::new().with_no_store()),
            command,
        )
            .into_response(),
        Err(error) => error_response(StatusCode::INTERNAL_SERVER_ERROR, error),
    }
}

pub(super) async fn replay(
    State(state): State<DashboardState>,
    Path(IdPath { id }): Path<IdPath>,
    ReadSignals(signals): ReadSignals<UiSignals>,
) -> Response {
    if signals
        .session
        .as_deref()
        .is_some_and(|session| !state.has_session(session))
    {
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

pub(super) async fn replay_captured(
    state: &DashboardState,
    id: u64,
) -> Result<StatusCode, BoxError> {
    let exchange = state.capture.exchange_capture(id)?;
    let connection_id = exchange.snapshot().connection_id;
    let source = if connection_id == 0 {
        ReplaySource::Exchange(id)
    } else {
        ReplaySource::Connection(connection_id)
    };
    let captured = state.capture.replay_request(id).await?;
    let (request, body, tls_client_hello) = build_captured_request(captured, true)?;
    let (parts, ()) = request.into_parts();
    let mut request = Request::from_parts(parts, Body::from_stream(body.stream(None)));
    request.extensions().insert(source);
    if let Some(client_hello) = tls_client_hello {
        request.extensions().insert_arc(Arc::new(TlsProfile {
            client_hello,
            ws_client_config_overwrites: None,
        }));
    }
    let replay_connection = state.capture.begin_connection_if_enabled(
        None,
        REPLAY_PROTOCOL,
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
    let response = state
        .replay_client
        .serve(request)
        .await
        .context("replay request")?;
    let status = response.status();
    let mut body = response.into_body();
    while let Some(frame) = body.frame().await {
        frame.context("drain replay response")?;
    }
    Ok(status)
}

pub(super) fn build_captured_request<B>(
    captured: ReplayRequest<B>,
    strip_transport_headers: bool,
) -> Result<(Request<()>, B, Option<ClientHello>), BoxError> {
    let mut request = Request::builder()
        .method(captured.method)
        .version(captured.version)
        .uri(captured.url)
        .body(())?;
    *request.headers_mut() = captured.headers;
    if strip_transport_headers {
        for name in ["host", "content-length", "proxy-authorization"] {
            request.headers_mut().remove(name);
        }
    }
    let hello = captured
        .metadata
        .connection
        .get_ref::<TlsObservation>()
        .and_then(|tls| tls.client_hello.clone());
    Ok((request, captured.body, hello))
}

pub(super) fn error_response(status: StatusCode, error: impl fmt::Display) -> Response {
    (status, error.to_string()).into_response()
}
