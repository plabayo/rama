//! This example shows how one can begin with creating a MITM proxy.
//!
//! Note that this MITM proxy is not production ready, and is only meant
//! to show you how one might start. You might want to address the following:
//!
//! - Load in your tls mitm cert/key pair from file or ACME
//! - Make sure your clients trust the MITM cert
//! - Do not enforce the Application protocol and instead convert requests when needed,
//!   e.g. in this example we _always_ map the protocol between two ends,
//!   even though it might be better to be able to map bidirectionaly between http versions
//! - ... and much more
//!
//! That said for basic usage it does work and should at least give you an idea on how to get started.
//!
//! It combines concepts that can seen in action separately in the following examples:
//!
//! - [`http_connect_proxy`](./http_connect_proxy.rs);
//! - [`tls_boring_termination`](./tls_boring_termination.rs);
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_mitm_proxy_boring --features=http-full,boring
//! ```
//!
//! ## Expected output
//!
//! The server will start and listen on `:62017`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' https://www.example.com/
//! ```
//!
//! ## WebSocket support
//!
//! Since July of 2025 this example also contains WebSocket MITM support.
//! You can for example test it using:
//!
//! ```sh
//! rama ws -k \
//!     --proxy http://127.0.0.1:62017 --proxy-user 'john:secret' \
//!     wss://echo.ramaproxy.org
//! ```
//!
//! Or use one of alternative sub protocols available in the echo server:
//!
//! ```sh
//! rama ws -k \
//!     --proxy http://127.0.0.1:62017 --proxy-user 'john:secret' \
//!     --protocols echo-upper wss://echo.ramaproxy.org
//! ```

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::Extensions,
    extensions::{ExtensionsMut, ExtensionsRef},
    futures::SinkExt,
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        conn::TargetHttpVersion,
        headers::{
            HeaderEncode, HeaderMapExt as _, SecWebSocketExtensions, TypedHeader,
            sec_websocket_extensions::Extension,
        },
        io::upgrade,
        layer::{
            compress_adapter::CompressAdaptLayer,
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            traffic_writer::{self, RequestWriterInspector},
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        proto::RequestHeaders,
        server::HttpServer,
        service::web::response::IntoResponse,
        ws::{
            AsyncWebSocket, Message, ProtocolError,
            handshake::{client::HttpClientWebSocketExt, server::WebSocketMatcher},
            protocol::{Role, WebSocketConfig},
        },
    },
    layer::{AddExtensionLayer, ConsumeErrLayer},
    matcher::Matcher,
    net::{
        http::RequestContext,
        proxy::ProxyTarget,
        stream::layer::http::BodyLimitLayer,
        tls::{
            ApplicationProtocol, SecureTransport,
            client::ServerVerifyMode,
            server::{SelfSignedData, ServerAuth, ServerConfig},
        },
        user::Basic,
    },
    rt::Executor,
    service::service_fn,
    tcp::server::TcpListener,
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::{
        client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
        server::{TlsAcceptorData, TlsAcceptorLayer},
    },
    ua::{
        layer::emulate::{
            UserAgentEmulateHttpConnectModifierLayer, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer,
        },
        profile::UserAgentDatabase,
    },
};

use itertools::Itertools;
use std::{convert::Infallible, sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    ua_db: Arc<UserAgentDatabase>,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let mitm_tls_service_data =
        new_mitm_tls_service_data().context("generate self-signed mitm tls cert")?;

    let state = State {
        mitm_tls_service_data,
        ua_db: Arc::new(UserAgentDatabase::embedded()),
    };

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(async |guard| {
        let tcp_service = TcpListener::build()
            .bind("127.0.0.1:62017")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62017");

        let exec = Executor::graceful(guard.clone());

        let http_mitm_service = new_http_mitm_proxy(&state);
        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(Basic::new_static("john", "secret")),
                UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ),
            )
                .into_layer(http_mitm_service),
        );

        tcp_service
            .serve_graceful(
                guard,
                (
                    AddExtensionLayer::new(state),
                    // protect the http proxy from too large bodies, both from request and response end
                    BodyLimitLayer::symmetric(2 * 1024 * 1024),
                )
                    .into_layer(http_service),
            )
            .await;
    });

    graceful
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .context("graceful shutdown")?;

    Ok(())
}

async fn http_connect_accept(mut req: Request) -> Result<(Response, Request), Response> {
    match RequestContext::try_from(&req).map(|ctx| ctx.authority) {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host(),
                server.port = %authority.port(),
                "accept CONNECT (lazy): insert proxy target into context",
            );
            req.extensions_mut().insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), req))
}

async fn http_connect_proxy(upgraded: Upgraded) -> Result<(), Infallible> {
    // In the past we deleted the request context here, as such:
    // ```
    // ctx.remove::<RequestContext>();
    // ```
    // This is however not correct, as the request context remains true.
    // The user proxies here with a target as aim. This target, incoming version
    // and so on does not change. This initial context remains true
    // and should be preserved. This is especially important,
    // as we otherwise might not be able to define the scheme/authority
    // for upstream http requests.

    let state = upgraded.extensions().get::<State>().unwrap();
    let http_service = new_http_mitm_proxy(state);

    let executor = upgraded
        .extensions()
        .get::<Executor>()
        .cloned()
        .unwrap_or_default();

    let mut http_tp = HttpServer::auto(executor);
    http_tp.h2_mut().enable_connect_protocol();

    let http_transport_service = http_tp.service(http_service);

    let https_service = TlsAcceptorLayer::new(state.mitm_tls_service_data.clone())
        .with_store_client_hello(true)
        .into_layer(http_transport_service);

    https_service.serve(upgraded).await.expect("infallible");

    Ok(())
}

fn new_http_mitm_proxy(
    state: &State,
) -> impl Service<Request, Response = Response, Error = Infallible> {
    (
        MapResponseBodyLayer::new(Body::new),
        TraceLayer::new_for_http(),
        ConsumeErrLayer::default(),
        UserAgentEmulateLayer::new(state.ua_db.clone())
            .try_auto_detect_user_agent(true)
            .optional(true),
        CompressAdaptLayer::default(),
        AddRequiredRequestHeadersLayer::new(),
        EmulateTlsProfileLayer::new(),
    )
        .into_layer(service_fn(http_mitm_proxy))
}

async fn http_mitm_proxy(req: Request) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations

    let base_tls_config = if let Some(hello) = req
        .extensions()
        .get::<SecureTransport>()
        .and_then(|st| st.client_hello())
        .cloned()
    {
        // TODO once we fully support building this from client hello directly remove this unwrap
        TlsConnectorDataBuilder::try_from(hello).unwrap()
    } else {
        TlsConnectorDataBuilder::new_http_auto()
    };
    let base_tls_config = base_tls_config.with_server_verify_mode(ServerVerifyMode::Disable);

    let executor = req
        .extensions()
        .get::<Executor>()
        .cloned()
        .unwrap_or_default();

    // NOTE: in a production proxy you most likely
    // wouldn't want to build this each invocation,
    // but instead have a pre-built one as a struct local
    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(Arc::new(base_tls_config)))
        .with_custom_connector(UserAgentEmulateHttpConnectModifierLayer::default())
        .with_default_http_connector()
        .with_svc_req_inspector((
            UserAgentEmulateHttpRequestModifier::default(),
            // these layers are for example purposes only,
            // best not to print requests like this in production...
            //
            // If you want to see the request that actually is send to the server
            // you also usually do not want it as a layer, but instead plug the inspector
            // directly JIT-style into your http (client) connector.
            RequestWriterInspector::stdout_unbounded(
                &executor,
                Some(traffic_writer::WriterMode::Headers),
            ),
        ))
        .build();

    if WebSocketMatcher::new().matches(None, &req) {
        return Ok(mitm_websocket(&client, req).await);
    }

    // these are not desired for WS MITM flow, but they are for regular HTTP flow
    let client = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
    )
        .into_layer(client);

    match client.serve(req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!("error in client request: {err:?}");
            Ok(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

// NOTE: for a production service you ideally use
// an issued TLS cert (if possible via ACME). Or at the very least
// load it in from memory/file, so that your clients can install the certificate for trust.
fn new_mitm_tls_service_data() -> Result<TlsAcceptorData, OpaqueError> {
    let tls_server_config = ServerConfig {
        application_layer_protocol_negotiation: Some(vec![
            ApplicationProtocol::HTTP_2,
            ApplicationProtocol::HTTP_11,
        ]),
        ..ServerConfig::new(ServerAuth::SelfSigned(SelfSignedData {
            organisation_name: Some("Example Server Acceptor".to_owned()),
            ..Default::default()
        }))
    };
    tls_server_config
        .try_into()
        .context("create tls server config")
}

async fn mitm_websocket<S>(client: &S, req: Request) -> Response
where
    S: Service<Request, Response = Response, Error = OpaqueError>,
{
    tracing::debug!("detected websocket request: starting MITM WS upgrade...");

    let (parts, body) = req.into_parts();
    let parts_copy = parts.clone();

    let req = Request::from_parts(parts, body);
    let guard = req
        .extensions()
        .get::<Executor>()
        .and_then(|exec| exec.guard())
        .cloned();
    let cancel = async move {
        match guard {
            Some(guard) => guard.downgrade().into_cancelled().await,
            None => std::future::pending::<()>().await,
        }
    };

    let target_version = req.version();
    tracing::debug!("forcing egress http connection as {target_version:?} to ensure WS upgrade");

    // Todo improve extensions handling here? This feels error prone and easy to forget.
    // In a better way this should be handled behind the scenes similar to tls alpn works
    // Now that we can pass extensions all around this will probably just work, but needs
    // to be looked at individually
    let mut extensions = Extensions::new();
    extensions.insert(TargetHttpVersion(target_version));

    let mut handshake = match client
        .websocket_with_request(req)
        .initiate_handshake(extensions)
        .await
    {
        Ok(socket) => socket,
        Err(err) => {
            tracing::error!("failed to create initiate egress websocket handshake: {err:?}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    if let Some(orig_req_headers) = handshake.response.extensions().get::<RequestHeaders>() {
        let req_extensions = orig_req_headers
            .headers()
            .typed_get::<SecWebSocketExtensions>();
        tracing::debug!(
            "apply original req WS extensions (perhaps after UA Emulation) as handshake exts: {req_extensions:?}"
        );
        handshake.extensions = req_extensions;
    }

    let egress_socket = match handshake.complete().await {
        Ok(socket) => socket,
        Err(err) => {
            tracing::error!("failed to complete WS handshake and create egress websocket: {err:?}");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let (egress_socket, mut response_parts, _) = egress_socket.into_parts();

    let mut ingress_socket_cfg: WebSocketConfig = Default::default();
    if let Some(ingress_header) = parts_copy.headers.typed_get::<SecWebSocketExtensions>() {
        tracing::debug!("ingress request contains sec-websocket-extensions header");
        if let Some(accept_pmd_cfg) = ingress_header.iter().find_map(|ext| {
            if let Extension::PerMessageDeflate(cfg) = ext {
                Some(cfg.clone())
            } else {
                None
            }
        }) {
            tracing::debug!("use deflate ext for ingress ws cfg: {accept_pmd_cfg:?}");
            ingress_socket_cfg.per_message_deflate = Some((&accept_pmd_cfg).into());
            let _ = response_parts.headers.insert(
                SecWebSocketExtensions::name(),
                SecWebSocketExtensions::per_message_deflate_with_config(accept_pmd_cfg)
                    .encode_to_value(),
            );
        } else {
            tracing::debug!(
                "remove sec-websocket-extensions header if it exts: no ext was requested by ingress client"
            );
            let _ = response_parts
                .headers
                .remove(SecWebSocketExtensions::name());
        }
    } else {
        tracing::debug!("ingress request does not contain sec-websocket-extensions header");
    }

    let response = Response::from_parts(response_parts, Body::empty());

    tokio::spawn(async move {
        tracing::debug!("egresss websocket active: starting ingress WS upgrade...");
        let request = Request::from_parts(parts_copy, Body::empty());

        let ingress_socket = match upgrade::handle_upgrade(&request).await {
            Ok(upgraded) => {
                let socket = AsyncWebSocket::from_raw_socket(
                    upgraded,
                    Role::Server,
                    Some(ingress_socket_cfg),
                )
                .await;
                // TODO in a place like this we dont really want to extend but instead prepend
                // which probably means we should do it here, but it should have already happened
                // socket.extensions_mut().extend(request.extensions().clone());
                #[allow(clippy::let_and_return)]
                socket
            }
            Err(err) => {
                tracing::error!("error in upgrading ingress websocket: {err:?}");
                return;
            }
        };
        tracing::debug!("both ingress and egress websockets active: MITM Relay started");

        relay_websockets(cancel, ingress_socket, egress_socket).await;
    });

    tracing::debug!("return egress WebSocket accept response as ingress WebSocket response");
    response
}

async fn relay_websockets<F>(
    cancel: F,
    mut ingress_socket: AsyncWebSocket,
    mut egress_socket: AsyncWebSocket,
) where
    F: Future<Output = ()>,
{
    let mut cancel = Box::pin(cancel);

    loop {
        tokio::select! {
            ingress_result = ingress_socket.recv_message() => {
                match ingress_result {
                    Ok(msg) => {
                        if let Some(msg) = mod_ws_message(msg) {
                            tracing::info!("relay ingress msg: {msg}");
                            if let Err(err) = egress_socket.send(msg).await {
                                if err.is_connection_error() {
                                    tracing::debug!("egress socket disconnected ({err})... drop MITM relay");
                                    return;
                                }
                                tracing::error!("failed to relay ingress msg: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        if err.is_connection_error() || matches!(err, ProtocolError::ResetWithoutClosingHandshake) {
                            tracing::debug!("ingress socket disconnected ({err})... drop MITM relay");
                        } else {
                            tracing::error!("ingress socket failed with error: {err}; drop MITM relay");
                        }
                        return
                    }
                }
            }

            egress_result = egress_socket.recv_message() => {
                match egress_result {
                    Ok(msg) => {
                        if let Some(msg) = mod_ws_message(msg) {
                            tracing::info!("relay egress msg: {msg}");
                            if let Err(err) = ingress_socket.send(msg).await {
                                if err.is_connection_error() {
                                    tracing::debug!("ingress socket disconnected ({err})... drop MITM relay");
                                    return;
                                }
                                tracing::error!("failed to relay egress msg: {err}");
                            }
                        }
                    }
                    Err(err) => {
                        if err.is_connection_error() || matches!(err, ProtocolError::ResetWithoutClosingHandshake) {
                            tracing::debug!("egress socket disconnected ({err})... drop MITM relay");
                        } else {
                            tracing::error!("egress socket failed with error: {err}; drop MITM relay");
                        }
                        return
                    }
                }
            }

            _ = cancel.as_mut() => {
                tracing::debug!("shutdown initiated... drop MITM relay early (cancelled)");
                return;
            }
        }
    }
}

fn mod_ws_message(msg: Message) -> Option<Message> {
    match msg {
        Message::Text(utf8_bytes) => {
            let s = utf8_bytes.as_str();

            let filtered_s = s
                .split_whitespace()
                .map(|word| {
                    let (prefix, core, suffix) = split_word(word);

                    let replacement = if core.eq_ignore_ascii_case("damn") {
                        Some("frack")
                    } else if core.eq_ignore_ascii_case("hell") {
                        Some("heckscape")
                    } else if core.eq_ignore_ascii_case("shit") {
                        Some("gronk")
                    } else if core.eq_ignore_ascii_case("fuck") {
                        Some("zarquon")
                    } else if core.eq_ignore_ascii_case("bastard") {
                        Some("shazbot")
                    } else if core.eq_ignore_ascii_case("crap") {
                        Some("quant-dump")
                    } else if core.eq_ignore_ascii_case("idiot") {
                        Some("neural-misfire")
                    } else if core.eq_ignore_ascii_case("stupid") {
                        Some("entropy-brained")
                    } else {
                        None
                    };

                    match replacement {
                        Some(rep) => format!("{prefix}{rep}{suffix}"),
                        None => word.to_owned(),
                    }
                })
                .join(" ");

            Some(filtered_s.into())
        }
        Message::Binary(_) => {
            tracing::warn!("drop unsupported ws message: {msg}");
            None
        }
        Message::Ping(_) | Message::Pong(_) | Message::Close(_) | Message::Frame(_) => {
            tracing::debug!("ignore meta ws message: {msg}");
            None
        }
    }
}

fn split_word(word: &str) -> (&str, &str, &str) {
    let bytes = word.as_bytes();
    let mut start = 0;
    let mut end = bytes.len();

    while start < end && !bytes[start].is_ascii_alphanumeric() {
        start += 1;
    }
    while end > start && !bytes[end - 1].is_ascii_alphanumeric() {
        end -= 1;
    }

    let prefix = &word[..start];
    let core = &word[start..end];
    let suffix = &word[end..];
    (prefix, core, suffix)
}
