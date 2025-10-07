//! This example is an adapted MITM (http) proxy which is mostly here to demonstrate
//! the HAR Export Layer in action. It can be used for clients, proxies and even servers,
//! to provide HAR export functionality for diagnostic and support purposes.
//!
//! As with most other examples, it is not meant to show a full production-ready setup,
//! but it is purely here to demonstrate a specific feature, HAR Exporting for this example.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_record_har --features=http-full,boring
//! ```
//!
//! ## Expected output
//!
//! The server will start and listen on `:62040`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62040 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62040 --proxy-user 'john:secret' https://www.example.com/
//! ```
//!
//! You can toggle the HAR Recording on and off using:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62040 --proxy-user 'john:secret' -XPOST http://har.toggle.internal/switch
//! ```
//!
//! This example injects the path of the file that a http request
//! is recorded to. Do not do this in production kids.
//!
//! Once a recording is finished you can import or replay the HAR file in
//! a tool for analysis. For example dev tools of a browser or some special-purpose
//! HAR Analyzer tool.

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    extensions::{ExtensionsMut, ExtensionsRef},
    http::{
        Body, HeaderValue, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            compress_adapter::CompressAdaptLayer,
            har::{
                self,
                layer::HARExportLayer,
                recorder::{FileRecorder, HarFilePath, Recorder},
            },
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::{DomainMatcher, MethodMatcher},
        server::HttpServer,
        service::web::{WebService, response::IntoResponse},
    },
    layer::{AddExtensionLayer, ConsumeErrLayer, HijackLayer},
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
        emulate::{
            UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer,
        },
        profile::UserAgentDatabase,
    },
};

use std::{
    convert::Infallible,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
use tokio::sync::mpsc;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    ua_db: Arc<UserAgentDatabase>,
    har_layer: HARExportLayer<FileRecorder, Arc<AtomicBool>>,
    har_toggle_ctl: mpsc::Sender<()>,
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

    let graceful = rama::graceful::Shutdown::default();

    let (har_toggle, har_toggle_ctl) =
        har::toggle::mpsc_toggle(8, graceful.guard_weak().into_cancelled());
    let har_layer = HARExportLayer::new(FileRecorder::default(), har_toggle);

    let state = State {
        mitm_tls_service_data,
        ua_db: Arc::new(UserAgentDatabase::embedded()),
        har_layer,
        har_toggle_ctl,
    };

    graceful.spawn_task_fn(async |guard| {
        let tcp_service = TcpListener::build()
            .bind("127.0.0.1:62040")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62040");

        let exec = Executor::graceful(guard.clone());

        let http_mitm_service = new_http_mitm_proxy(&state);
        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(Basic::new_static("john", "secret")),
                // used to toggle HAR recording on and off
                // ...
                // NOTE that in a production proxy you would probably
                // put this behind its own local-only socket though,
                // not reachable from the outside, instead of exposing
                // it to the web...
                // ...
                // Remember kids: authentication != security
                HijackLayer::new(
                    DomainMatcher::exact("har.toggle.internal"),
                    Arc::new(WebService::default().post("/switch", async |req: Request| {
                        let state = req.extensions().get::<State>().unwrap();
                        if let Err(err) = state.har_toggle_ctl.send(()).await {
                            tracing::error!("failed to toggle HAR Recording: {err}");
                            return StatusCode::INTERNAL_SERVER_ERROR;
                        } else {
                            tracing::debug!(
                                "force a stop recording so the file immediately flushes (DX etc)"
                            );
                            state.har_layer.recorder.stop_record().await;
                        }
                        StatusCode::OK
                    })),
                ),
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

    // NOTE: in a production proxy you most likely
    // wouldn't want to build this each invocation,
    // but instead have a pre-built one as a struct local
    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(Arc::new(base_tls_config)))
        .with_jit_req_inspector(UserAgentEmulateHttpConnectModifier::default())
        .with_svc_req_inspector(UserAgentEmulateHttpRequestModifier::default())
        .build();

    let state = req.extensions().get::<State>().unwrap();

    // these are not desired for WS MITM flow, but they are for regular HTTP flow
    let client = (
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        state.har_layer.clone(),
    )
        .into_layer(client);

    match client.serve(req).await {
        Ok(mut resp) => {
            if let Some(har_fp) = resp
                .extensions()
                .get::<HarFilePath>()
                .map(|fp| fp.display().to_string())
                .map(|fp| HeaderValue::try_from(fp).unwrap())
            {
                resp.headers_mut().insert("x-rama-har-file-path", har_fp);
            }

            Ok(resp)
        }
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
