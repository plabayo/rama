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
//! # Expected output
//!
//! The server will start and listen on `:62017`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' http://www.example.com/
//! curl -k -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' https://www.example.com/
//! ```

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        Body, Request, Response, StatusCode,
        client::EasyHttpWebClient,
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
        server::HttpServer,
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
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
    tls::boring::client::{EmulateTlsProfileLayer, TlsConnectorDataBuilder},
    tls::boring::server::{TlsAcceptorData, TlsAcceptorLayer},
    ua::{
        emulate::{
            UserAgentEmulateHttpConnectModifier, UserAgentEmulateHttpRequestModifier,
            UserAgentEmulateLayer,
        },
        profile::UserAgentDatabase,
    },
};

use std::{convert::Infallible, sync::Arc, time::Duration};
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Debug, Clone)]
struct State {
    mitm_tls_service_data: TlsAcceptorData,
    ua_db: Arc<UserAgentDatabase>,
}

type Context = rama::Context<State>;

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
        let tcp_service = TcpListener::build_with_state(state.clone())
            .bind("127.0.0.1:62017")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62017");

        let exec = Executor::graceful(guard.clone());
        let http_mitm_service = new_http_mitm_proxy(&Context::with_state(state));
        let http_service = HttpServer::auto(exec).service(
            (
                TraceLayer::new_for_http(),
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                ProxyAuthLayer::new(Basic::new("john", "secret")),
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

async fn http_connect_accept(
    mut ctx: Context,
    req: Request,
) -> Result<(Response, Context, Request), Response> {
    match ctx
        .get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into())
        .map(|ctx| ctx.authority.clone())
    {
        Ok(authority) => {
            tracing::info!(
                server.address = %authority.host(),
                server.port = %authority.port(),
                "accept CONNECT (lazy): insert proxy target into context",
            );
            ctx.insert(ProxyTarget(authority));
        }
        Err(err) => {
            tracing::error!("error extracting authority: {err:?}");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy(ctx: Context, upgraded: Upgraded) -> Result<(), Infallible> {
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

    let http_service = new_http_mitm_proxy(&ctx);

    let http_transport_service = HttpServer::auto(ctx.executor().clone()).service(http_service);

    let https_service = TlsAcceptorLayer::new(ctx.state().mitm_tls_service_data.clone())
        .with_store_client_hello(true)
        .into_layer(http_transport_service);

    https_service
        .serve(ctx, upgraded)
        .await
        .expect("infallible");

    Ok(())
}

fn new_http_mitm_proxy(
    ctx: &Context,
) -> impl Service<State, Request, Response = Response, Error = Infallible> {
    (
        MapResponseBodyLayer::new(Body::new),
        TraceLayer::new_for_http(),
        ConsumeErrLayer::default(),
        UserAgentEmulateLayer::new(ctx.state().ua_db.clone())
            .try_auto_detect_user_agent(true)
            .optional(true),
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        CompressAdaptLayer::default(),
        AddRequiredRequestHeadersLayer::new(),
        EmulateTlsProfileLayer::new(),
    )
        .into_layer(service_fn(http_mitm_proxy))
}

async fn http_mitm_proxy(ctx: Context, req: Request) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations

    let base_tls_config = if let Some(hello) = ctx
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

    let client = EasyHttpWebClient::builder()
        .with_default_transport_connector()
        .with_tls_proxy_support_using_boringssl()
        .with_proxy_support()
        .with_tls_support_using_boringssl(Some(Arc::new(base_tls_config)))
        .with_jit_req_inspector(UserAgentEmulateHttpConnectModifier::default())
        .with_svc_req_inspector((
            UserAgentEmulateHttpRequestModifier::default(),
            // these layers are for example purposes only,
            // best not to print requests like this in production...
            //
            // If you want to see the request that actually is send to the server
            // you also usually do not want it as a layer, but instead plug the inspector
            // directly JIT-style into your http (client) connector.
            RequestWriterInspector::stdout_unbounded(
                ctx.executor(),
                Some(traffic_writer::WriterMode::Headers),
            ),
        ))
        .build();

    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!("error in client request: {err:?}");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
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
