//! HTTP(S) MITM proxy that replaces the client's fingerprint with a captured
//! browser profile.
//!
//! Relay examples such as `http_mitm_relay_proxy_boring` mirror the client.
//! This proxy terminates ingress TLS and sends every request again through its
//! own client, which emulates a profile from rama's embedded database: the TLS
//! ClientHello, HTTP/2 settings and request headers all come from that profile.
//!
//! The profile is chosen from proxy-auth username labels, so each client
//! picks its own identity without changing the proxy:
//!
//! - `john`: no filter, any embedded profile;
//! - `john-ua_firefox`: a Firefox profile;
//! - `john-ua_chrome-ua_macos`: a Chrome profile on macOS;
//! - `john-ua_mobile`: any mobile profile.
//!
//! Egress certificate verification is disabled, as in the other MITM examples.
//! This example is not production ready: load a persistent, client-trusted MITM
//! CA and verify egress certificates in a real deployment.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_mitm_proxy_emulate_boring --features=http-full,boring,ua-embed-profiles
//! ```
//!
//! # Expected output
//!
//! The server listens on `127.0.0.1:12066`. Compare the fingerprints echo.ramaproxy.org
//! reports for different labels:
//!
//! ```sh
//! curl -k -x http://127.0.0.1:12066 --proxy-user 'john-ua_firefox:secret' https://echo.ramaproxy.org/
//! curl -k -x http://127.0.0.1:12066 --proxy-user 'john-ua_chrome-ua_macos:secret' https://echo.ramaproxy.org/
//! ```

#![expect(
    clippy::expect_used,
    reason = "example/test/bench: panic-on-error and print-for-output are the standard patterns for demos and harnesses"
)]

use rama::{
    Layer, Service,
    error::{BoxError, ErrorContext},
    extensions::{Extension, ExtensionsRef},
    graceful::{Scope, WeakScope},
    http::{
        Body, BodyLimitLayer, Request, Response, StatusCode,
        client::EasyHttpWebClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            trace::TraceLayer,
            upgrade::{LazyHttpProxyConnectReplyService, UpgradeLayer, UpgradeResponse, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    layer::{AddInputExtensionLayer, ConsumeErrLayer},
    net::user::credentials::basic,
    service::{BoxService, service_fn},
    tcp::server::TcpListener,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt},
    },
    tls::{
        boring::{client::profile::compiler::ConnectionProfileCompiler, server::TlsAcceptorLayer},
        client::{ServerVerifyMode, TlsClientConfig},
        server::{GeneratedServerAuthConfig, TlsServerConfig},
    },
    ua::{
        UserAgent,
        layer::emulate::{
            ProfileEmulateHttpConnectModifier, ProfileEmulateHttpRequestModifierLayer,
            ProfileEmulateLayer, ProfileSelectFallback, ProfileSelectorUsernameParser,
        },
        profile::selection::database::UserAgentDatabase,
    },
    utils::octets::mib,
};

use std::{convert::Infallible, sync::Arc, time::Duration};

type EmulatingClient = BoxService<Request, Response, BoxError>;

#[derive(Debug, Clone, Extension)]
struct State {
    mitm_tls: TlsServerConfig,
    client: EmulatingClient,
    scope: WeakScope,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let scope = Scope::new()
        .with_default_signal()
        .with_grace(Duration::from_secs(30));
    let weak_scope = scope.clone_weak();

    let database =
        Arc::new(UserAgentDatabase::try_embedded().context("load embedded user-agent database")?);
    let state = State {
        mitm_tls: TlsServerConfig::new()
            .try_with_generated_server_auth(GeneratedServerAuthConfig::default())
            .context("generate MITM server auth")?
            .with_alpn_http_auto(),
        client: new_emulating_client(database, weak_scope.clone()),
        scope: weak_scope.clone(),
    };

    scope.spawn_task(async move {
        let tcp_service = TcpListener::build(weak_scope.clone())
            .bind_address("127.0.0.1:12066")
            .await
            .expect("bind tcp proxy to 127.0.0.1:12066");

        let http_service = HttpServer::auto(weak_scope.clone()).service(Arc::new(
            (
                TraceLayer::new_for_http(),
                ConsumeErrLayer::default(),
                ProxyAuthLayer::new(basic!("john", "secret"))
                    .with_labels::<ProfileSelectorUsernameParser>(),
                // Defer egress until the decrypted request selects its profile.
                UpgradeLayer::new_with_services(
                    weak_scope,
                    MethodMatcher::CONNECT,
                    service_fn(reply_to_connect),
                    service_fn(serve_tunnel),
                ),
            )
                .into_layer(new_mitm_service()),
        ));

        tcp_service
            .serve(
                (
                    AddInputExtensionLayer::new(state),
                    BodyLimitLayer::symmetric(mib(2)),
                )
                    .into_layer(http_service),
            )
            .await;
    });

    scope.join().await.context("graceful shutdown")?;

    Ok(())
}

/// Accepts the CONNECT and hands the profile filter its username labels chose to
/// the tunnel: CONNECT request extensions do not reach the upgraded stream.
async fn reply_to_connect(req: Request) -> Result<UpgradeResponse<Request, Response>, Response> {
    let agent = req.extensions().get_ref::<UserAgent>().cloned();
    let upgrade = LazyHttpProxyConnectReplyService::new().serve(req).await?;
    Ok(match agent {
        Some(agent) => upgrade.with_extension(agent),
        None => upgrade,
    })
}

async fn serve_tunnel(upgraded: Upgraded) -> Result<(), BoxError> {
    let state = upgraded
        .extensions()
        .get_ref::<State>()
        .context("missing proxy state")?
        .clone();
    let http_service = HttpServer::auto(state.scope.clone()).service(new_mitm_service());
    TlsAcceptorLayer::new(state.mitm_tls)
        .into_layer(http_service)
        .serve(upgraded)
        .await
}

fn new_mitm_service() -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    Arc::new(
        (
            RemoveRequestHeaderLayer::hop_by_hop(),
            MapResponseBodyLayer::new_boxed_streaming_body(),
            TraceLayer::new_for_http(),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(service_fn(forward)),
    )
}

async fn forward(req: Request) -> Result<Response, Infallible> {
    let Some(client) = req
        .extensions()
        .get_ref::<State>()
        .map(|state| state.client.clone())
    else {
        return Ok(error_response(StatusCode::INTERNAL_SERVER_ERROR));
    };
    match client.serve(req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!("emulated egress request failed: {err:?}");
            Ok(error_response(StatusCode::BAD_GATEWAY))
        }
    }
}

fn error_response(status: StatusCode) -> Response {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = status;
    resp
}

fn new_emulating_client(database: Arc<UserAgentDatabase>, scope: WeakScope) -> EmulatingClient {
    // The selected profile supplies ALPN and every other ClientHello field.
    let tls_config = TlsClientConfig::new().with_server_verify(ServerVerifyMode::Disable);
    let client = EasyHttpWebClient::connector_builder()
        .with_default_transport_connector()
        .with_default_dns_connector()
        .without_tls_proxy_support()
        .without_proxy_support()
        .with_tls_support_using_boringssl(tls_config.clone())
        .map_connector(|connector| {
            ProfileEmulateHttpConnectModifier::new(connector)
                .with_connection_compiler(ConnectionProfileCompiler::new(tls_config))
        })
        .with_default_http_connector(scope)
        // Erase the deep emulating connector type before pooling it.
        .map_connector(|connector| connector.boxed())
        .with_default_connection_pool()
        .build_client()
        .with_jit_layer(ProfileEmulateHttpRequestModifierLayer);
    // The client's own User-Agent is not used: labels alone choose the profile.
    ProfileEmulateLayer::new(database)
        .with_select_fallback(ProfileSelectFallback::SameClient)
        .into_layer(client)
        .boxed()
}
