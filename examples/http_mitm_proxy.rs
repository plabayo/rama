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
//! - [`tls_termination`](./tls_termination.rs);
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example http_mitm_proxy --features=rustls
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62017`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' http://www.example.com/
//! curl -v -x http://127.0.0.1:62017 --proxy-user 'john:secret' https://www.example.com/
//! ```

use rama::{
    error::{BoxError, ErrorContext, OpaqueError},
    http::{
        client::HttpClient,
        layer::{
            map_response_body::MapResponseBodyLayer,
            proxy_auth::ProxyAuthLayer,
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            required_header::AddRequiredRequestHeadersLayer,
            trace::TraceLayer,
            traffic_writer::{self, RequestWriterLayer},
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        Body, IntoResponse, Request, RequestContext, Response, StatusCode,
    },
    layer::ConsumeErrLayer,
    net::user::Basic,
    rt::Executor,
    service::service_fn,
    stream::layer::http::BodyLimitLayer,
    tcp::server::TcpListener,
    tls::{
        backend::rustls::{
            dep::{
                pki_types::{CertificateDer, PrivatePkcs8KeyDer},
                rustls::ServerConfig,
            },
            server::TlsAcceptorLayer,
        },
        dep::rcgen::KeyPair,
    },
    Layer, Service,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Debug, Clone)]
struct State {
    mitm_tls_config: Arc<ServerConfig>,
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

    let mitm_tls_config = Arc::new(
        mitm_tls_server_credentials()
            .map_err(OpaqueError::from_boxed)
            .context("generate self-signed mitm tls cert")?,
    );
    let state = State { mitm_tls_config };

    let graceful = rama::graceful::Shutdown::default();

    graceful.spawn_task_fn(|guard| async move {
        let tcp_service = TcpListener::build_with_state(state)
            .bind("127.0.0.1:62017")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62017");

        let exec = Executor::graceful(guard.clone());
        let http_mitm_service = new_http_mitm_proxy(&exec);
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
                .layer(http_mitm_service),
        );

        tcp_service
            .serve_graceful(
                guard,
                (
                    // protect the http proxy from too large bodies, both from request and response end
                    BodyLimitLayer::symmetric(2 * 1024 * 1024),
                )
                    .layer(http_service),
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
    match ctx.get_or_try_insert_with_ctx::<RequestContext, _>(|ctx| (ctx, &req).try_into()) {
        Ok(request_ctx) => {
            tracing::info!("accept CONNECT to {}", request_ctx.authority);
        }
        Err(err) => {
            tracing::error!(err = %err, "error extracting authority");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy(mut ctx: Context, upgraded: Upgraded) -> Result<(), Infallible> {
    // delete request context as a new one should be made per seen request
    ctx.remove::<RequestContext>();

    let http_service = new_http_mitm_proxy(ctx.executor());

    let http_transport_service = HttpServer::auto(ctx.executor().clone()).service(http_service);

    let https_service =
        TlsAcceptorLayer::new(ctx.state().mitm_tls_config.clone()).layer(http_transport_service);

    https_service
        .serve(ctx, upgraded)
        .await
        .expect("infallible");

    Ok(())
}

fn new_http_mitm_proxy(
    exec: &Executor,
) -> impl Service<State, Request, Response = Response, Error = Infallible> {
    (
        MapResponseBodyLayer::new(Body::new),
        TraceLayer::new_for_http(),
        RemoveResponseHeaderLayer::hop_by_hop(),
        RemoveRequestHeaderLayer::hop_by_hop(),
        ConsumeErrLayer::default(),
        AddRequiredRequestHeadersLayer::new(),
        // these layers are for example purposes only,
        // best not to print requests like this in production...
        RequestWriterLayer::stdout_unbounded(exec, Some(traffic_writer::WriterMode::Headers)),
    )
        .layer(service_fn(http_mitm_proxy))
}

async fn http_mitm_proxy(ctx: Context, req: Request) -> Result<Response, Infallible> {
    // This function will receive all requests going through this proxy,
    // be it sent via HTTP or HTTPS, both are equally visible. Hence... MITM

    // NOTE: use a custom connector (layers) in case you wish to add custom features,
    // such as upstream proxies or other configurations
    let client = HttpClient::default();
    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = ?err, "error in client request");
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
fn mitm_tls_server_credentials() -> Result<ServerConfig, BoxError> {
    // Create an issuer CA cert.
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key_pair = KeyPair::generate_for(alg).expect("generate ca key pair");

    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("create ca params");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Example CA");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;

    let server_key_pair = KeyPair::generate_for(alg)?;
    let mut server_ee_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])?;
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_ee_params.signed_by(&server_key_pair, &ca_cert, &ca_key_pair)?;
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    let mut tls_server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert_der],
            PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
        )?;
    tls_server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tls_server_config)
}
