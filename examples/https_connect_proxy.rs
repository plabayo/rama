//! This example demonstrates how to create an https proxy.
//!
//! This proxy example does not perform any TLS termination on the actual proxied traffic.
//! It is an adoptation of the `http_connect_proxy` example with tls termination for the incoming connections.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example https_connect_proxy
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:62016`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl --proxy-insecure -v -x https://127.0.0.1:62016 --proxy-user 'john:secret' http://www.example.com
//! curl --proxy-insecure -k -v https://127.0.0.1:62016 --proxy-user 'john:secret' https://www.example.com
//! ```
//!
//! You should see in both cases the responses from the example domains.
//!
//! In case you want to use it in a standard browser,
//! you'll need to first import and trust the generated certificate.

use rama::{
    http::{
        client::HttpClient,
        layer::{
            proxy_auth::ProxyAuthLayer,
            trace::TraceLayer,
            upgrade::{UpgradeLayer, Upgraded},
        },
        matcher::MethodMatcher,
        server::HttpServer,
        Body, IntoResponse, Request, RequestContext, Response, StatusCode,
    },
    rt::Executor,
    service::{service_fn, Context, Service, ServiceBuilder},
    stream::layer::http::BodyLimitLayer,
    tcp::{server::TcpListener, utils::is_connection_error},
    tls::{
        dep::rcgen::KeyPair,
        rustls::{
            dep::{
                pki_types::{CertificateDer, PrivatePkcs8KeyDer},
                rustls::ServerConfig,
            },
            server::{IncomingClientHello, TlsAcceptorLayer, TlsClientConfigHandler},
        },
    },
    utils::graceful::Shutdown,
};

use std::convert::Infallible;
use std::time::Duration;
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::DEBUG.into())
                .from_env_lossy(),
        )
        .init();

    let shutdown = Shutdown::default();

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
    let ca_cert = ca_params.self_signed(&ca_key_pair).expect("create ca cert");

    // Create a server end entity cert issued by the CA.
    let server_key_pair = KeyPair::generate_for(alg).expect("generate server key pair");
    let mut server_ee_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()])
        .expect("create server ee params");
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_ee_params
        .signed_by(&server_key_pair, &ca_cert, &ca_key_pair)
        .expect("create server cert");
    let server_cert_der: CertificateDer = server_cert.into();
    let server_key_der = PrivatePkcs8KeyDer::from(server_key_pair.serialize_der());

    // create tls proxy
    shutdown.spawn_task_fn(|guard| async move {
        let tls_client_config_handler = TlsClientConfigHandler::default()
            .store_client_hello()
            .server_config_provider(|client_hello: IncomingClientHello| async move {
                tracing::debug!(?client_hello, "client hello");

                // Return None in case you want to use the default acceptor Tls config
                // Usually though when implementing this trait it's because you
                // want to use the client hello to determine which server config to use.
                Ok(None)
            });

        let tls_server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![server_cert_der],
                PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
            )
            .expect("create tls server config");

        let tcp_service = TcpListener::build()
            .bind("127.0.0.1:62016")
            .await
            .expect("bind tcp proxy to 127.0.0.1:62016");

        let exec = Executor::graceful(guard.clone());
        let http_service = HttpServer::auto(exec).service(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                // See [`ProxyAuthLayer::with_labels`] for more information,
                // e.g. can also be used to extract upstream proxy filters
                .layer(ProxyAuthLayer::basic(("john", "secret")))
                .layer(UpgradeLayer::new(
                    MethodMatcher::CONNECT,
                    service_fn(http_connect_accept),
                    service_fn(http_connect_proxy),
                ))
                .service_fn(http_plain_proxy),
        );

        tcp_service
            .serve_graceful(
                guard,
                ServiceBuilder::new()
                    // protect the http proxy from too large bodies, both from request and response end
                    .layer(BodyLimitLayer::symmetric(2 * 1024 * 1024))
                    .layer(TlsAcceptorLayer::with_client_config_handler(
                        tls_server_config,
                        tls_client_config_handler,
                    ))
                    .service(http_service),
            )
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn http_connect_accept<S>(
    mut ctx: Context<S>,
    req: Request,
) -> Result<(Response, Context<S>, Request), Response>
where
    S: Send + Sync + 'static,
{
    match ctx
        .get_or_insert_with::<RequestContext>(|| RequestContext::from(&req))
        .host
        .as_ref()
    {
        Some(host) => tracing::info!("accept CONNECT to {host}"),
        None => {
            tracing::error!("error extracting host");
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
    }

    Ok((StatusCode::OK.into_response(), ctx, req))
}

async fn http_connect_proxy<S>(ctx: Context<S>, mut upgraded: Upgraded) -> Result<(), Infallible>
where
    S: Send + Sync + 'static,
{
    let host = ctx
        .get::<RequestContext>()
        .unwrap()
        .host
        .as_ref()
        .unwrap()
        .clone();
    tracing::info!("CONNECT to {}", host);
    let mut stream = match tokio::net::TcpStream::connect(&host).await {
        Ok(stream) => stream,
        Err(err) => {
            tracing::error!(error = %err, "error connecting to host");
            return Ok(());
        }
    };
    if let Err(err) = tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await {
        if !is_connection_error(&err) {
            tracing::error!(error = %err, "error copying data");
        }
    }
    Ok(())
}

async fn http_plain_proxy<S>(ctx: Context<S>, req: Request) -> Result<Response, Infallible>
where
    S: Send + Sync + 'static,
{
    let client = HttpClient::default();
    match client.serve(ctx, req).await {
        Ok(resp) => Ok(resp),
        Err(err) => {
            tracing::error!(error = %err, "error in client request");
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::empty())
                .unwrap())
        }
    }
}
