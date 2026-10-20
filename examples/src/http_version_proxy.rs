//! HTTP version conversion at a reverse proxy and a CONNECT MITM proxy.
//!
//! Run with `--features http-full,boring`. `ingress` accepts TLS h1/h2 and
//! QUIC h3 on the same address and forwards to a plaintext h1 origin.
//! `mitm` accepts h1/h2 CONNECT on TCP and terminates TLS inside the tunnel.
//! Usernames can contain one dash-separated label `h1`, `h2`, or `h3`
//! (e.g. `john-h3:secret`). This demo parses routing labels, not passwords.
//! Without a label, egress prefers the HTTP version inside the tunnel.
//!
//! Explicit labels are strict: the upstream connection is established before
//! CONNECT succeeds; failure returns 502, or 504 on timeout. This sends no
//! probe HTTP request. With no label, selection waits for the tunneled request;
//! connection failure then returns 502/504 inside the tunnel.
//!
//! Example (provide your own ingress PEM certificate/key):
//! ```sh
//! cargo run -p rama-examples --bin http_version_proxy --features http-full,boring -- ingress --cert cert.pem --key key.pem --upstream http://127.0.0.1:8080
//! cargo run -p rama-examples --bin http_version_proxy --features http-full,boring -- mitm --upstream-ca cert.pem
//! curl -k --proxy http://127.0.0.1:62065 --proxy-user john-h3:secret https://localhost:62064/
//! ```
//! The demo MITM uses an ephemeral CA; `-k` is for this local example only.
//! Both listeners bind loopback by default. Bodies remain streaming.

// The composed TCP/TLS/QUIC pooled connector exceeds rustc's default type-layout depth.
#![recursion_limit = "256"]

use clap::{Parser, Subcommand};
use rama::{
    Layer, Service,
    crypto::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    error::BoxError,
    extensions::{Extensions, ExtensionsRef as _},
    http::{
        Body, Request, Response, StatusCode, Version,
        client::{EasyHttpWebClient, Http3Connector},
        conn::TargetHttpVersion,
        headers::{HeaderMapExt as _, ProxyAuthorization},
        layer::{
            remove_header::{RemoveRequestHeaderLayer, RemoveResponseHeaderLayer},
            upgrade::{UpgradeLayer, UpgradeOutput, UpgradeResponse},
            version_adapter::ResponseVersionAdapter,
        },
        matcher::MethodMatcher,
        server::HttpServer,
    },
    net::{
        address::SocketAddress, client::ConnectorService as _, tls::ApplicationProtocol, uri::Uri,
        user::Basic,
    },
    quic::{
        Endpoint, ServerConfig, TransportConfig,
        tls::{BoringTlsProvider, TlsOptions},
    },
    rt::Executor,
    service::{BoxService, service_fn},
    tcp::server::TcpListener,
    tls::{
        boring::server::{BoringServerConfigExt as _, ServerCertIssuerData, TlsAcceptorLayer},
        client::TlsClientConfig,
        server::{ServerAuthData, TlsServerConfig},
    },
    username::{UsernameLabelParser, UsernameLabelState, parse_username_lossy},
};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type Web = Arc<BoxService<Request, Response, BoxError>>;
type Preflight = Arc<BoxService<Request, (), BoxError>>;

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    mode: Mode,
}

#[derive(Subcommand)]
enum Mode {
    Ingress {
        #[arg(long, default_value = "127.0.0.1:62064")]
        listen: SocketAddress,
        #[arg(long)]
        cert: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        upstream: Uri,
    },
    Mitm {
        #[arg(long, default_value = "127.0.0.1:62065")]
        listen: SocketAddress,
        #[arg(long)]
        upstream_ca: Option<PathBuf>,
    },
}

fn client(exec: Executor, tls: TlsClientConfig) -> Result<(Web, Preflight), BoxError> {
    let h3 = Http3Connector::builder(exec.clone())
        .with_tls_config(tls.clone())
        .with_tls_provider(Arc::new(BoringTlsProvider))
        .build_lazy()?;
    let connector = Arc::new(
        EasyHttpWebClient::connector_builder()
            .with_default_transport_connector()
            .with_default_dns_connector()
            .without_tls_proxy_support()
            .without_proxy_support()
            .with_tls_support_using_boringssl_and_default_http_version(tls, Version::HTTP_11)
            .with_default_http_connector(exec)
            .with_http3_support(h3)
            .with_default_connection_pool()
            .build_connector(),
    );
    let probe = connector.clone();
    let preflight = Arc::new(
        service_fn(move |req: Request| {
            let probe = probe.clone();
            async move { probe.connect(req).await.map(drop).map_err(Into::into) }
        })
        .boxed(),
    );

    let web = EasyHttpWebClient::new(connector);
    let web = ResponseVersionAdapter::new(
        (
            RemoveRequestHeaderLayer::hop_by_hop(),
            RemoveResponseHeaderLayer::hop_by_hop(),
        )
            .into_layer(web),
    );

    Ok((Arc::new(web.boxed()), preflight))
}

fn error_response(status: StatusCode, message: impl Into<Body>) -> Response {
    let mut response = Response::new(message.into());
    *response.status_mut() = status;
    response
}

#[derive(Default)]
struct HttpVersionLabels(Option<Version>);

impl UsernameLabelParser for HttpVersionLabels {
    type Error = Infallible;

    fn parse_label(&mut self, label: &str) -> UsernameLabelState {
        let version = match label {
            "h1" => Version::HTTP_11,
            "h2" => Version::HTTP_2,
            "h3" => Version::HTTP_3,
            _ => return UsernameLabelState::Ignored,
        };

        if self.0.replace(version).is_some() {
            return UsernameLabelState::Abort;
        }

        UsernameLabelState::Used
    }

    fn build(self, extensions: &Extensions) -> Result<(), Self::Error> {
        if let Some(version) = self.0 {
            extensions.insert(TargetHttpVersion(version));
        }

        Ok(())
    }
}

async fn forward(web: &Web, mut req: Request, base: &Uri, version: Option<Version>) -> Response {
    req.uri_mut().maybe_set_scheme(base.scheme().cloned());
    req.uri_mut()
        .maybe_set_authority(base.authority().map(|authority| authority.into_owned()));

    req.headers_mut().remove("host");
    req.headers_mut().remove("proxy-authorization");
    let version =
        version.or_else(|| (req.version() <= Version::HTTP_11).then_some(Version::HTTP_11));
    if let Some(version) = version {
        req.extensions().insert(TargetHttpVersion(version));
    }
    match timeout(CONNECT_TIMEOUT, web.serve(req)).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => error_response(
            StatusCode::BAD_GATEWAY,
            format!("upstream HTTP connection failed: {error}"),
        ),
        Err(_) => error_response(
            StatusCode::GATEWAY_TIMEOUT,
            "upstream HTTP connection timed out",
        ),
    }
}

fn forwarding_service(
    web: Web,
    base: Uri,
    version: Option<Version>,
) -> Arc<BoxService<Request, Response, Infallible>> {
    Arc::new(
        service_fn(move |req: Request| {
            let web = web.clone();
            let base = base.clone();
            async move { Ok::<_, Infallible>(forward(&web, req, &base, version).await) }
        })
        .boxed(),
    )
}

fn mitm(
    exec: Executor,
    web: Web,
    preflight: Preflight,
) -> impl Service<Request, Output = Response, Error = Infallible> + Clone {
    let connector_exec = exec.clone();
    let connect = service_fn(move |req: Request| {
        let exec = connector_exec.clone();
        let web = web.clone();
        let preflight = preflight.clone();
        async move {
            let selected = match req.headers().typed_get::<ProxyAuthorization<Basic>>() {
                Some(auth) => {
                    let labels = Extensions::new();
                    parse_username_lossy(&labels, HttpVersionLabels::default(), auth.0.username())
                        .map_err(|error| {
                            error_response(StatusCode::BAD_REQUEST, error.to_string())
                        })?;
                    labels
                        .get_ref::<TargetHttpVersion>()
                        .map(|version| version.0)
                }
                None if req.headers().contains_key("proxy-authorization") => {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        "expected valid Basic proxy credentials",
                    ));
                }
                None => None,
            };
            let authority = req.uri().to_string();
            let authority: rama::net::address::HostWithPort =
                authority.parse().map_err(|_error| {
                    error_response(StatusCode::BAD_REQUEST, "CONNECT requires host:port")
                })?;
            let base: Uri = format!("https://{authority}/").parse().map_err(|_error| {
                error_response(StatusCode::BAD_REQUEST, "invalid CONNECT authority")
            })?;
            let probe = Request::builder()
                .uri(base.clone())
                .body(Body::empty())
                .map_err(|_error| {
                    error_response(StatusCode::BAD_REQUEST, "invalid CONNECT authority")
                })?;
            if let Some(version) = selected {
                probe.extensions().insert(TargetHttpVersion(version));
                match timeout(CONNECT_TIMEOUT, preflight.serve(probe)).await {
                    Ok(Ok(())) => (),
                    Ok(Err(error)) => {
                        return Err(error_response(
                            StatusCode::BAD_GATEWAY,
                            format!("requested {version:?} unavailable: {error}"),
                        ));
                    }
                    Err(_) => {
                        return Err(error_response(
                            StatusCode::GATEWAY_TIMEOUT,
                            format!("requested {version:?} connection timed out"),
                        ));
                    }
                }
            }
            let inner = forwarding_service(web, base, selected);

            let tls = TlsServerConfig::new()
                .with_cert_issuer(ServerCertIssuerData::default())
                .with_alpn_http_auto();
            let tunnel =
                TlsAcceptorLayer::new(tls).into_layer(HttpServer::auto(exec).service(inner));
            Ok::<UpgradeOutput<Request, Response>, Response>(
                UpgradeResponse::new(req, Response::new(Body::empty()))
                    .with_handler(move |io| async move { tunnel.serve(io).await }),
            )
        }
    });
    UpgradeLayer::new(exec, MethodMatcher::CONNECT, connect).into_layer(service_fn(
        async |_: Request| {
            Ok::<_, Infallible>(error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "use CONNECT",
            ))
        },
    ))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();

    rama::telemetry::tracing::subscriber::fmt()
        .with_env_filter(rama::telemetry::tracing::subscriber::EnvFilter::from_default_env())
        .init();

    let shutdown = rama::graceful::Shutdown::default();
    let exec = Executor::graceful(shutdown.guard());

    match args.mode {
        Mode::Mitm {
            listen,
            upstream_ca,
        } => {
            let mut tls = TlsClientConfig::default_http();
            if let Some(ca) = upstream_ca {
                tls = tls.try_with_server_trust_anchors(
                    CertificateDer::pem_file_iter(ca)?.collect::<Result<Vec<_>, _>>()?,
                )?;
            }

            let (web, preflight) = client(exec.clone(), tls)?;
            let listener = TcpListener::bind_address(listen, exec.clone()).await?;
            let listen = SocketAddress::from(listener.local_addr()?);

            rama::telemetry::tracing::info!(%listen, "HTTP version MITM proxy listening");

            let service = HttpServer::auto(exec.clone()).service(mitm(exec, web, preflight));
            shutdown.spawn_task(async move {
                listener.serve(service).await;
            });
        }
        Mode::Ingress {
            listen,
            cert,
            key,
            upstream,
        } => {
            if upstream.scheme() != Some(&rama::net::Protocol::HTTP)
                || upstream.authority().is_none()
                || upstream.path_or_root() != "/"
                || upstream.query().is_some()
            {
                return Err(
                    "upstream must be a plaintext http origin without a path or query".into(),
                );
            }

            let auth = ServerAuthData {
                cert_chain: CertificateDer::pem_file_iter(cert)?.collect::<Result<Vec<_>, _>>()?,
                private_key: PrivateKeyDer::from_pem_file(key)?,
                ocsp: None,
            };

            let (web, _) = client(exec.clone(), TlsClientConfig::default_http())?;
            let forwarder = forwarding_service(web, upstream, Some(Version::HTTP_11));

            let tls = TlsServerConfig::new()
                .with_server_auth(auth.clone())
                .with_alpn_http_auto();
            let listener = TcpListener::bind_address(listen, exec.clone()).await?;
            let listen = SocketAddress::from(listener.local_addr()?);

            let tcp = TlsAcceptorLayer::new(tls)
                .into_layer(HttpServer::auto(exec.clone()).service(forwarder.clone()));
            shutdown.spawn_task(async move {
                listener.serve(tcp).await;
            });

            let tls = TlsServerConfig::new()
                .with_server_auth(auth)
                .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
            let http = HttpServer::new_http3(exec.clone());
            let mut transport = TransportConfig::default();
            http.http3().configure_transport(&mut transport)?;
            let mut config = ServerConfig::try_from_rama_tls_with_provider(
                &tls,
                TlsOptions::default(),
                &BoringTlsProvider,
            )?;
            config.set_transport_config(Arc::new(transport));

            let endpoint = Endpoint::build(Executor::new())
                .with_server_config(config)
                .bind_address(listen)
                .await?;
            rama::telemetry::tracing::info!(%listen, "HTTP/1, HTTP/2 and HTTP/3 ingress listening");
            let service = http.service(forwarder);
            shutdown.spawn_task(endpoint.serve(exec, service));
        }
    }

    shutdown
        .shutdown_with_limit(Duration::from_secs(15))
        .await?;

    Ok(())
}
