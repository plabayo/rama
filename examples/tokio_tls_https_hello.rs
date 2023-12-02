use std::{convert::Infallible, time::Duration};

use rama::{
    http::server as http,
    http::StatusCode,
    rt::{graceful::Shutdown, io::AsyncWriteExt, tls::rustls::server::TlsServerConfig},
    service::Service,
    tcp::server::TcpListener,
    tls::server::rustls::RustlsAcceptorLayer,
};

use pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tracing::metadata::LevelFilter;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[rama::rt::main]
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
    let mut ca_params = rcgen::CertificateParams::new(Vec::new());
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
    ca_params.alg = alg;
    let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

    // Create a server end entity cert issued by the CA.
    let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_ee_params.alg = alg;
    let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
    let server_cert_der =
        CertificateDer::from(server_cert.serialize_der_with_signer(&ca_cert).unwrap());
    let server_key_der = PrivatePkcs8KeyDer::from(server_cert.serialize_private_key_der());

    // create tls proxy
    shutdown.spawn_task_fn(|guard| async move {
        let web_server = http::HttpServer::http1()
            .compression()
            .trace()
            .timeout(Duration::from_secs(10))
            .service::<WebServer, _, _, _>(WebServer::new());

        TcpListener::bind("127.0.0.1:8443")
            .await
            .expect("bind TCP Listener: tls")
            .spawn()
            .layer(RustlsAcceptorLayer::new(
                TlsServerConfig::builder()
                    .with_safe_defaults()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![server_cert_der.clone()],
                        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned())
                            .into(),
                    )
                    .expect("create tls server config"),
            ))
            .serve_graceful(guard, web_server)
            .await
            .expect("serve incoming https connections: tls");
    });

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        TcpListener::bind("127.0.0.1:8080")
            .await
            .expect("bind TCP Listener: http")
            .spawn()
            .serve_fn_graceful(guard, |mut stream| async move {
                stream
                    .write_all(
                        &b"HTTP/1.0 200 ok\r\n\
                    Connection: close\r\n\
                    Content-length: 12\r\n\
                    \r\n\
                    Hello world!"[..],
                    )
                    .await
                    .expect("write to stream");
                Ok::<_, std::convert::Infallible>(())
            })
            .await
            .expect("serve incoming TCP connections: http");
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

#[derive(Debug, Clone)]
struct WebServer {
    start_time: std::time::Instant,
}

impl WebServer {
    fn new() -> Self {
        Self {
            start_time: std::time::Instant::now(),
        }
    }

    async fn render_page_fast(&self) -> Response {
        self.render_page(StatusCode::OK, "This was a fast response.")
    }

    async fn render_page_slow(&self) -> Response {
        rama::rt::time::sleep(std::time::Duration::from_secs(5)).await;
        self.render_page(StatusCode::OK, "This was a slow response.")
    }

    async fn render_page_not_found(&self, path: &str) -> Response {
        self.render_page(
            StatusCode::NOT_FOUND,
            format!("The path {} was not found.", path).as_str(),
        )
    }

    fn render_page(&self, status: StatusCode, msg: &str) -> Response {
        hyper::Response::builder()
            .header(hyper::header::CONTENT_TYPE, "text/html")
            .status(status)
            .body(format!(
                r##"<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rama Https Server Example</title>
    </head>
    <body>
        <h1>Hello!</h1>
        <p>{msg}<p>
        <p>Server has been running {} seconds.</p>
    </body>
</html>
"##,
                self.start_time.elapsed().as_secs()
            ))
            .unwrap()
    }
}

type Request = http::Request;
type Response = http::Response<String>;

impl Service<Request> for WebServer {
    type Response = Response;
    type Error = Infallible;

    async fn call(&self, request: Request) -> Result<Self::Response, Self::Error> {
        Ok(match request.uri().path() {
            "/fast" => self.render_page_fast().await,
            "/slow" => self.render_page_slow().await,
            path => self.render_page_not_found(path).await,
        })
    }
}
