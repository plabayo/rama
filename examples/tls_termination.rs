use rama::{
    graceful::Shutdown,
    service::ServiceBuilder,
    tcp::server::TcpListener,
    tls::dep::pki_types::{CertificateDer, PrivatePkcs8KeyDer},
    tls::dep::rcgen,
    tls::dep::rustls::{server::TlsStream, ServerConfig},
    tls::server::TlsAcceptorLayer,
};
use std::{convert::Infallible, time::Duration};
use tokio::{io::AsyncWriteExt, net::TcpStream};
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
        let tcp_service = ServiceBuilder::new()
            .layer(TlsAcceptorLayer::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![server_cert_der.clone()],
                        PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned())
                            .into(),
                    )
                    .expect("create tls server config"),
            ))
            .service_fn(|mut stream: TlsStream<TcpStream>| async move {
                let result = async {
                    let mut target_stream =
                        tokio::net::TcpStream::connect("127.0.0.1:8080").await?;
                    match tokio::io::copy_bidirectional(&mut stream, &mut target_stream).await {
                        Ok(_) => Ok(()),
                        Err(err) => {
                            if err.kind() == std::io::ErrorKind::ConnectionReset {
                                Ok(())
                            } else {
                                Err(err)
                            }
                        }
                    }
                }
                .await;
                match result {
                    Ok(_) => Ok::<_, Infallible>(()),
                    Err(err) => {
                        tracing::error!(error = %err, "proxy error");
                        Ok(())
                    }
                }
            });

        TcpListener::bind("127.0.0.1:8443")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        TcpListener::bind("127.0.0.1:8080")
            .await
            .expect("bind TCP Listener: http")
            .serve_fn_graceful(guard, |mut stream: TcpStream| async move {
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
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}
