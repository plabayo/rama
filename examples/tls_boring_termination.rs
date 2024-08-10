//! This example demonstrates how to create a TLS termination proxy, forwarding the
//! plain transport stream to another service.
//!
//! This example is an alternative version of the [tls_termination](./tls_termination.rs) example,
//! but using boring instead of rustls.
//!
//! # Run the example
//!
//! ```sh
//! cargo run --example tls_boring_termination
//! ```
//!
//! # Expected output
//!
//! The server will start and listen on `:63801`. You can use `curl` to interact with the service:
//!
//! ```sh
//! curl -v https://127.0.0.1:62801
//! ```
//!
//! The above will fail, due to not being haproxy encoded, but also because it is not a tls service...
//!
//! This one will work however:
//!
//! ```sh
//! curl -k -v https://127.0.0.1:63801
//! ```
//!
//! You should see a response with `HTTP/1.0 200 ok` and the body `Hello world!`.

// these dependencies are re-exported by rama for your convenience,
// as to make it easy to use them and ensure that the versions remain compatible
// (given most do not have a stable release yet)

// rama provides everything out of the box to build a TLS termination proxy
use rama::{
    error::BoxError,
    net::{
        forwarded::Forwarded,
        stream::{SocketInfo, Stream},
    },
    proxy::pp::{
        client::HaProxyLayer as HaProxyClientLayer, server::HaProxyLayer as HaProxyServerLayer,
    },
    service::{
        layer::{ConsumeErrLayer, GetExtensionLayer},
        Context, ServiceBuilder,
    },
    tcp::{
        client::service::{Forwarder, HttpConnector},
        server::TcpListener,
    },
    tls::{
        boring::{
            dep::boring::{
                asn1::Asn1Time,
                bn::{BigNum, MsbOption},
                hash::MessageDigest,
                pkey::{PKey, Private},
                rsa::Rsa,
                x509::{
                    extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier},
                    X509NameBuilder, X509,
                },
            },
            server::{ServerConfig, TlsAcceptorLayer},
        },
        ApplicationProtocol, SecureTransport,
    },
    utils::graceful::Shutdown,
};

// everything else is provided by the standard library, community crates or tokio
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
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

    // create server cert/key pair
    let (cert, key) = mk_ca_cert().expect("generate ca/key pair");

    // create tls proxy
    shutdown.spawn_task_fn(|guard| async move {
        // let tls_server_config = ServerConfig::builder()
        //     .with_no_client_auth()
        //     .with_single_cert(
        //         vec![server_cert_der],
        //         PrivatePkcs8KeyDer::from(server_key_der.secret_pkcs8_der().to_owned()).into(),
        //     )
        //     .expect("create tls server config");
        let mut tls_server_config = ServerConfig::new(key, vec![cert]);
        tls_server_config.alpn_protocols =
            vec![ApplicationProtocol::HTTP_2, ApplicationProtocol::HTTP_11];
        if let Ok(keylog_file) = std::env::var("SSLKEYLOGFILE") {
            tls_server_config.keylog_filename = Some(keylog_file);
        }

        let tcp_service = ServiceBuilder::new()
            .layer(TlsAcceptorLayer::new(Arc::new(tls_server_config)).with_store_client_hello(true))
            .layer(GetExtensionLayer::new(|st: SecureTransport| async move {
                let client_hello = st.client_hello().unwrap();
                tracing::debug!(?client_hello, "secure connection established");
            }))
            .service(
                Forwarder::new(([127, 0, 0, 1], 62801)).connector(
                    ServiceBuilder::new()
                        // ha proxy protocol used to forwarded the client original IP
                        .layer(HaProxyClientLayer::tcp())
                        .service(HttpConnector::new()),
                ),
            );

        TcpListener::bind("127.0.0.1:63801")
            .await
            .expect("bind TCP Listener: tls")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    // create http server
    shutdown.spawn_task_fn(|guard| async {
        let tcp_service = ServiceBuilder::new()
            .layer(ConsumeErrLayer::default())
            .layer(HaProxyServerLayer::new())
            .service_fn(internal_tcp_service_fn);

        TcpListener::bind("127.0.0.1:62801")
            .await
            .expect("bind TCP Listener: http")
            .serve_graceful(guard, tcp_service)
            .await;
    });

    shutdown
        .shutdown_with_limit(Duration::from_secs(30))
        .await
        .expect("graceful shutdown");
}

async fn internal_tcp_service_fn<S>(ctx: Context<()>, mut stream: S) -> Result<(), Infallible>
where
    S: Stream + Unpin,
{
    // REMARK: builds on the assumption that we are using the haproxy protocol
    let client_addr = ctx
        .get::<Forwarded>()
        .unwrap()
        .client_socket_addr()
        .unwrap();
    // REMARK: builds on the assumption that rama's TCP service sets this for you :)
    let proxy_addr = ctx.get::<SocketInfo>().unwrap().peer_addr();

    // create the minimal http response
    let payload = format!(
        "hello client {client_addr}, you were served by tls terminator proxy {proxy_addr}\r\n"
    );
    let response = format!(
        "HTTP/1.0 200 ok\r\n\
                            Connection: close\r\n\
                            Content-length: {}\r\n\
                            \r\n\
                            {}",
        payload.len(),
        payload
    );

    stream
        .write_all(response.as_bytes())
        .await
        .expect("write to stream");

    Ok(())
}

/// Make a CA certificate and private key
fn mk_ca_cert() -> Result<(X509, PKey<Private>), BoxError> {
    let rsa = Rsa::generate(4096)?;
    let privkey = PKey::from_rsa(rsa)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "BE")?;
    x509_name.append_entry_by_text("ST", "OVL")?;
    x509_name.append_entry_by_text("O", "Plabayo")?;
    x509_name.append_entry_by_text("CN", "localhost")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&privkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(90)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&privkey, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok((cert, privkey))
}
