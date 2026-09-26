//! Map a verified ingress client to a different upstream mTLS identity.
//!
//! Run: `cargo run -p rama-examples --bin tls_mitm_relay_client_auth --features boring`
//! The self-contained demo creates ephemeral certificates and TCP listeners,
//! exchanges a request/response through the relay, and exits. No external PKI is needed.
//! Use `--tls12` for TLS 1.2, `--no-upstream-auth` for independent ingress admission,
//! or `--client missing|unmapped|untrusted` to observe rejection (a nonzero exit).
//! Test: `cargo test -p rama-examples --features boring --test integration tls_mitm_relay_client_auth -- --ignored`

#![expect(clippy::print_stdout, reason = "example reports its verified exchange")]

#[path = "tls_mitm_relay_client_auth/support.rs"]
mod support;

use clap::Parser as _;
use rama::{
    Service, ServiceInput,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::ExtensionsRef as _,
    io::BridgeIo,
    net::address::Host,
    tls::{
        KeyLogIntent,
        boring::{
            client::tls_connect,
            core::{
                self,
                ssl::{SslCredential, SslVersion},
                x509::store::X509Store,
            },
            proxy::{
                TlsMitmRelay,
                cert_issuer::StaticBoringMitmCertIssuer,
                client_auth::{
                    TlsMitmClientAuthInput, TlsMitmClientAuthPlan, TlsMitmClientAuthPolicy,
                    TlsMitmClientIdentity,
                },
            },
        },
        client::NegotiatedTlsParameters,
    },
    utils::collections::NonEmptyVec,
};
use std::{sync::Arc, time::Duration};
use support::{DemoCertificates, Options};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream},
};

/// Stage X scopes credentials to a destination and requests native ingress auth.
#[derive(Clone)]
struct MappingPolicy {
    ingress_trust: X509Store,
    mapping: ClientMapping,
}

impl Service<TlsMitmClientAuthInput> for MappingPolicy {
    type Output = TlsMitmClientAuthPlan;
    type Error = BoxError;

    async fn serve(&self, input: TlsMitmClientAuthInput) -> Result<Self::Output, Self::Error> {
        if input.server_name.as_ref() != Some(&Host::from_static("localhost")) {
            return Err(BoxError::from_static_str(
                "destination outside mapping policy",
            ));
        }
        let resolver = ResolveClient {
            mapping: self.mapping.clone(),
            upstream_requested: input.request.is_some(),
        };
        // Require ingress authentication even when upstream requests no certificate.
        Ok(TlsMitmClientAuthPlan::new(resolver).with_ingress_trust(self.ingress_trust.clone()))
    }
}

/// Replace this exact-leaf match with an application-owned storage service.
#[derive(Clone)]
struct ClientMapping {
    ingress_leaf: Arc<[u8]>,
    egress: SslCredential,
}

/// Stage Y sees an identity only after TLS verification and proof of possession.
#[derive(Clone)]
struct ResolveClient {
    mapping: ClientMapping,
    upstream_requested: bool,
}

impl Service<TlsMitmClientIdentity> for ResolveClient {
    type Output = Option<SslCredential>;
    type Error = BoxError;

    async fn serve(&self, identity: TlsMitmClientIdentity) -> Result<Self::Output, Self::Error> {
        let leaf = identity
            .leaf()
            .ok_or_else(|| BoxError::from_static_str("missing ingress identity"))?;
        if leaf.to_der()?.as_slice() != self.mapping.ingress_leaf.as_ref() {
            return Err(BoxError::from_static_str("unmapped ingress identity"));
        }
        // Mapping requires our own credential/key; the client's certificate alone
        // cannot authenticate us upstream. None here means admission without egress mTLS.
        Ok(self.upstream_requested.then(|| self.mapping.egress.clone()))
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let options = Options::parse();
    tokio::time::timeout(Duration::from_secs(15), run(options))
        .await
        .context("example exchange timed out")??;
    Ok(())
}

async fn run(options: Options) -> Result<(), BoxError> {
    let certs = DemoCertificates::new()?;
    let policy = MappingPolicy {
        ingress_trust: certs.ingress_ca.trust_store()?,
        mapping: ClientMapping {
            ingress_leaf: certs.client.cert.to_der()?.into(),
            egress: certs.mapped.credential()?,
        },
    };
    let relay = TlsMitmRelay::new(StaticBoringMitmCertIssuer::new(
        NonEmptyVec::new(certs.relay.cert.clone()),
        certs.relay.key.clone(),
    ))
    .with_keylog_intent(KeyLogIntent::Disabled)
    .with_client_auth(TlsMitmClientAuthPolicy::new(policy));
    // Both connectors verify localhost against the demo server CA.
    let egress_data = certs.connector(options.version())?;
    let mut client_data = certs.connector(options.version())?;
    if let Some(credential) = certs.client_credential(options.client)? {
        client_data.config.add_credential(&credential)?;
    }
    let origin_acceptor = certs.origin_acceptor(&options)?;
    let origin_listener = TcpListener::bind("127.0.0.1:0").await?;
    let relay_listener = TcpListener::bind("127.0.0.1:0").await?;
    let origin_addr = origin_listener.local_addr()?;
    let relay_addr = relay_listener.local_addr()?;

    let origin = async {
        let (socket, _) = origin_listener.accept().await?;
        let mut stream = core::tokio::accept(&origin_acceptor, socket)
            .await
            .context("upstream TLS handshake")?;
        if stream.ssl().version() != Some(options.version()) {
            return Err(BoxError::from_static_str(
                "upstream negotiated the wrong TLS version",
            ));
        }
        let peer = stream
            .ssl()
            .peer_certificate()
            .map(|c| c.to_der())
            .transpose()?;
        let expected = options
            .upstream_auth()
            .then(|| certs.mapped.cert.to_der())
            .transpose()?;
        if peer != expected {
            return Err(BoxError::from_static_str(
                "upstream received the wrong identity",
            ));
        }
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        if request != *b"ping" {
            return Err(BoxError::from_static_str(
                "upstream received the wrong request",
            ));
        }
        stream.write_all(b"pong").await?;
        stream.shutdown().await?;
        Ok::<_, BoxError>(())
    };
    let bridge = async {
        let (ingress, _) = relay_listener.accept().await?;
        let egress = TcpStream::connect(origin_addr).await?;
        let input = BridgeIo(ServiceInput::new(ingress), ServiceInput::new(egress));
        let BridgeIo(mut ingress, mut egress) = relay.handshake(input, Some(egress_data)).await?;
        let parameters = ingress
            .extensions()
            .get_ref::<NegotiatedTlsParameters>()
            .ok_or_else(|| BoxError::from_static_str("missing ingress TLS metadata"))?;
        let leaf = parameters
            .peer_certificate_chain
            .as_ref()
            .and_then(|c| c.first());
        if leaf.map(AsRef::as_ref) != Some(certs.client.cert.to_der()?.as_slice()) {
            return Err(BoxError::from_static_str(
                "relay reported the wrong ingress identity",
            ));
        }
        tokio::io::copy_bidirectional(&mut ingress, &mut egress).await?;
        Ok::<_, BoxError>(())
    };
    let client = async {
        let socket = TcpStream::connect(relay_addr).await?;
        let mut stream = tls_connect(ServiceInput::new(socket), Some(client_data)).await?;
        if stream.ssl_ref().version() != Some(options.version()) {
            return Err(BoxError::from_static_str(
                "client negotiated the wrong TLS version",
            ));
        }
        stream.write_all(b"ping").await?;
        let mut response = [0; 4];
        stream.read_exact(&mut response).await?;
        if response != *b"pong" {
            return Err(BoxError::from_static_str(
                "client received the wrong response",
            ));
        }
        stream.shutdown().await?;
        Ok::<_, BoxError>(())
    };
    // Join owned futures: every leg terminates, and cancellation drops all sockets.
    let (origin, bridge, client) = tokio::join!(origin, bridge, client);
    bridge.context("relay")?;
    origin.context("origin")?;
    client.context("client")?;
    let version = if options.version() == SslVersion::TLS1_2 {
        "TLS1.2"
    } else {
        "TLS1.3"
    };
    let upstream = if options.upstream_auth() {
        "mapped"
    } else {
        "none"
    };
    println!("{version}: ingress=trusted-client upstream={upstream} request=ping response=pong");
    Ok(())
}
