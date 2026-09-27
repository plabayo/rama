//! Map a verified ingress client to a different upstream mTLS identity.
//!
//! Run: `cargo run -p rama-examples --bin tls_mitm_relay_client_auth --features boring`
//! The self-contained demo creates ephemeral certificates and TCP listeners,
//! exchanges a request/response through the relay, and exits. No external PKI is needed.
//! Copy this file into a project with `rama` (boring), `clap` (derive), and `tokio` (full).
//! Logs go to stderr; use `RUST_LOG=debug` for TLS and transport details.
//! Use `--tls12` for TLS 1.2, `--no-upstream-auth` for independent ingress admission,
//! or `--client missing|unmapped|untrusted` to observe rejection (a nonzero exit).
//! Test: `cargo test -p rama-examples --features boring --test integration tls_mitm_relay_client_auth -- --ignored`

use clap::{Parser, ValueEnum};
use rama::{
    Service, ServiceInput,
    crypto::{
        cert::{
            CertificateSubject, LeafCertConfig, LeafCertRequest, SelfSignedCaConfig,
            boring::{
                generate_certificate_authority_x509, issue_client_leaf_certificate,
                issue_leaf_certificate,
            },
        },
        pki_types::CertificateDer,
    },
    error::{BoxError, BoxErrorExt as _, ErrorContext as _},
    extensions::ExtensionsRef as _,
    io::BridgeIo,
    net::address::Host,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _},
    },
    tls::{
        KeyLogIntent,
        boring::{
            client::{ConnectorConfigClientAuth, TlsConnectorData, tls_connect},
            core::{
                self,
                pkey::{PKey, Private},
                ssl::{SslAcceptor, SslCredential, SslMethod, SslVerifyMode, SslVersion},
                x509::{
                    X509,
                    store::{X509Store, X509StoreBuilder},
                },
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
        client::{NegotiatedTlsParameters, ServerVerifyMode, TlsClientConfig},
    },
    utils::collections::NonEmptyVec,
};
use std::{process::ExitCode, sync::Arc, time::Duration};
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
        tracing::info!(
            server_name = ?input.server_name,
            upstream_requested = input.request.is_some(),
            "requiring ingress client authentication",
        );
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
            tracing::warn!("rejecting an authenticated but unmapped ingress identity");
            return Err(BoxError::from_static_str("unmapped ingress identity"));
        }
        tracing::info!(
            upstream_requested = self.upstream_requested,
            "matched authenticated ingress identity",
        );
        // Mapping requires our own credential/key; the client's certificate alone
        // cannot authenticate us upstream. None here means admission without egress mTLS.
        Ok(self.upstream_requested.then(|| self.mapping.egress.clone()))
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let options = Options::parse();
    tracing::subscriber::registry()
        .with(fmt::layer().with_writer(std::io::stderr).with_ansi(false))
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let result = tokio::time::timeout(Duration::from_secs(15), run(options))
        .await
        .context("example exchange timed out")
        .and_then(|result| result);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(?error, "exchange failed");
            ExitCode::FAILURE
        }
    }
}

async fn run(options: Options) -> Result<(), BoxError> {
    tracing::info!(
        client = ?options.client,
        tls_version = ?options.version(),
        upstream_auth = options.upstream_auth(),
        "creating ephemeral demo certificates",
    );
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
    tracing::info!(%relay_addr, %origin_addr, "demo listeners ready");

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
        tracing::debug!(
            tls_version = stream.ssl().version_str(),
            client_authenticated = peer.is_some(),
            "upstream accepted the selected identity",
        );
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
        let (ingress_bytes, egress_bytes) =
            tokio::io::copy_bidirectional(&mut ingress, &mut egress).await?;
        tracing::debug!(ingress_bytes, egress_bytes, "relay streams closed");
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
    tracing::info!(
        tls_version = version,
        ingress = "trusted-client",
        upstream,
        request = "ping",
        response = "pong",
        "exchange complete",
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Client {
    Trusted,
    Missing,
    Unmapped,
    Untrusted,
}

#[derive(Parser)]
#[command(about = "Map ingress mTLS to an upstream identity in a local TLS exchange")]
struct Options {
    /// Use TLS 1.2 instead of TLS 1.3 on both legs.
    #[arg(long)]
    tls12: bool,
    /// Still require ingress authentication when upstream requests none.
    #[arg(long)]
    no_upstream_auth: bool,
    /// Select the client identity; only trusted completes the exchange.
    #[arg(long, value_enum, default_value = "trusted")]
    client: Client,
}

impl Options {
    fn version(&self) -> SslVersion {
        if self.tls12 {
            SslVersion::TLS1_2
        } else {
            SslVersion::TLS1_3
        }
    }

    fn upstream_auth(&self) -> bool {
        !self.no_upstream_auth
    }
}

struct Identity {
    cert: X509,
    key: PKey<Private>,
}

impl Identity {
    fn ca() -> Result<Self, BoxError> {
        let (cert, key) = generate_certificate_authority_x509(&SelfSignedCaConfig::default())?;
        Ok(Self { cert, key })
    }

    fn server(ca: &Self) -> Result<Self, BoxError> {
        let (cert, key) = issue_leaf_certificate(&LeafCertRequest::default(), &ca.cert, &ca.key)?;
        Ok(Self { cert, key })
    }

    fn client(name: &str, ca: &Self) -> Result<Self, BoxError> {
        let request = LeafCertRequest {
            config: LeafCertConfig {
                subject: CertificateSubject {
                    common_name: Some(name.to_owned()),
                    ..Default::default()
                },
                ..Default::default()
            },
            identities: vec![],
        };
        let (cert, key) = issue_client_leaf_certificate(&request, &ca.cert, &ca.key)?;
        Ok(Self { cert, key })
    }

    fn credential(&self) -> Result<SslCredential, BoxError> {
        ConnectorConfigClientAuth {
            cert_chain: vec![self.cert.clone()],
            private_key: self.key.clone(),
        }
        .try_into()
    }

    fn trust_store(&self) -> Result<X509Store, BoxError> {
        let mut store = X509StoreBuilder::new()?;
        store.add_cert(self.cert.clone())?;
        Ok(store.build())
    }
}

struct DemoCertificates {
    ingress_ca: Identity,
    server_ca: Identity,
    egress_ca: Identity,
    origin: Identity,
    relay: Identity,
    client: Identity,
    mapped: Identity,
}

impl DemoCertificates {
    fn new() -> Result<Self, BoxError> {
        let ingress_ca = Identity::ca()?;
        let server_ca = Identity::ca()?;
        let egress_ca = Identity::ca()?;
        Ok(Self {
            origin: Identity::server(&server_ca)?,
            relay: Identity::server(&server_ca)?,
            client: Identity::client("trusted-client", &ingress_ca)?,
            mapped: Identity::client("mapped-client", &egress_ca)?,
            ingress_ca,
            server_ca,
            egress_ca,
        })
    }

    fn client_credential(&self, client: Client) -> Result<Option<SslCredential>, BoxError> {
        match client {
            Client::Trusted => self.client.credential().map(Some),
            Client::Missing => Ok(None),
            Client::Unmapped => Identity::client("unmapped-client", &self.ingress_ca)?
                .credential()
                .map(Some),
            Client::Untrusted => Identity::client("untrusted-client", &Identity::ca()?)?
                .credential()
                .map(Some),
        }
    }

    fn connector(&self, version: SslVersion) -> Result<TlsConnectorData, BoxError> {
        let config = TlsClientConfig::new()
            .with_server_name(Host::from_static("localhost"))
            .with_server_verify(ServerVerifyMode::Auto)
            .try_with_server_trust_anchors([CertificateDer::from(self.server_ca.cert.to_der()?)])?
            .with_keylog(KeyLogIntent::Disabled);
        let mut data = TlsConnectorData::try_from(&config)?;
        data.config.set_min_proto_version(Some(version))?;
        data.config.set_max_proto_version(Some(version))?;
        Ok(data)
    }

    fn origin_acceptor(&self, options: &Options) -> Result<SslAcceptor, BoxError> {
        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
        acceptor.set_min_proto_version(Some(options.version()))?;
        acceptor.set_max_proto_version(Some(options.version()))?;
        acceptor.set_certificate(&self.origin.cert)?;
        acceptor.set_private_key(&self.origin.key)?;
        acceptor.set_cert_store(self.egress_ca.trust_store()?);
        acceptor.set_verify(if options.upstream_auth() {
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
        } else {
            SslVerifyMode::NONE
        });
        Ok(acceptor.build())
    }
}
