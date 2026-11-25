use std::sync::Arc;

#[cfg(all(test, any(feature = "aws-lc", feature = "ring")))]
use std::time::SystemTime;

use moka::sync::Cache;
use rama_core::{
    Service,
    conversion::{RamaFrom, RamaInto},
    error::{ArcError, BoxError, BoxErrorExt as _, ErrorContext},
    extensions::{Extensions, ExtensionsRef},
    io::Io,
};
#[cfg(all(test, any(feature = "aws-lc", feature = "ring")))]
use rama_crypto::cert::ensure_credential_valid_at;
use rama_crypto::pki_types::CertificateDer;
use rama_net::{
    extensions::StreamTransformed,
    tls::{AlpnPolicy, ApplicationProtocol, ServerName},
};
use rama_tls::{
    client::{NegotiatedTlsAlgorithms, NegotiatedTlsParameters},
    server::TlsServerConfig,
};
use rama_utils::macros::{define_inner_service_accessors, generate_set_and_with};

use super::{
    TlsAcceptorData, TlsStream, acceptor_data::ServerConfig, config::RustlsTlsAcceptorConfig,
    observe::ObserveHello,
};
use crate::{
    dep::{
        rustls::{
            self, HandshakeKind,
            server::{
                Acceptor, NoServerSessionStorage, ProducesTickets, danger::ClientCertVerifier,
            },
        },
        tokio_rustls::{LazyConfigAcceptor, StartHandshake},
    },
    types::SecureTransport,
};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
///
/// Connections that do not override the TLS configuration share one native
/// configuration, built on first use; clones of this service share it.
#[derive(Debug, Clone, ExtensionsRef)]
pub struct TlsAcceptorService<S> {
    config: TlsServerConfig,
    store_client_hello: bool,
    resumption: bool,
    shared: Arc<SharedConfig>,
    inner: S,
}

/// The native configuration shared by connections, built at most once.
#[derive(Debug)]
struct SharedConfig(Cache<(), TlsAcceptorData>);

impl Default for SharedConfig {
    fn default() -> Self {
        Self(Cache::new(1))
    }
}

impl SharedConfig {
    /// Concurrent first connections wait for one build, so one ticket key is ever made.
    fn get_or_try_init(
        &self,
        build: impl FnOnce() -> Result<TlsAcceptorData, BoxError>,
    ) -> Result<TlsAcceptorData, BoxError> {
        self.0
            .try_get_with((), || build().map_err(ArcError::from))
            .map_err(|error| ArcError::clone(&error).into())
    }
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`] from a copy of `config`; later changes to it do not apply.
    pub fn new(config: TlsServerConfig, inner: S, store_client_hello: bool) -> Self {
        Self {
            config: config.detached(),
            store_client_hello,
            resumption: false,
            shared: Arc::default(),
            inner,
        }
    }

    generate_set_and_with!(
        /// Let clients resume sessions of earlier connections to this acceptor. Off by default,
        /// and then the shared configuration issues no session tickets.
        ///
        /// Tickets are encrypted under a key of this acceptor's shared configuration, so no
        /// other acceptor can resume them; clones of this service share it. Without the
        /// `aws-lc` or `ring` feature, sessions are kept in a bounded in-memory cache instead.
        /// Connections that override the TLS configuration are built per connection.
        /// Configurations with a modify hook or dynamic provider cannot resume sessions:
        /// their selected client verifier is unavailable for rechecking restored chains.
        /// Static configurations recheck the entire restored client path before serving.
        pub fn session_resumption(mut self, enabled: bool) -> Self {
            self.resumption = enabled;
            self.shared = Arc::default();
            self
        }
    );

    define_inner_service_accessors!();

    /// The acceptor data for one connection: the shared configuration unless the
    /// connection overrides it or the configuration must be built per connection.
    fn acceptor_data(
        &self,
        connection: &Extensions,
        merged: &Extensions,
    ) -> Result<TlsAcceptorData, BoxError> {
        let config = RustlsTlsAcceptorConfig::from_extensions(merged);
        // A hook may read changing state on every build and a provider resolves per ClientHello.
        if !RustlsTlsAcceptorConfig::from_extensions(connection).is_empty()
            || config.modify.is_some()
            || config.dynamic.is_some()
        {
            return TlsAcceptorData::try_from(config)
                .context("rustls acceptor: build acceptor data from config");
        }
        self.shared.get_or_try_init(|| {
            let mut data = TlsAcceptorData::try_from(config)
                .context("rustls acceptor: build shared config")?;
            if let ServerConfig::Stored(server_config) = &mut data.server_config {
                configure_resumption(Arc::make_mut(server_config), self.resumption)?;
            }
            Ok(data)
        })
    }
}

/// Refuse a restored client certificate outside its validity period at `now`.
#[cfg(all(test, any(feature = "aws-lc", feature = "ring")))]
pub(super) fn ensure_currently_valid(
    leaf: &CertificateDer<'_>,
    now: SystemTime,
) -> Result<(), BoxError> {
    ensure_credential_valid_at(leaf, now)
}

fn verify_restored_client(
    verifier: &dyn ClientCertVerifier,
    selected: &rustls::ServerConfig,
    chain: &[CertificateDer<'_>],
) -> Result<(), BoxError> {
    let Some(leaf) = chain.first() else {
        return Ok(());
    };
    let now = selected
        .time_provider
        .current_time()
        .context("rustls acceptor: time provider unavailable")?;
    verifier
        .verify_client_cert(leaf, &chain[1..], now)
        .context("verify restored client path")?;
    Ok(())
}

#[derive(Debug)]
struct NoTickets;

impl ProducesTickets for NoTickets {
    fn enabled(&self) -> bool {
        false
    }

    fn lifetime(&self) -> u32 {
        0
    }

    fn encrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn decrypt(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

/// Issue tickets only when a later connection to this acceptor can resume them.
fn configure_resumption(config: &mut rustls::ServerConfig, enabled: bool) -> Result<(), BoxError> {
    if !enabled {
        config.ticketer = Arc::new(NoTickets);
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        return Ok(());
    }
    // Stateless tickets when a ticket cipher is available; rustls's bounded cache otherwise.
    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    {
        #[cfg(feature = "aws-lc")]
        let ticketer = rustls::crypto::aws_lc_rs::Ticketer::new();
        #[cfg(not(feature = "aws-lc"))]
        let ticketer = rustls::crypto::ring::Ticketer::new();
        config.ticketer = ticketer.context("rustls acceptor: create session ticket key")?;
        config.session_storage = Arc::new(NoServerSessionStorage {});
    }
    Ok(())
}

impl<S, IO> Service<IO> for TlsAcceptorService<S>
where
    IO: Io + Unpin + ExtensionsRef + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        let handshake = async {
            let merged = stream.extensions().with_base(self.config.as_extensions());
            let tls_acceptor_data = self.acceptor_data(stream.extensions(), &merged)?;

            let require_alpn = merged.get_ref::<AlpnPolicy>() == Some(&AlpnPolicy::Require);
            let acceptor = LazyConfigAcceptor::new(Acceptor::default(), ObserveHello::new(stream));

            let start = acceptor.await?;
            let observed = self
                .store_client_hello
                .then(|| start.io.client_hello())
                .flatten();
            let received_name = observed
                .as_ref()
                .map(|hello| hello.ext_server_name().cloned())
                .or_else(|| start.io.server_name().ok());
            let received_name = received_name.unwrap_or_else(|| {
                start
                    .client_hello()
                    .server_name()
                    .and_then(ServerName::parse)
            });
            let start = StartHandshake::from_parts(start.accepted, start.io.io);

            let secure_transport = if self.store_client_hello {
                SecureTransport::with_client_hello(
                    observed.unwrap_or_else(|| start.client_hello().rama_into()),
                )
            } else {
                SecureTransport::default()
            };

            let server_config = match &tls_acceptor_data.server_config {
                ServerConfig::Stored(server_config) => server_config.clone(),
                ServerConfig::Async(dynamic) => {
                    dynamic
                        .get_config(start.client_hello(), received_name.as_ref())
                        .await?
                }
            };

            let server_config = if tls_acceptor_data.resumption_safe {
                server_config
            } else {
                let mut config = (*server_config).clone();
                configure_resumption(&mut config, false)?;
                Arc::new(config)
            };

            // The backend refuses an offer that names none of the configured protocols by
            // itself; a required protocol also rules out an offer that names none at all.
            if require_alpn {
                if server_config.alpn_protocols.is_empty() {
                    return Err(BoxError::from_static_str(
                        "rustls acceptor: ALPN is required but no protocols are configured",
                    ));
                }
                if start.client_hello().alpn().is_none() {
                    return Err(BoxError::from_static_str(
                        "rustls acceptor: client offered no application protocol",
                    ));
                }
            }

            let stream = start.into_stream(server_config.clone()).await?;
            let stream = TlsStream::new(stream);

            let (_, conn_data_ref) = stream.stream.get_ref();
            // A resumed session restores the client chain without verifying it again.
            if conn_data_ref.handshake_kind() == Some(HandshakeKind::Resumed)
                && let Some(chain) = conn_data_ref.peer_certificates()
            {
                verify_restored_client(
                    tls_acceptor_data
                        .client_verifier
                        .as_deref()
                        .context("restored client verifier unavailable")?,
                    &server_config,
                    chain,
                )?;
            }
            let negotiated_tls_params = NegotiatedTlsParameters {
                protocol_version: conn_data_ref
                    .protocol_version()
                    .context("no protocol version available")?
                    .rama_into(),
                application_layer_protocol: conn_data_ref
                    .alpn_protocol()
                    .map(ApplicationProtocol::from),
                // Currently not supported as this would mean we need to wrap rustls config
                peer_certificate_chain: None,
                server_name: received_name,
                resumed: conn_data_ref
                    .handshake_kind()
                    .map(|kind| kind == crate::dep::rustls::HandshakeKind::Resumed),
                algorithms: NegotiatedTlsAlgorithms::rama_from(&***conn_data_ref),
                server_hello: None,
            };

            stream.extensions().insert(negotiated_tls_params);
            stream.extensions().insert(secure_transport);
            stream.extensions().insert(StreamTransformed {
                by: "rama-tls-rustls::TlsAcceptor",
            });

            Ok::<_, BoxError>(stream)
        };
        #[cfg(feature = "dial9")]
        let stream =
            rama_core::telemetry::dial9::record_result("tls.rustls.server", handshake).await?;
        #[cfg(not(feature = "dial9"))]
        let stream = handshake.await?;

        // NOTE(#1014): graceful TLS `close_notify` on this stream relies on the
        // inner service driving `poll_shutdown` before `stream` is dropped here.
        // The h1 dispatcher now does so on both clean finish and error, but inner
        // HTTP/2 (GOAWAY only), panics, and raw (non-http) tunnels still don't. A
        // bounded shutdown guard wrapping `stream` here (cf. the once-gated,
        // grace-timeout idiom in `rama_net::proxy::forward`; it must spawn via the
        // `WeakScope` since `Drop` is sync) would cover those paths uniformly.
        self.inner
            .serve(stream)
            .await
            .context("rustls acceptor: service error")
    }
}

#[cfg(test)]
#[cfg(any(feature = "aws-lc", feature = "ring"))]
mod tests {
    use std::{
        convert::Infallible,
        future::ready,
        io::Cursor,
        sync::{
            Arc, Barrier, OnceLock,
            atomic::{AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use rama_core::{
        Service as _, ServiceInput,
        error::{BoxError, BoxErrorExt as _},
        extensions::ExtensionsRef as _,
        service::service_fn,
    };
    use rama_crypto::{cert::generate_server_auth, pki_types::PrivatePkcs8KeyDer};
    use rama_net::tls::ServerName;
    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    use rama_tls::server::ServerAuthData;
    use rama_tls::{
        client::parse_client_hello_handshake,
        server::{ClientVerifyMode, GeneratedServerAuthConfig, TlsClientVerify, TlsServerConfig},
    };
    use rama_utils::octets::kib;
    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair,
    };
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};
    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    use tokio::{io::duplex, time::timeout};

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    use super::{RustlsTlsAcceptorConfig, rustls::HandshakeKind};
    use super::{
        SharedConfig, TlsAcceptorData, TlsAcceptorService, TlsStream, rustls,
        rustls::{
            ClientConnection, RootCertStore, pki_types::UnixTime, server,
            time_provider::TimeProvider,
        },
    };
    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    use crate::dep::tokio_rustls::TlsConnector;
    use crate::server::{DynamicConfigProvider, RustlsDynamicConfig, RustlsServerConfigExt as _};

    #[test]
    fn concurrent_first_connections_build_the_shared_config_once() {
        crate::ensure_default_crypto_provider();
        let (chain, key) = generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let shared = Arc::new(SharedConfig::default());
        let builds = Arc::new(AtomicUsize::new(0));
        let start = Arc::new(Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (shared, builds, start, config) = (
                    shared.clone(),
                    builds.clone(),
                    start.clone(),
                    config.clone(),
                );
                thread::spawn(move || {
                    start.wait();
                    shared.get_or_try_init(|| {
                        builds.fetch_add(1, Ordering::SeqCst);
                        Ok(TlsAcceptorData::from(config))
                    })
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        assert_eq!(builds.load(Ordering::SeqCst), 1);
    }

    struct RecordName(Arc<OnceLock<Option<ServerName>>>);

    impl DynamicConfigProvider for RecordName {
        async fn get_config(
            &self,
            _: server::ClientHello<'_>,
            name: Option<&ServerName>,
        ) -> Result<Arc<rustls::ServerConfig>, BoxError> {
            self.0.set(name.cloned()).unwrap();
            Err(BoxError::from_static_str(
                "stop after certificate selection",
            ))
        }
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[tokio::test]
    async fn dynamic_selection_retains_the_native_name_when_observation_rejects_sni() {
        crate::ensure_default_crypto_provider();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let mut client =
            ClientConnection::new(Arc::new(client), "selection.test".try_into().unwrap()).unwrap();
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        for received in ["selection.test", "2001:db8::1234"] {
            let mut wire = wire.clone();
            let name = wire
                .windows(b"selection.test".len())
                .position(|name| name == b"selection.test")
                .unwrap();
            wire[name..name + received.len()].copy_from_slice(received.as_bytes());
            let mut offset = 9 + 34;
            offset += 1 + usize::from(wire[offset]);
            offset += 2 + usize::from(u16::from_be_bytes([wire[offset], wire[offset + 1]]));
            offset += 1 + usize::from(wire[offset]);
            let extensions_length = offset;
            offset += 2;
            while u16::from_be_bytes([wire[offset], wire[offset + 1]]) != 0 {
                offset += 4 + usize::from(u16::from_be_bytes([wire[offset + 2], wire[offset + 3]]));
            }
            let length = usize::from(u16::from_be_bytes([wire[offset + 2], wire[offset + 3]]));
            let end = offset + 4 + length;
            wire.splice(end..end, [1, 0, 1, 0]);
            for index in [3, extensions_length, offset + 2, offset + 4] {
                let length = u16::from_be_bytes([wire[index], wire[index + 1]]) + 4;
                wire[index..index + 2].copy_from_slice(&length.to_be_bytes());
            }
            let length = u32::from_be_bytes([0, wire[6], wire[7], wire[8]]) + 4;
            wire[6..9].copy_from_slice(&length.to_be_bytes()[1..]);
            parse_client_hello_handshake(&wire).unwrap_err();
            for store_hello in [false, true] {
                let name = Arc::new(OnceLock::new());
                let config =
                    TlsServerConfig::new().with_dynamic_config(Arc::new(RecordName(name.clone())));
                let service = TlsAcceptorService::new(
                    config,
                    service_fn(async |_| Ok::<_, Infallible>(())),
                    store_hello,
                );
                service
                    .serve(ServiceInput::new(Cursor::new(wire.clone())))
                    .await
                    .unwrap_err();
                assert_eq!(name.get(), Some(&ServerName::parse(received)));
            }
        }
    }

    #[derive(Debug)]
    struct TestTime(AtomicU64);

    impl TimeProvider for TestTime {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(
                self.0.load(Ordering::Relaxed),
            )))
        }
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[tokio::test]
    async fn resumed_client_auth_uses_the_verified_path_and_configured_clock() {
        check_client_auth_resumption(0).await;
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[tokio::test]
    async fn dynamic_client_auth_configs_do_not_resume_authenticated_sessions() {
        check_client_auth_resumption(1).await;
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[tokio::test]
    async fn modified_client_auth_configs_do_not_resume_authenticated_sessions() {
        check_client_auth_resumption(2).await;
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    #[tokio::test]
    async fn resumed_client_auth_retains_the_policy_selected_before_the_handshake() {
        check_client_auth_resumption(3).await;
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    struct FixedConfig(Arc<rustls::ServerConfig>);

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    impl DynamicConfigProvider for FixedConfig {
        async fn get_config(
            &self,
            _: server::ClientHello<'_>,
            _: Option<&ServerName>,
        ) -> Result<Arc<rustls::ServerConfig>, BoxError> {
            Ok(self.0.clone())
        }
    }

    #[cfg(any(feature = "aws-lc", feature = "ring"))]
    async fn check_client_auth_resumption(selection: u8) {
        let dynamic = selection == 1;
        let modified = selection == 2;
        let mutate = selection == 3;
        crate::ensure_default_crypto_provider();
        let mut root_params = CertificateParams::default();
        root_params.distinguished_name = DistinguishedName::new();
        root_params
            .distinguished_name
            .push(DnType::CommonName, "root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        root_params.not_after = rcgen::date_time_ymd(2025, 1, 1);
        let root_key = KeyPair::generate().unwrap();
        let root = root_params.self_signed(&root_key).unwrap();
        let issuer = Issuer::from_ca_cert_der(root.der(), root_key).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "intermediate");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate = params.signed_by(&intermediate_key, &issuer).unwrap();
        let issuer = Issuer::from_ca_cert_der(intermediate.der(), intermediate_key).unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "client");
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&leaf_key, &issuer).unwrap();
        let expiry = u64::try_from(rcgen::date_time_ymd(2030, 1, 1).unix_timestamp()).unwrap();
        let clock = Arc::new(TestTime(AtomicU64::new(expiry - 1)));
        let (server_chain, server_key) =
            generate_server_auth(GeneratedServerAuthConfig::default()).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(server_chain.last().unwrap().clone()).unwrap();
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![
                    leaf.der().clone(),
                    intermediate.der().clone(),
                    root.der().clone(),
                ],
                PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
            )
            .unwrap();
        let client = TlsConnector::from(Arc::new(client));
        let config = TlsServerConfig::new()
            .with_client_verify(ClientVerifyMode::ClientAuth(vec![root.der().clone()]))
            .with_server_auth(ServerAuthData {
                cert_chain: server_chain,
                private_key: server_key,
                ocsp: None,
            });
        let reached = Arc::new(AtomicUsize::new(0));
        let mut service = TlsAcceptorService::new(
            config.clone(),
            service_fn({
                let reached = reached.clone();
                move |mut stream: TlsStream<ServiceInput<DuplexStream>>| {
                    let reached = reached.clone();
                    async move {
                        reached.fetch_add(1, Ordering::Relaxed);
                        let byte = stream.read_u8().await?;
                        stream.write_u8(byte).await?;
                        Ok::<_, BoxError>(())
                    }
                }
            }),
            false,
        );
        let mut acceptor_data = TlsAcceptorData::try_from(
            RustlsTlsAcceptorConfig::from_extensions(config.as_extensions()),
        )
        .unwrap();
        let super::ServerConfig::Stored(stored) = &acceptor_data.server_config else {
            panic!("a static configuration is stored");
        };
        let mut native = (**stored).clone();
        native.time_provider = clock.clone();
        super::configure_resumption(&mut native, true).unwrap();
        if dynamic {
            service
                .config
                .as_extensions()
                .insert(RustlsDynamicConfig(Arc::new(FixedConfig(Arc::new(
                    native.clone(),
                )))));
        }
        if modified {
            let selected = native.clone();
            service.config = service
                .config
                .clone()
                .with_modify_rustls_config(move |_| Ok(selected.clone()));
        }
        acceptor_data.server_config = super::ServerConfig::Stored(Arc::new(native));
        service.shared.0.insert((), acceptor_data);
        for attempt in 0..3 {
            if attempt == 2 {
                clock.0.store(expiry + 1, Ordering::Relaxed);
            }
            let (client_io, server_io) = duplex(kib(16));
            let input = ServiceInput::new(server_io);
            let extensions = input.extensions().clone();
            let accepted = service.serve(input);
            tokio::pin!(accepted);
            if mutate {
                tokio::select! {
                    biased;
                    result = &mut accepted => panic!("handshake completed without a client: {result:?}"),
                    _ = ready(()) => (),
                }
                extensions.insert(TlsClientVerify(ClientVerifyMode::Disable));
            }
            let connected = async {
                let mut stream = client
                    .connect("localhost".try_into().unwrap(), client_io)
                    .await
                    .unwrap();
                assert_eq!(
                    stream.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed),
                    attempt != 0 && !dynamic && !modified
                );
                stream.write_u8(b'x').await.unwrap();
                stream.read_u8().await
            };
            let (accepted, echoed) = Box::pin(timeout(Duration::from_secs(5), async {
                tokio::join!(accepted, connected)
            }))
            .await
            .unwrap();
            assert_eq!(accepted.is_ok(), attempt < 2);
            assert_eq!(echoed.is_ok(), attempt < 2);
        }
        assert_eq!(reached.load(Ordering::Relaxed), 2);
    }
}
