use super::TlsAcceptorData;
use super::config::BoringTlsAcceptorConfig;
use crate::{
    TlsStream,
    core::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef},
    types::SecureTransport,
};
use parking_lot::Mutex;
use rama_core::error::BoxErrorExt as _;
use rama_core::{
    Service,
    conversion::RamaTryInto,
    error::{BoxError, ErrorContext, ErrorExt},
    extensions::ExtensionsRef,
    io::Io,
    telemetry::tracing::{debug, trace},
};
use rama_net::extensions::StreamTransformed;
use rama_tls::keylog::{KeyLogSink, open_intent_sink};
use rama_tls::{ApplicationProtocol, client::NegotiatedTlsParameters, server::TlsServerConfig};
use rama_utils::macros::define_inner_service_accessors;
use std::{io::ErrorKind, sync::Arc};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
#[derive(Debug, Clone)]
pub struct TlsAcceptorService<S> {
    config: TlsServerConfig,
    store_client_hello: bool,
    inner: S,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(config: TlsServerConfig, inner: S, store_client_hello: bool) -> Self {
        Self {
            config,
            store_client_hello,
            inner,
        }
    }

    define_inner_service_accessors!();
}

// TODO provide stand-alone handshake based on pre-built acceptor...
// we need this acceptor based on server hello if possible

impl<S, IO> Service<IO> for TlsAcceptorService<S>
where
    IO: Io + Unpin + ExtensionsRef + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        let merged = stream.extensions().with_base(self.config.as_extensions());
        let tls_config =
            TlsAcceptorData::try_from(BoringTlsAcceptorConfig::from_extensions(&merged))
                .context("boring acceptor: build acceptor data from config")?
                .config;

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("create boring ssl acceptor")?;

        acceptor_builder.set_grease_enabled(true);
        // Deliberately NOT calling `set_default_verify_paths()`: this acceptor
        // never enables client-certificate verification (`SSL_VERIFY_PEER` is
        // never set; `add_client_ca` below only advertises CA names and is inert
        // without it), so the OS trust store it would parse is never consulted.
        // Loading it parsed the whole bundle per handshake and kept it resident
        // for the connection's lifetime. If client-cert auth is wired up later,
        // install an explicit client-CA store + verify mode instead of the OS
        // bundle (which is the wrong trust anchor set for client auth anyway).

        let server_domain = stream
            .extensions()
            .get_ref::<SecureTransport>()
            .and_then(|t| t.client_hello())
            .and_then(|c| c.ext_server_name().cloned());

        // We use arc mutex instead of oneshot channel since it is possible that certificate callbacks
        // are called multiples times (fn closures type). But in testing it seems fnOnce should also
        // work (at least for how we use it). When we integrate boringssl bindings we should reconsider
        // this and see if we can expose this in a better way.
        let mut maybe_client_hello = self
            .store_client_hello
            .then_some(Arc::new(Mutex::new(None)));

        let mut acceptor_builder = tls_config
            .cert_source
            .issue_certs(
                acceptor_builder,
                server_domain.clone(),
                maybe_client_hello.as_ref(),
            )
            .await?;

        if let Some(min_ver) = tls_config.protocol_versions.iter().flatten().min() {
            acceptor_builder
                .set_min_proto_version(Some((*min_ver).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("build boring ssl acceptor: cast min proto version")
                        .context_field("protocol_version", v)
                })?))
                .context("build boring ssl acceptor: set min proto version")?;
        }

        if let Some(max_ver) = tls_config.protocol_versions.iter().flatten().max() {
            acceptor_builder
                .set_max_proto_version(Some((*max_ver).rama_try_into().map_err(|v| {
                    BoxError::from_static_str("build boring ssl acceptor: cast max proto version")
                        .context_field("protocol_version", v)
                })?))
                .context("build boring ssl acceptor: set max proto version")?;
        }

        for ca_cert in tls_config.client_cert_chain.iter().flatten() {
            acceptor_builder
                .add_client_ca(ca_cert)
                .context("build boring ssl acceptor: set ca client cert")?;
        }

        if let Some(alpn_protocols) = tls_config.alpn_protocols {
            trace!("tls boring server service: set alpn protos callback");
            acceptor_builder.set_alpn_select_callback(
                move |_: &mut SslRef, client_alpns: &[u8]| {
                    let mut reader = std::io::Cursor::new(client_alpns);
                    loop {
                        let n = reader.position() as usize;
                        match ApplicationProtocol::decode_wire_format(&mut reader) {
                            Ok(proto) => {
                                if alpn_protocols.contains(&proto) {
                                    let m = reader.position() as usize;
                                    return Ok(&client_alpns[n+1..m]);
                                }
                            }
                            Err(error) => {
                                return Err(if error.kind() == ErrorKind::UnexpectedEof {
                                    trace!(
                                        "tls boring server service: alpn protos callback: no compatible ALPN found: {error:?}",
                                    );
                                    AlpnError::NOACK
                                } else {
                                    debug!(
                                        "tls boring server service: alpn protos callback: client ALPN decode error: {error:?}",
                                    );
                                    AlpnError::ALERT_FATAL
                                })
                            }
                        }
                    }
                },
            );
        }

        if let Some(sink) = open_intent_sink(&tls_config.keylog_intent)? {
            acceptor_builder.set_keylog_callback(move |_, line| {
                let mut buf = String::with_capacity(line.len() + 1);
                buf.push_str(line);
                buf.push('\n');
                sink.write_line(&buf);
            });
        }

        let acceptor = acceptor_builder.build();

        let stream = rama_boring_tokio::accept(&acceptor, stream)
            .await
            .map_err(|err| {
                let maybe_ssl_code = err.code();
                if let Some(io_err) = err.as_io_error() {
                    BoxError::from(format!(
                        "boring ssl acceptor (accept): with io error: {io_err}"
                    ))
                    .context_debug_field("domain", server_domain)
                    .context_debug_field("code", maybe_ssl_code)
                } else if let Some(err) = err.as_ssl_error_stack() {
                    err.context("boring ssl acceptor (accept): with ssl-error info")
                        .context_debug_field("domain", server_domain)
                        .context_debug_field("code", maybe_ssl_code)
                } else {
                    BoxError::from_static_str("boring ssl acceptor (accept): without error info")
                        .context_debug_field("domain", server_domain)
                        .context_debug_field("code", maybe_ssl_code)
                }
            })?;

        let negotiated_tls_params = match stream.ssl().session() {
            Some(ssl_session) => {
                let protocol_version =
                    ssl_session
                        .protocol_version()
                        .rama_try_into()
                        .map_err(|v| {
                            BoxError::from_static_str("boring ssl acceptor: cast min proto version")
                                .context_field("protocol_version", v)
                        })?;
                let application_layer_protocol = stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(ApplicationProtocol::from);

                let client_certificate_chain = if let Some(certificate) = tls_config
                    .store_client_certificate_chain
                    .then(|| stream.ssl().peer_certificate())
                    .flatten()
                {
                    // peer_cert_chain doesn't contain the leaf certificate in a server ctx
                    let mut chain = stream
                        .ssl()
                        .peer_cert_chain()
                        .map_or(Ok(vec![]), RamaTryInto::rama_try_into)?;

                    let certificate = certificate
                        .as_ref()
                        .rama_try_into()
                        .context("boring ssl session: failed to convert peer certificate to der")?;
                    chain.insert(0, certificate);
                    Some(chain)
                } else {
                    None
                };

                NegotiatedTlsParameters {
                    protocol_version,
                    application_layer_protocol,
                    peer_certificate_chain: client_certificate_chain,
                }
            }
            None => {
                return Err(BoxError::from_static_str(
                    "boring ssl acceptor: failed to establish session",
                ));
            }
        };

        let secure_transport = maybe_client_hello
            .take()
            .and_then(|maybe_client_hello| maybe_client_hello.lock().take())
            .map(SecureTransport::with_client_hello)
            .unwrap_or_default();

        let stream = TlsStream::new(stream);
        stream.extensions().insert(secure_transport);
        stream.extensions().insert(negotiated_tls_params);
        stream.extensions().insert(StreamTransformed {
            by: "rama-tls-boring::TlsAcceptor",
        });

        // NOTE(#1014): graceful TLS `close_notify` on this stream relies on the
        // inner service driving `poll_shutdown` before `stream` is dropped here.
        // The h1 dispatcher now does so on both clean finish and error, but inner
        // HTTP/2 (GOAWAY only), panics, and raw (non-http) tunnels still don't. A
        // bounded shutdown guard wrapping `stream` here (cf. the once-gated,
        // grace-timeout idiom in `rama_net::proxy::forward`; it must spawn via the
        // `Executor` since `Drop` is sync) would cover those paths uniformly.
        self.inner
            .serve(stream)
            .await
            .context("boring acceptor: service error")
    }
}
