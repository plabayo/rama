use super::TlsAcceptorData;
use crate::{
    core::ssl::{AlpnError, SslAcceptor, SslMethod, SslRef},
    keylog::try_new_key_log_file_handle,
    server::TlsStream,
    types::SecureTransport,
};
use parking_lot::Mutex;
use rama_core::{
    Service,
    conversion::RamaTryInto,
    error::{BoxError, ErrorContext, ErrorExt},
    extensions::ExtensionsMut,
    stream::Stream,
    telemetry::tracing::{debug, trace},
};
use rama_net::{
    http::RequestContext,
    tls::{ApplicationProtocol, DataEncoding, client::NegotiatedTlsParameters},
    transport::TransportContext,
};
use rama_utils::macros::define_inner_service_accessors;
use std::{io::ErrorKind, sync::Arc};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
#[derive(Debug, Clone)]
pub struct TlsAcceptorService<S> {
    data: TlsAcceptorData,
    store_client_hello: bool,
    inner: S,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(data: TlsAcceptorData, inner: S, store_client_hello: bool) -> Self {
        Self {
            data,
            store_client_hello,
            inner,
        }
    }

    define_inner_service_accessors!();
}

impl<S, IO> Service<IO> for TlsAcceptorService<S>
where
    IO: Stream + Unpin + ExtensionsMut + 'static,
    S: Service<TlsStream<IO>, Error: Into<BoxError>>,
{
    type Output = S::Output;
    type Error = BoxError;

    async fn serve(&self, stream: IO) -> Result<Self::Output, Self::Error> {
        // allow tls acceptor data to be injected,
        // e.g. useful for TLS environments where some data (such as server auth, think ACME)
        // is updated at runtime, be it infrequent
        let tls_config = stream
            .extensions()
            .get::<TlsAcceptorData>()
            .unwrap_or(&self.data)
            .config
            .clone();

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("create boring ssl acceptor")?;

        acceptor_builder.set_grease_enabled(true);
        acceptor_builder
            .set_default_verify_paths()
            .context("build boring ssl acceptor: set default verify paths")?;

        let server_domain = stream
            .extensions()
            .get::<SecureTransport>()
            .and_then(|t| t.client_hello())
            .and_then(|c| c.ext_server_name().cloned())
            .or_else(|| {
                stream
                    .extensions()
                    .get::<TransportContext>()
                    .and_then(|ctx| ctx.authority.host.as_domain().cloned())
            })
            .or_else(|| {
                stream
                    .extensions()
                    .get::<RequestContext>()
                    .and_then(|ctx| ctx.authority.host.as_domain().cloned())
            });

        // We use arc mutex instead of oneshot channel since it is possible that certificate callbacks
        // are called multiples times (fn closures type). But in testing it seems fnOnce should also
        // work (at least for how we use it). When we integrate boringssl bindings we should reconsider
        // this and see if we can expose this in a better way.
        let mut maybe_client_hello = self
            .store_client_hello
            .then_some(Arc::new(Mutex::new(None)));

        let mut acceptor_builder = tls_config
            .cert_source
            .clone()
            .issue_certs(
                acceptor_builder,
                server_domain.clone(),
                maybe_client_hello.as_ref(),
            )
            .await?;

        if let Some(min_ver) = tls_config.protocol_versions.iter().flatten().min() {
            acceptor_builder
                .set_min_proto_version(Some((*min_ver).rama_try_into().map_err(|v| {
                    BoxError::from("build boring ssl acceptor: cast min proto version")
                        .context_field("protocol_version", v)
                })?))
                .context("build boring ssl acceptor: set min proto version")?;
        }

        if let Some(max_ver) = tls_config.protocol_versions.iter().flatten().max() {
            acceptor_builder
                .set_max_proto_version(Some((*max_ver).rama_try_into().map_err(|v| {
                    BoxError::from("build boring ssl acceptor: cast max proto version")
                        .context_field("protocol_version", v)
                })?))
                .context("build boring ssl acceptor: set max proto version")?;
        }

        for ca_cert in tls_config.client_cert_chain.iter().flatten() {
            acceptor_builder
                .add_client_ca(ca_cert)
                .context("build boring ssl acceptor: set ca client cert")?;
        }

        if let Some(alpn_protocols) = tls_config.alpn_protocols.clone() {
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

        if let Some(keylog_filename) = tls_config.keylog_intent.file_path().as_deref() {
            let handle = try_new_key_log_file_handle(keylog_filename)?;
            acceptor_builder.set_keylog_callback(move |_, line| {
                let line = format!("{line}\n");
                handle.write_log_line(line);
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
                    BoxError::from("boring ssl acceptor (accept): without error info")
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
                            BoxError::from("boring ssl acceptor: cast min proto version")
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
                    let mut chain = stream.ssl().peer_cert_chain().map_or(Ok(vec![]), |chain| {
                        chain
                            .into_iter()
                            .map(|cert| {
                                cert.to_der()
                                    .context("boring ssl session: failed to convert peer certificates to der")
                            })
                            .collect::<Result<Vec<Vec<u8>>, _>>()
                    })?;

                    let certificate = certificate
                        .to_der()
                        .context("boring ssl session: failed to convert peer certificate to der")?;
                    chain.insert(0, certificate);
                    Some(DataEncoding::DerStack(chain))
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
                return Err(BoxError::from(
                    "boring ssl acceptor: failed to establish session...",
                ));
            }
        };

        let secure_transport = maybe_client_hello
            .take()
            .and_then(|maybe_client_hello| maybe_client_hello.lock().take())
            .map(SecureTransport::with_client_hello)
            .unwrap_or_default();

        let mut stream = TlsStream::new(stream);
        stream.extensions_mut().insert(secure_transport);
        stream.extensions_mut().insert(negotiated_tls_params);

        self.inner
            .serve(stream)
            .await
            .context("boring acceptor: service error")
    }
}
