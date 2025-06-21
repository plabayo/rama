use super::TlsAcceptorData;
use crate::{
    RamaTryInto,
    core::{
        ssl::{AlpnError, SslAcceptor, SslMethod, SslRef},
        tokio::SslStream,
    },
    keylog::new_key_log_file_handle,
    types::SecureTransport,
};
use parking_lot::Mutex;
use rama_core::telemetry::tracing::{debug, trace};
use rama_core::{
    Context, Service,
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
};
use rama_net::{
    address::Host,
    http::RequestContext,
    stream::Stream,
    tls::{ApplicationProtocol, DataEncoding, client::NegotiatedTlsParameters},
    transport::TransportContext,
};
use rama_utils::macros::define_inner_service_accessors;
use std::{io::ErrorKind, sync::Arc};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
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

impl<S: std::fmt::Debug> std::fmt::Debug for TlsAcceptorService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorService")
            .field("data", &self.data)
            .field("store_client_hello", &self.store_client_hello)
            .field("inner", &self.inner)
            .finish()
    }
}

impl<S> Clone for TlsAcceptorService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
            store_client_hello: self.store_client_hello,
            inner: self.inner.clone(),
        }
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, SslStream<IO>, Error: Into<BoxError>>,
{
    type Response = S::Response;
    type Error = BoxError;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        // allow tls acceptor data to be injected,
        // e.g. useful for TLS environments where some data (such as server auth, think ACME)
        // is updated at runtime, be it infrequent
        let tls_config = &ctx.get::<TlsAcceptorData>().unwrap_or(&self.data).config;

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("create boring ssl acceptor")?;

        acceptor_builder.set_grease_enabled(true);
        acceptor_builder
            .set_default_verify_paths()
            .context("build boring ssl acceptor: set default verify paths")?;

        let server_domain = ctx
            .get::<SecureTransport>()
            .and_then(|t| t.client_hello())
            .and_then(|c| c.ext_server_name().map(|domain| Host::Name(domain.clone())))
            .or_else(|| {
                ctx.get::<TransportContext>()
                    .map(|ctx| ctx.authority.host().clone())
            })
            .or_else(|| {
                ctx.get::<RequestContext>()
                    .map(|ctx| ctx.authority.host().clone())
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
            .issue_certs(acceptor_builder, server_domain, &maybe_client_hello)
            .await?;

        if let Some(min_ver) = tls_config.protocol_versions.iter().flatten().min() {
            acceptor_builder
                .set_min_proto_version(Some((*min_ver).rama_try_into().map_err(|v| {
                    OpaqueError::from_display(format!("protocol version {v}"))
                        .context("build boring ssl acceptor: min proto version")
                })?))
                .context("build boring ssl acceptor: set min proto version")?;
        }

        if let Some(max_ver) = tls_config.protocol_versions.iter().flatten().max() {
            acceptor_builder
                .set_max_proto_version(Some((*max_ver).rama_try_into().map_err(|v| {
                    OpaqueError::from_display(format!("protocol version {v}"))
                        .context("build boring ssl acceptor: max proto version")
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

        if let Some(keylog_filename) = tls_config.keylog_intent.file_path() {
            let handle = new_key_log_file_handle(keylog_filename)?;
            acceptor_builder.set_keylog_callback(move |_, line| {
                let line = format!("{}\n", line);
                handle.write_log_line(line);
            });
        }

        let acceptor = acceptor_builder.build();

        let stream = rama_boring_tokio::accept(&acceptor, stream)
            .await
            .map_err(|err| match err.as_io_error() {
                Some(err) => OpaqueError::from_display(err.to_string())
                    .context("boring ssl acceptor: accept"),
                None => OpaqueError::from_display(format!(
                    "boring ssl acceptor: accept ({:?})",
                    err.code()
                )),
            })?;

        match stream.ssl().session() {
            Some(ssl_session) => {
                let protocol_version =
                    ssl_session
                        .protocol_version()
                        .rama_try_into()
                        .map_err(|v| {
                            OpaqueError::from_display(format!("protocol version {v}"))
                                .context("boring ssl acceptor: min proto version")
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

                ctx.insert(NegotiatedTlsParameters {
                    protocol_version,
                    application_layer_protocol,
                    peer_certificate_chain: client_certificate_chain,
                });
            }
            None => {
                return Err(OpaqueError::from_display(
                    "boring ssl acceptor: failed to establish session...",
                )
                .into_boxed());
            }
        }

        let secure_transport = maybe_client_hello
            .take()
            .and_then(|maybe_client_hello| maybe_client_hello.lock().take())
            .map(SecureTransport::with_client_hello)
            .unwrap_or_default();
        ctx.insert(secure_transport);

        self.inner.serve(ctx, stream).await.map_err(|err| {
            OpaqueError::from_boxed(err.into())
                .context("boring acceptor: service error")
                .into_boxed()
        })
    }
}
