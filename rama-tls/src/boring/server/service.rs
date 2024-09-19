use super::TlsAcceptorData;
use crate::{
    boring::dep::{
        boring::ssl::{SslAcceptor, SslMethod},
        tokio_boring::SslStream,
    },
    types::client::ClientHello,
    types::SecureTransport,
};
use parking_lot::Mutex;
use rama_core::{
    error::{BoxError, ErrorContext, ErrorExt, OpaqueError},
    Context, Service,
};
use rama_net::{
    stream::Stream,
    tls::{client::NegotiatedTlsParameters, ApplicationProtocol},
};
use rama_utils::macros::define_inner_service_accessors;
use std::sync::Arc;
use tracing::trace;

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

        for (i, ca_cert) in tls_config.cert_chain.iter().enumerate() {
            if i == 0 {
                acceptor_builder
                    .set_certificate(ca_cert.as_ref())
                    .context("build boring ssl acceptor: set Leaf CA certificate (x509)")?;
            } else {
                acceptor_builder
                    .add_extra_chain_cert(ca_cert.clone())
                    .context("build boring ssl acceptor: add extra chain certificate (x509)")?;
            }
        }
        acceptor_builder
            .set_private_key(tls_config.private_key.as_ref())
            .context("build boring ssl acceptor: set private key")?;
        acceptor_builder
            .check_private_key()
            .context("build boring ssl acceptor: check private key")?;

        if let Some(min_ver) = tls_config.protocol_versions.iter().flatten().min() {
            acceptor_builder
                .set_min_proto_version(Some((*min_ver).try_into().map_err(|v| {
                    OpaqueError::from_display(format!("protocol version {v}"))
                        .context("build boring ssl acceptor: min proto version")
                })?))
                .context("build boring ssl acceptor: set min proto version")?;
        }

        if let Some(max_ver) = tls_config.protocol_versions.iter().flatten().max() {
            acceptor_builder
                .set_max_proto_version(Some((*max_ver).try_into().map_err(|v| {
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

        let mut maybe_client_hello = if self.store_client_hello {
            let maybe_client_hello = Arc::new(Mutex::new(None));
            let cb_maybe_client_hello = maybe_client_hello.clone();
            acceptor_builder.set_select_certificate_callback(move |boring_client_hello| {
                let maybe_client_hello = match ClientHello::try_from(boring_client_hello) {
                    Ok(ch) => Some(ch),
                    Err(err) => {
                        tracing::warn!(err = %err, "failed to extract boringssl client hello");
                        None
                    }
                };
                *cb_maybe_client_hello.lock() = maybe_client_hello;
                Ok(())
            });
            Some(maybe_client_hello)
        } else {
            None
        };

        if !tls_config
            .alpn_protocols
            .as_ref()
            .map(|v| !v.is_empty())
            .unwrap_or_default()
        {
            let mut buf = vec![];
            for alpn in tls_config.alpn_protocols.iter().flatten() {
                alpn.encode_wire_format(&mut buf)
                    .context("build boring ssl acceptor: encode alpn")?;
            }
            acceptor_builder
                .set_alpn_protos(&buf[..])
                .context("build boring ssl acceptor: set alpn")?;
        }

        if let Some(keylog_filename) = &tls_config.keylog_filename {
            trace!(path = ?keylog_filename, "boring acceptor service: open keylog file for debug purposes");
            // open file in append mode and write keylog to it with callback
            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(keylog_filename)
                .context("build boring ssl acceptor: set keylog: open file")?;
            acceptor_builder.set_keylog_callback(move |_, line| {
                use std::io::Write;
                let line = format!("{}\n", line);
                let mut file = &file;
                let _ = file.write_all(line.as_bytes());
            });
        }

        let acceptor = acceptor_builder.build();

        let stream = tokio_boring::accept(&acceptor, stream)
            .await
            .map_err(|err| match err.as_io_error() {
                Some(err) => OpaqueError::from_display(err.to_string())
                    .context("boring ssl acceptor: accept"),
                None => OpaqueError::from_display("boring ssl acceptor: accept"),
            })?;

        match stream.ssl().session() {
            Some(ssl_session) => {
                let protocol_version = ssl_session.protocol_version().try_into().map_err(|v| {
                    OpaqueError::from_display(format!("protocol version {v}"))
                        .context("boring ssl acceptor: min proto version")
                })?;
                let application_layer_protocol = stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(ApplicationProtocol::from);
                ctx.insert(NegotiatedTlsParameters {
                    protocol_version,
                    application_layer_protocol,
                });
            }
            None => {
                return Err(OpaqueError::from_display(
                    "boring ssl acceptor: failed to establish session...",
                )
                .into_boxed())
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
                .context("rustls acceptor: service error")
                .into_boxed()
        })
    }
}
