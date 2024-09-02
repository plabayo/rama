use super::ServerConfig;
use crate::utils::macros::define_inner_service_accessors;
use crate::{
    error::{ErrorContext, ErrorExt, OpaqueError},
    stream::Stream,
    tls::{
        backend::boring::dep::{
            boring::ssl::{SslAcceptor, SslMethod},
            tokio_boring::SslStream,
        },
        client::ClientHello,
        SecureTransport,
    },
    Context, Service,
};
use parking_lot::Mutex;
use std::{fmt, sync::Arc};

/// A [`Service`] which accepts TLS connections and delegates the underlying transport
/// stream to the given service.
pub struct TlsAcceptorService<S> {
    config: Arc<ServerConfig>,
    store_client_hello: bool,
    inner: S,
}

impl<S> TlsAcceptorService<S> {
    /// Creates a new [`TlsAcceptorService`].
    pub const fn new(config: Arc<ServerConfig>, inner: S, store_client_hello: bool) -> Self {
        Self {
            config,
            store_client_hello,
            inner,
        }
    }

    define_inner_service_accessors!();
}

impl<S: std::fmt::Debug> std::fmt::Debug for TlsAcceptorService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsAcceptorService")
            .field("config", &self.config)
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
            config: self.config.clone(),
            store_client_hello: self.store_client_hello,
            inner: self.inner.clone(),
        }
    }
}

impl<T, S, IO> Service<T, IO> for TlsAcceptorService<S>
where
    T: Send + Sync + 'static,
    IO: Stream + Unpin + 'static,
    S: Service<T, SslStream<IO>>,
{
    type Response = S::Response;
    type Error = TlsAcceptorError<S::Error>;

    async fn serve(&self, mut ctx: Context<T>, stream: IO) -> Result<Self::Response, Self::Error> {
        // let acceptor = TlsAcceptor::from(self.config.clone());

        let mut acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())
            .context("create boring ssl acceptor")
            .map_err(TlsAcceptorError::Accept)?;

        acceptor_builder.set_grease_enabled(true);
        acceptor_builder
            .set_default_verify_paths()
            .context("build boring ssl acceptor: set default verify paths")
            .map_err(TlsAcceptorError::Accept)?;

        for (i, ca_cert) in self.config.ca_cert_chain.iter().enumerate() {
            if i == 0 {
                acceptor_builder
                    .set_certificate(ca_cert.as_ref())
                    .context("build boring ssl acceptor: set Leaf CA certificate (x509)")
                    .map_err(TlsAcceptorError::Accept)?;
            } else {
                acceptor_builder
                    .add_extra_chain_cert(ca_cert.clone())
                    .context("build boring ssl acceptor: add extra chain certificate (x509)")
                    .map_err(TlsAcceptorError::Accept)?;
            }
        }
        acceptor_builder
            .set_private_key(self.config.private_key.as_ref())
            .context("build boring ssl acceptor: set private key")
            .map_err(TlsAcceptorError::Accept)?;
        acceptor_builder
            .check_private_key()
            .context("build boring ssl acceptor: check private key")
            .map_err(TlsAcceptorError::Accept)?;

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

        if !self.config.alpn_protocols.is_empty() {
            let mut buf = vec![];
            for alpn in &self.config.alpn_protocols {
                alpn.encode_wire_format(&mut buf)
                    .context("build boring ssl acceptor: encode alpn")
                    .map_err(TlsAcceptorError::Accept)?;
            }
            acceptor_builder
                .set_alpn_protos(&buf[..])
                .context("build boring ssl acceptor: set alpn")
                .map_err(TlsAcceptorError::Accept)?;
        }

        if let Some(keylog_filename) = &self.config.keylog_filename {
            // open file in append mode and write keylog to it with callback
            let file = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(keylog_filename)
                .context("build boring ssl acceptor: set keylog: open file")
                .map_err(TlsAcceptorError::Accept)?;
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
            })
            .map_err(TlsAcceptorError::Accept)?;

        let secure_transport = maybe_client_hello
            .take()
            .and_then(|maybe_client_hello| maybe_client_hello.lock().take())
            .map(SecureTransport::with_client_hello)
            .unwrap_or_default();
        ctx.insert(secure_transport);

        self.inner
            .serve(ctx, stream)
            .await
            .map_err(TlsAcceptorError::Service)
    }
}

/// Errors that can happen when using [`TlsAcceptorService`].
pub enum TlsAcceptorError<E> {
    /// An error occurred while accepting a TLS connection.
    Accept(OpaqueError),
    /// An error occurred while serving the underlying transport stream
    /// using the inner service.
    Service(E),
}

impl<E: fmt::Debug> fmt::Debug for TlsAcceptorError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accept(err) => write!(f, "TlsAcceptorError::Accept({err:?})"),
            Self::Service(err) => write!(f, "TlsAcceptorError::Service({err:?})"),
        }
    }
}

impl<E> std::fmt::Display for TlsAcceptorError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsAcceptorError::Accept(e) => write!(f, "accept error: {}", e),
            TlsAcceptorError::Service(e) => write!(f, "service error: {}", e),
        }
    }
}

impl<E> std::error::Error for TlsAcceptorError<E>
where
    E: std::fmt::Debug + std::fmt::Display,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TlsAcceptorError::Accept(e) => Some(e),
            TlsAcceptorError::Service(_) => None,
        }
    }
}
