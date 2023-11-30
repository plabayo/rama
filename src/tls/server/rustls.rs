use std::sync::Arc;

use crate::{
    rt::tls::rustls::{
        server::{TlsServerConfig, TlsStream},
        TlsAcceptor,
    },
    service::{Layer, Service},
    stream::Stream,
    tcp::TcpStream,
};

pub struct RustlsAcceptorService<S> {
    acceptor: TlsAcceptor,
    inner: S,
}

impl<S> std::fmt::Debug for RustlsAcceptorService<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustlsAcceptorService").finish()
    }
}

impl<S> Clone for RustlsAcceptorService<S>
where
    S: Clone,
{
    fn clone(&self) -> Self {
        Self {
            acceptor: self.acceptor.clone(),
            inner: self.inner.clone(),
        }
    }
}

impl<S, I> Service<TcpStream<I>> for RustlsAcceptorService<S>
where
    S: Service<TcpStream<TlsStream<I>>>,
    I: Stream + Unpin,
{
    type Response = S::Response;
    type Error = RustlsAcceptorError<S::Error>;

    async fn call(&self, stream: TcpStream<I>) -> Result<Self::Response, Self::Error> {
        let (stream, extensions) = stream.into_parts();
        let stream = self
            .acceptor
            .accept(stream)
            .await
            .map_err(RustlsAcceptorError::Accept)?;
        let stream = TcpStream::from_parts(stream, extensions);

        self.inner
            .call(stream)
            .await
            .map_err(RustlsAcceptorError::Service)
    }
}

#[derive(Debug)]
pub enum RustlsAcceptorError<E> {
    Accept(std::io::Error),
    Service(E),
}

impl<E> std::fmt::Display for RustlsAcceptorError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RustlsAcceptorError::Accept(e) => write!(f, "accept error: {}", e),
            RustlsAcceptorError::Service(e) => write!(f, "service error: {}", e),
        }
    }
}

impl<E> std::error::Error for RustlsAcceptorError<E> where E: std::fmt::Display + std::fmt::Debug {}

pub struct RustlsAcceptorLayer {
    acceptor: TlsAcceptor,
}

impl RustlsAcceptorLayer {
    pub fn new(config: TlsServerConfig) -> Self {
        Self {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        }
    }
}

impl<S> Layer<S> for RustlsAcceptorLayer {
    type Service = RustlsAcceptorService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RustlsAcceptorService {
            acceptor: self.acceptor.clone(),
            inner,
        }
    }
}
