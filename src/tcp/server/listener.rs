use std::{future::Future, io, net::SocketAddr};

use crate::rt::{
    graceful::ShutdownGuard,
    net::{TcpListener as AsyncTcpListener, TcpStream as AsyncTcpStream, ToSocketAddrs},
};

use crate::{
    service::{
        util::{Identity, Stack},
        Layer, Service, ServiceBuilder,
    },
    state::Extendable,
    tcp::TcpStream,
    BoxError,
};

pub struct TcpListener<L> {
    inner: AsyncTcpListener,
    builder: ServiceBuilder<L>,
}

impl TcpListener<Identity> {
    /// Creates a new TcpListener, which will be bound to the specified address.
    ///
    /// The returned listener is ready for accepting connections.
    ///
    /// Binding with a port number of 0 will request that the OS assigns a port
    /// to this listener. The port allocated can be queried via the `local_addr`
    /// method.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<Self> {
        let inner = AsyncTcpListener::bind(addr).await?;
        let builder = ServiceBuilder::new();
        Ok(TcpListener { inner, builder })
    }
}

impl<L> TcpListener<L> {
    /// Returns the local address that this listener is bound to.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out
    /// which port was actually bound.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Gets the value of the `IP_TTL` option for this socket.
    ///
    /// For more information about this option, see [`set_ttl`].
    ///
    /// [`set_ttl`]: method@Self::set_ttl
    pub fn ttl(&self) -> io::Result<u32> {
        self.inner.ttl()
    }

    /// Sets the value for the `IP_TTL` option on this socket.
    ///
    /// This value sets the time-to-live field that is used in every packet sent
    /// from this socket.
    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        self.inner.set_ttl(ttl)
    }

    /// Adds a layer to the service.
    ///
    /// This method can be used to add a middleware to the service.
    pub fn layer<M>(self, layer: M) -> TcpListener<Stack<M, L>>
    where
        M: tower_async::layer::Layer<L>,
    {
        TcpListener {
            inner: self.inner,
            builder: self.builder.layer(layer),
        }
    }

    /// Optionally add a new layer `T`.
    pub fn option_layer<M>(
        self,
        layer: Option<M>,
    ) -> TcpListener<Stack<crate::service::util::Either<M, Identity>, L>>
    where
        M: tower_async::layer::Layer<L>,
    {
        self.layer(crate::service::util::option_layer(layer))
    }

    /// Spawn a task to handle each incoming request.
    pub fn spawn(self) -> TcpListener<Stack<crate::service::spawn::SpawnLayer, L>> {
        self.layer(crate::service::spawn::SpawnLayer::new())
    }

    /// Attach a bytes tracker to each incoming request.
    ///
    /// This can be used to track the number of bytes read and written,
    /// by using the [`BytesRWTrackerHandle`] found in the extensions.
    ///
    /// [`BytesRWTrackerHandle`]: crate::stream::layer::BytesRWTrackerHandle
    pub fn bytes_tracker(self) -> TcpListener<Stack<crate::stream::layer::BytesTrackerLayer, L>> {
        self.layer(crate::stream::layer::BytesTrackerLayer::new())
    }

    /// Fail requests that take longer than `timeout`.
    pub fn timeout(
        self,
        timeout: std::time::Duration,
    ) -> TcpListener<Stack<crate::service::timeout::TimeoutLayer, L>> {
        self.layer(crate::service::timeout::TimeoutLayer::new(timeout))
    }

    // Conditionally reject requests based on `predicate`.
    ///
    /// `predicate` must implement the [`Predicate`] trait.
    ///
    /// This wraps the inner service with an instance of the [`Filter`]
    /// middleware.
    ///
    /// [`Filter`]: crate::service::filter::Filter
    /// [`Predicate`]: crate::service::filter::Predicate
    pub fn filter<P>(
        self,
        predicate: P,
    ) -> TcpListener<Stack<crate::service::filter::FilterLayer<P>, L>>
    where
        P: Clone,
    {
        self.layer(crate::service::filter::FilterLayer::new(predicate))
    }

    /// Conditionally reject requests based on an asynchronous `predicate`.
    ///
    /// `predicate` must implement the [`AsyncPredicate`] trait.
    ///
    /// This wraps the inner service with an instance of the [`AsyncFilter`]
    /// middleware.
    ///
    /// [`AsyncFilter`]: crate::service::filter::AsyncFilter
    /// [`AsyncPredicate`]: crate::service::filter::AsyncPredicate
    pub fn filter_async<P>(
        self,
        predicate: P,
    ) -> TcpListener<Stack<crate::service::filter::AsyncFilterLayer<P>, L>>
    where
        P: Clone,
    {
        self.layer(crate::service::filter::AsyncFilterLayer::new(predicate))
    }

    /// Limit the number of in-flight requests.
    ///
    /// This wraps the inner service with an instance of the [`Limit`]
    /// middleware. The `policy` determines how to handle requests sent
    /// to the inner service when the limit has been reached.
    ///
    /// [`Limit`]: crate::service::limit::Limit
    pub fn limit<P>(self, policy: P) -> TcpListener<Stack<crate::service::limit::LimitLayer<P>, L>>
    where
        P: Clone,
    {
        self.layer(crate::service::limit::LimitLayer::new(policy))
    }
}

impl<L> TcpListener<L> {
    /// Serve connections from this listener with the given service.
    ///
    /// This method will block the current listener for each incoming connection,
    /// the underlying service can choose to spawn a task to handle the accepted stream.
    pub async fn serve<T, S, E>(self, service: S) -> TcpServeResult<()>
    where
        L: Layer<S>,
        L::Service: Service<TcpStream<AsyncTcpStream>, Response = T, Error = E>,
        E: Into<BoxError>,
    {
        let service = self.builder.service(service);

        loop {
            let (stream, _) = self.inner.accept().await?;
            let stream = TcpStream::new(stream);
            service
                .call(stream)
                .await
                .map_err(|err| TcpServeError::Service(err.into()))?;
        }
    }

    /// Serve connections from this listener with the given service function.
    ///
    /// See [`Self::serve`] for more details.
    pub async fn serve_fn<T, S, E, F, Fut>(self, service: F) -> TcpServeResult<()>
    where
        L: Layer<crate::service::ServiceFn<F>>,
        L::Service: Service<TcpStream<AsyncTcpStream>, Response = T, Error = E>,
        E: Into<BoxError>,
        F: Fn(TcpStream<S>) -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let service = crate::service::service_fn(service);
        self.serve(service).await
    }

    /// Serve gracefully connections from this listener with the given service.
    ///
    /// This method does the same as [`Self::serve`] but it
    /// will respect the given [`crate::graceful::ShutdownGuard`], and also pass
    /// it to the service.
    pub async fn serve_graceful<T, S, E>(
        self,
        guard: ShutdownGuard,
        service: S,
    ) -> TcpServeResult<()>
    where
        L: Layer<S>,
        L::Service: Service<TcpStream<AsyncTcpStream>, Response = T, Error = E>,
        E: Into<BoxError>,
    {
        let service = self.builder.service(service);

        loop {
            let guard = guard.clone();
            crate::rt::select! {
                _ = guard.cancelled() => {
                    tracing::info!("signal received: initiate graceful shutdown");
                    break Ok(());
                }
                result = self.inner.accept() => {
                    match result {
                        Ok((socket, _)) => {
                            let mut stream = TcpStream::new(socket);
                            stream.extensions_mut().insert(guard.clone());
                            service.call(stream).await.map_err(|err| TcpServeError::Service(err.into()))?;
                        }
                        Err(err) => {
                            tracing::debug!(error = &err as &dyn std::error::Error, "service error");
                        }
                    }
                }
            }
        }
    }

    /// Serve gracefully connections from this listener with the given service function.
    ///
    /// See [`Self::serve_graceful`] for more details.
    pub async fn serve_fn_graceful<T, S, E, F, Fut>(
        self,
        guard: ShutdownGuard,
        service: F,
    ) -> TcpServeResult<()>
    where
        L: Layer<crate::service::ServiceFn<F>>,
        L::Service: Service<TcpStream<AsyncTcpStream>, Response = T, Error = E>,
        E: Into<BoxError>,
        F: Fn(TcpStream<S>) -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        let service = crate::service::service_fn(service);
        self.serve_graceful(guard, service).await
    }
}

pub type TcpServeResult<T> = Result<T, TcpServeError>;

#[derive(Debug)]
pub enum TcpServeError {
    Io(io::Error),
    Service(BoxError),
}

impl From<io::Error> for TcpServeError {
    fn from(e: io::Error) -> Self {
        TcpServeError::Io(e)
    }
}

impl std::fmt::Display for TcpServeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpServeError::Io(e) => write!(f, "IO error: {}", e),
            TcpServeError::Service(e) => write!(f, "Service error: {}", e),
        }
    }
}

impl std::error::Error for TcpServeError {}
