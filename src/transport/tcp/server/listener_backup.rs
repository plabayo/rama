use std::{
    net::{TcpListener as StdTcpListener, ToSocketAddrs},
    time::Duration, future::Future, convert::Infallible,
};

use tokio::net::TcpListener;

use crate::{transport::graceful, service::{Service, ServiceFactory}};

mod marker {
    #[derive(Debug)]
    pub(super) struct None;

    #[derive(Debug)]
    pub(super) struct Some<T>(pub(super) T);
}

#[derive(Debug)]
pub struct Listener<F, State> {
    tcp: TcpListener,
    service_factory: F,
    shutdown_timeout: Option<Duration>,
    graceful: graceful::GracefulService,
    state: State,
}

#[derive(Debug)]
pub struct Builder<I, G, S> {
    incoming: I,
    graceful: G,
    state: S,
}

#[derive(Debug)]
pub struct SocketConfig<L> {
    listener: L,
    ttl: Option<u32>,
}

#[derive(Debug)]
pub struct GracefulConfig<S> {
    shutdown: S,
    timeout: Option<Duration>,
}

pub trait IntoTcpListener {
    fn into_tcp_listener(self) -> Result<TcpListener, std::io::Error>;
}

impl IntoTcpListener for TcpListener {
    fn into_tcp_listener(self) -> Result<TcpListener, std::io::Error> {
        Ok(self)
    }
}

impl IntoTcpListener for StdTcpListener {
    fn into_tcp_listener(self) -> Result<TcpListener, std::io::Error> {
        TcpListener::from_std(self)
    }
}

impl Listener<marker::None, marker::None> {
    pub fn bind<A: ToSocketAddrs>(addr: A) -> Builder<SocketConfig<TcpListener>, marker::None, marker::None> {
        match Self::try_bind(addr) {
            Ok(incoming) => incoming,
            Err(err) => panic!("failed to bind tcp listener: {}", err),
        }
    }

    pub fn try_bind<A: ToSocketAddrs>(
        addr: A,
    ) -> Result<Builder<SocketConfig<TcpListener>, marker::None, marker::None>, std::io::Error> {
        let incoming = StdTcpListener::bind(addr)?;
        incoming.set_nonblocking(true)?;
        Self::build(incoming)
    }

    pub fn build(incoming: impl IntoTcpListener) -> Result<Builder<SocketConfig<TcpListener>, marker::None, marker::None>, std::io::Error> {
        let listener = incoming.into_tcp_listener()?;
        Ok(Builder::new(listener, marker::None, marker::None))
    }
}

impl<G, S> Builder<SocketConfig<TcpListener>, G, S> {
    /// Create a new `Builder` with the specified address.
    fn new(listener: TcpListener, graceful: G, state: S) -> Self {
        Self {
            incoming: SocketConfig {
                listener,
                ttl: None,
            },
            graceful,
            state,
        }
    }

    /// Set the value of `IP_TTL` option for accepted connections.
    ///
    /// If `None` is specified, ttl is not explicitly set.
    pub fn ttl(mut self, ttl: Option<u32>) -> Self {
        self.incoming.ttl = ttl;
        self
    }
}

impl<I, State> Builder<I, marker::None, State> {
    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the given future resolves.
    pub fn graceful<S: Future<Output = ()>>(
        self,
        shutdown: S,
    ) -> Builder<I, GracefulConfig<S>, State> {
        Builder {
            incoming: self.incoming,
            graceful: GracefulConfig {
                shutdown,
                timeout: None,
            },
            state: self.state,
        }
    }

    /// Upgrade the builder to one which builds
    /// a graceful TCP listener which will shutdown once the "ctrl+c" signal is received (SIGINT).
    pub fn graceful_ctrl_c(self) -> Builder<I, GracefulConfig<impl Future<Output = ()>>, State> {
        self.graceful(async {
            let _ = tokio::signal::ctrl_c().await;
        })
    }
}

impl<I, G> Builder<I, G, marker::None> {
    pub fn state<S>(self, state: S) -> Builder<I, G, marker::Some<S>> {
        Builder {
            incoming: self.incoming,
            graceful: self.graceful,
            state: marker::Some(state),
        }
    }
}

impl<I, S, State> Builder<I, GracefulConfig<S>, State> {
    /// Set the timeout for graceful shutdown.
    ///
    /// If `None` is specified, the default timeout is used.
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.graceful.timeout = timeout;
        self
    }
}

impl<S, State> Builder<SocketConfig<TcpListener>, GracefulConfig<S>, State>
where
    S: Future + Send + 'static,
{
    pub async fn serve<F>(self, service_factory: F) -> Result<(), Box<dyn std::error::Error>>
    where
        F: ServiceFactory<State>,
        F::Service: Service<State> + Send + 'static,
    {
        // create and configure the tcp listener...
        let listener = self.incoming.listener;
        if let Some(ttl) = self.incoming.ttl {
            listener.set_ttl(ttl)?;
        }
        // listen gracefully..
        Listener::new(
            listener,
            service_factory,
            self.graceful.shutdown,
            self.graceful.timeout,
        )
        .serve()
        .await
    }
}