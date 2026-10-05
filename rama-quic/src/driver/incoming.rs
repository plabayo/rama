use std::{
    fmt,
    future::{Future, IntoFuture},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use crate::driver::sockets::Lease;
use crate::proto::{
    ClientHelloPeek, ConnectionError, RetryRefused, ServerConfig, crypto::ClientHelloMessage,
};
use rama_core::telemetry::tracing;
use rama_quic_proto::{ConnectionId, TransportError};
use rama_tls::client::ClientHello;

use crate::driver::{
    connection::{Connecting, Connection},
    endpoint::EndpointRef,
};

/// An incoming connection for which the server has not yet begun its part of the handshake
#[derive(Debug)]
pub struct Incoming(Option<State>);

impl Incoming {
    #[expect(
        clippy::expect_used,
        reason = "state is removed only by consuming methods, which cannot leave a callable Incoming behind"
    )]
    fn state(&self) -> &State {
        self.0.as_ref().expect("unconsumed incoming state")
    }

    #[expect(
        clippy::expect_used,
        reason = "this consumes Incoming exactly once and clears state before its Drop runs"
    )]
    fn into_state(mut self) -> State {
        self.0.take().expect("unconsumed incoming state")
    }

    pub(crate) fn new(inner: crate::proto::Incoming, endpoint: EndpointRef, lease: Lease) -> Self {
        Self(Some(State {
            inner,
            endpoint,
            lease,
        }))
    }

    /// Attempt to accept this incoming connection (an error may still occur)
    ///
    /// A server configuration whose TLS provider resolves its configuration per ClientHello,
    /// such as one issuing certificates on demand, cannot start here: `await` this attempt
    /// instead, or resolve one with [`Self::client_hello`] and use [`Self::accept_with`].
    pub fn accept(self) -> Result<Connecting, ConnectionError> {
        let state = self.into_state();
        state.endpoint.accept(state.inner, state.lease, None)
    }

    /// Accept this incoming connection using a custom configuration
    ///
    /// See [`accept()`][Incoming::accept] for more details.
    pub fn accept_with(
        self,
        server_config: Arc<ServerConfig>,
    ) -> Result<Connecting, ConnectionError> {
        let state = self.into_state();
        state
            .endpoint
            .accept(state.inner, state.lease, Some(server_config))
    }

    /// Reject this incoming connection attempt
    pub fn refuse(self) {
        let state = self.into_state();
        state.endpoint.refuse(state.inner, state.lease);
    }

    /// Respond with a retry packet, requiring the client to retry with address validation
    ///
    /// Errors if `may_retry()` is false.
    pub fn retry(self) -> Result<(), RetryError> {
        let state = self.into_state();
        state
            .endpoint
            .retry(state.inner, state.lease)
            .map_err(|(e, lease)| {
                let reason = e.reason();
                RetryError {
                    incoming: Box::new(Self(Some(State {
                        inner: e.into_incoming(),
                        endpoint: state.endpoint,
                        lease,
                    }))),
                    reason,
                }
            })
    }

    /// Ignore this incoming connection attempt, not sending any packet in response
    pub fn ignore(self) {
        let state = self.into_state();
        state.endpoint.ignore(state.inner, state.lease);
    }

    /// The local IP address which was used when the peer established the connection
    pub fn local_ip(&self) -> Option<IpAddr> {
        self.state().inner.local_ip()
    }

    /// The peer's UDP address
    pub fn remote_address(&self) -> SocketAddr {
        self.state().inner.remote_address()
    }

    /// Whether the socket address that is initiating this connection has been validated
    ///
    /// This means that the sender of the initial packet has proved that they can receive traffic
    /// sent to `self.remote_address()`.
    ///
    /// Before expiry, if `self.remote_address_validated()` is false, `self.may_retry()` is true.
    /// The inverse is not guaranteed.
    pub fn remote_address_validated(&self) -> bool {
        self.state().inner.remote_address_validated()
    }

    /// Whether this pending attempt has expired or was retired by endpoint shutdown.
    pub fn is_expired(&self) -> bool {
        self.state().inner.is_expired()
    }

    /// Whether it is legal to respond with a retry packet
    ///
    /// Before expiry, if `self.remote_address_validated()` is false, `self.may_retry()` is true.
    /// The inverse is not guaranteed.
    pub fn may_retry(&self) -> bool {
        self.state().inner.may_retry()
    }

    /// The original destination CID when initiating the connection
    pub fn orig_dst_cid(&self) -> ConnectionId {
        *self.state().inner.orig_dst_cid()
    }

    /// The client's ClientHello, once its first flight delivered all of it.
    ///
    /// A ClientHello can span several Initial packets; this waits for the rest until the
    /// attempt expires or the endpoint closes. One larger than 16 KiB is refused. Use it to
    /// choose a configuration for [`Self::accept_with`].
    pub async fn client_hello(&self) -> Result<ClientHello, ConnectionError> {
        self.client_hello_message()
            .await
            .map(ClientHelloMessage::into_client_hello)
    }

    async fn client_hello_message(&self) -> Result<ClientHelloMessage, ConnectionError> {
        let state = self.state();
        let deadline = tokio::time::Instant::from_std(state.inner.deadline());
        loop {
            if state.inner.is_expired() {
                return Err(ConnectionError::TimedOut);
            }
            let (peek, seen) = state.endpoint.client_hello_progress(&state.inner)?;
            match peek {
                ClientHelloPeek::Complete(message) => return Ok(message),
                ClientHelloPeek::Incomplete => {}
                ClientHelloPeek::Invalid => {
                    return Err(ConnectionError::TransportError(
                        TransportError::PROTOCOL_VIOLATION("unreadable ClientHello"),
                    ));
                }
            }
            let progress = state.inner.progress();
            let progressed = std::future::poll_fn(|cx| {
                progress.register(cx.waker());
                if progress.generation() == seen {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            });
            if tokio::time::timeout_at(deadline, progressed).await.is_err() {
                return Err(ConnectionError::TimedOut);
            }
        }
    }

    /// Resolve this attempt's TLS configuration from its ClientHello, then accept it.
    ///
    /// Any failure drops the attempt, which refuses it.
    async fn resolve_and_accept(
        self,
        admitted: Arc<ServerConfig>,
    ) -> Result<Connection, ConnectionError> {
        let client_hello = self.client_hello_message().await?;
        let resolved = admitted
            .crypto
            .clone()
            .resolve(client_hello)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "QUIC: resolve server TLS configuration from ClientHello");
                ConnectionError::TransportError(TransportError::CONNECTION_REFUSED(
                    "server configuration unresolved",
                ))
            })?;
        if resolved.requires_client_hello() {
            return Err(ConnectionError::TransportError(
                TransportError::INTERNAL_ERROR("resolved server configuration is not final"),
            ));
        }
        let mut config = ServerConfig::clone(&admitted);
        config.crypto = resolved;
        self.accept_with(Arc::new(config))?.await
    }
}

impl Drop for Incoming {
    fn drop(&mut self) {
        // Implicit reject, similar to Connection's implicit close
        if let Some(state) = self.0.take() {
            state.endpoint.refuse(state.inner, state.lease);
        }
    }
}

#[derive(Debug)]
struct State {
    inner: crate::proto::Incoming,
    endpoint: EndpointRef,
    /// The attempt's hold on the endpoint socket the Initial arrived on; every response and the
    /// accepted connection use that socket, and the hold is released exactly once.
    lease: Lease,
}

/// Error for a Retry that was not sent; the [`Incoming`] is handed back for another decision
#[derive(Debug)]
pub struct RetryError {
    incoming: Box<Incoming>,
    reason: RetryRefused,
}

impl core::fmt::Display for RetryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.reason {
            RetryRefused::AlreadyRetried => {
                f.write_str("retry requires an active incoming attempt without a previous Retry")
            }
            RetryRefused::NoServerConfig => f.write_str("retry requires a server configuration"),
            RetryRefused::TokenSealing => f.write_str("the retry token could not be sealed"),
            RetryRefused::IntegrityProtection => {
                f.write_str("the retry packet could not be authenticated")
            }
            RetryRefused::LifetimeUnrepresentable => f.write_str(
                "the configured retry token lifetime cannot be represented on the clock",
            ),
        }
    }
}

impl std::error::Error for RetryError {}

impl RetryError {
    /// Why the Retry was not sent
    #[must_use]
    pub fn reason(&self) -> RetryRefused {
        self.reason
    }

    /// Take the [`Incoming`] back, to accept, refuse or ignore it instead.
    #[must_use]
    pub fn into_incoming(self) -> Incoming {
        *self.incoming
    }
}

/// Adapter to let [`Incoming`] be `await`-ed like a [`Connecting`]
///
/// When the server's TLS configuration resolves per ClientHello, the attempt waits for its
/// ClientHello and that resolution before it is accepted.
pub struct IncomingFuture(IncomingFutureState);

#[expect(
    clippy::large_enum_variant,
    reason = "accepting is the common path; only the rare resolving future is boxed"
)]
enum IncomingFutureState {
    Accepting(Result<Connecting, ConnectionError>),
    Resolving(Pin<Box<dyn Future<Output = Result<Connection, ConnectionError>> + Send>>),
}

impl fmt::Debug for IncomingFuture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            IncomingFutureState::Accepting(accepting) => {
                f.debug_tuple("IncomingFuture").field(accepting).finish()
            }
            IncomingFutureState::Resolving(_) => f.write_str("IncomingFuture(Resolving)"),
        }
    }
}

impl Future for IncomingFuture {
    type Output = Result<Connection, ConnectionError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match &mut self.0 {
            IncomingFutureState::Accepting(Ok(connecting)) => Pin::new(connecting).poll(cx),
            IncomingFutureState::Accepting(Err(e)) => Poll::Ready(Err(e.clone())),
            IncomingFutureState::Resolving(resolving) => resolving.as_mut().poll(cx),
        }
    }
}

impl IntoFuture for Incoming {
    type Output = Result<Connection, ConnectionError>;
    type IntoFuture = IncomingFuture;

    fn into_future(self) -> Self::IntoFuture {
        IncomingFuture(match self.state().inner.resolving().cloned() {
            None => IncomingFutureState::Accepting(self.accept()),
            Some(admitted) => {
                IncomingFutureState::Resolving(Box::pin(self.resolve_and_accept(admitted)))
            }
        })
    }
}
