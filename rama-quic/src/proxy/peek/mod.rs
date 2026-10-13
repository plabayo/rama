//! Peek at a QUIC client's Initial flight before choosing how to handle the association.

use std::{fmt, time::Duration};

use rama_core::{
    Service,
    bytes::Bytes,
    error::{BoxError, BoxErrorExt as _},
    extensions::{Extensions, ExtensionsRef},
    io::peek::PeekTimeoutPolicy,
    service::RejectService,
    telemetry::tracing,
};
use rama_quic_proto::{
    capture::{CaptureLimits, KeyProvider},
    peek::{InitialPeek, PeekedClientHello},
};
use rama_udp::{
    DatagramMetadata, DatagramPeekInput, DatagramSocketExt as _, PrefixedDatagramSocket,
    RetainedDatagram,
};
use rama_utils::octets::kib;
use tokio::time::{Instant, timeout_at};

/// The default for [`PeekQuicClientHelloService::with_peek_timeout`]: one handshake flight
/// over a slow path, short enough that a silent client cannot hold an inspection open.
pub const DEFAULT_QUIC_PEEK_TIMEOUT: Duration = Duration::from_secs(2);

/// Every datagram fits: the largest UDP payload.
const RECEIVE_BUFFER: usize = kib(64);

/// The input handed on after a complete QUIC ClientHello was found in the client's Initials.
#[derive(Debug)]
pub struct InputWithQuicClientHello<Input> {
    pub input: Input,
    pub client_hello: PeekedClientHello,
}

impl<Input: ExtensionsRef> ExtensionsRef for InputWithQuicClientHello<Input> {
    fn extensions(&self) -> &Extensions {
        self.input.extensions()
    }
}

/// Inspects the first datagrams of a UDP association for a QUIC client's Initial flight and
/// its ClientHello, then hands the association on with those datagrams replayed in front.
///
/// A complete ClientHello goes to the inner service as [`InputWithQuicClientHello`]; anything
/// else (not QUIC, an unsupported version, malformed or truncated input, exhausted limits, or
/// the deadline) goes to the fallback with the same datagrams intact, so the fallback can still
/// forward the association untouched. Nothing is ever sent while peeking: the decision is made
/// before any local QUIC output exists. The deadline is absolute from `serve`, and the read
/// ahead is bounded by [`CaptureLimits`].
///
/// The fallback rejects by default; use [`Self::with_fallback`] to forward instead.
pub struct PeekQuicClientHelloService<K, S, F = RejectService<(), NoQuicRejectError>> {
    keys: K,
    inner: S,
    fallback: F,
    limits: CaptureLimits,
    peek_timeout: Duration,
    peek_timeout_policy: PeekTimeoutPolicy,
}

impl<K, S> PeekQuicClientHelloService<K, S> {
    /// Peek with `keys` deriving the Initial keys of the client's offered version. No
    /// certificate or server identity is needed.
    pub fn new(keys: K, inner: S) -> Self {
        Self {
            keys,
            inner,
            fallback: RejectService::new(NoQuicRejectError),
            limits: CaptureLimits::default(),
            peek_timeout: DEFAULT_QUIC_PEEK_TIMEOUT,
            peek_timeout_policy: PeekTimeoutPolicy::default(),
        }
    }
}

impl<K, S, F> PeekQuicClientHelloService<K, S, F> {
    /// Hand associations without a complete QUIC ClientHello to `fallback`.
    pub fn with_fallback<G>(self, fallback: G) -> PeekQuicClientHelloService<K, S, G> {
        PeekQuicClientHelloService {
            keys: self.keys,
            inner: self.inner,
            fallback,
            limits: self.limits,
            peek_timeout: self.peek_timeout,
            peek_timeout_policy: self.peek_timeout_policy,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bounds on the datagrams, packets and bytes read ahead.
        pub fn limits(mut self, limits: CaptureLimits) -> Self {
            self.limits = limits;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// How long the whole inspection may take, from `serve`. Defaults to
        /// [`DEFAULT_QUIC_PEEK_TIMEOUT`].
        pub fn peek_timeout(mut self, timeout: Duration) -> Self {
            self.peek_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether an inspection still inconclusive at its deadline goes to the fallback
        /// (the default) or fails.
        pub fn peek_timeout_policy(mut self, policy: PeekTimeoutPolicy) -> Self {
            self.peek_timeout_policy = policy;
            self
        }
    }
}

impl<K: fmt::Debug, S: fmt::Debug, F: fmt::Debug> fmt::Debug
    for PeekQuicClientHelloService<K, S, F>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeekQuicClientHelloService")
            .field("keys", &self.keys)
            .field("inner", &self.inner)
            .field("fallback", &self.fallback)
            .field("limits", &self.limits)
            .field("peek_timeout", &self.peek_timeout)
            .field("peek_timeout_policy", &self.peek_timeout_policy)
            .finish()
    }
}

impl<K: Clone, S: Clone, F: Clone> Clone for PeekQuicClientHelloService<K, S, F> {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            inner: self.inner.clone(),
            fallback: self.fallback.clone(),
            limits: self.limits,
            peek_timeout: self.peek_timeout,
            peek_timeout_policy: self.peek_timeout_policy,
        }
    }
}

/// How an inspection ended.
enum Peeked {
    ClientHello(PeekedClientHello),
    Other,
    Deadline,
}

impl<I, K, S, F, O> Service<I> for PeekQuicClientHelloService<K, S, F>
where
    I: DatagramPeekInput,
    K: KeyProvider + Send + Sync + 'static,
    S: Service<
            InputWithQuicClientHello<I::Mapped<PrefixedDatagramSocket<I::Socket>>>,
            Output = O,
            Error: Into<BoxError>,
        >,
    F: Service<I::Mapped<PrefixedDatagramSocket<I::Socket>>, Output = O, Error: Into<BoxError>>,
    O: Send + 'static,
{
    type Output = O;
    type Error = BoxError;

    fn serve(&self, mut input: I) -> impl Future<Output = Result<O, BoxError>> + Send + '_ {
        // Fixed when the association is handed over, so a late first poll gains no time.
        let deadline = Instant::now() + self.peek_timeout;
        async move {
            let mut retained = Vec::new();
            let peeked = self
                .peek(input.peek_socket_mut(), deadline, &mut retained)
                .await?;
            let input =
                input.map_peek_socket(|socket| PrefixedDatagramSocket::new(socket, retained));
            match peeked {
                Peeked::ClientHello(client_hello) => self
                    .inner
                    .serve(InputWithQuicClientHello {
                        input,
                        client_hello,
                    })
                    .await
                    .map_err(Into::into),
                Peeked::Deadline if self.peek_timeout_policy == PeekTimeoutPolicy::FailClosed => {
                    Err(BoxError::from_static_str(
                        "QUIC ClientHello peek deadline exceeded",
                    ))
                }
                Peeked::Deadline | Peeked::Other => {
                    self.fallback.serve(input).await.map_err(Into::into)
                }
            }
        }
    }
}

impl<K: KeyProvider, S, F> PeekQuicClientHelloService<K, S, F> {
    async fn peek<Socket: rama_udp::DatagramSocket>(
        &self,
        socket: &mut Socket,
        deadline: Instant,
        retained: &mut Vec<RetainedDatagram>,
    ) -> Result<Peeked, BoxError> {
        let mut inspector = InitialPeek::new(self.limits, deadline.into_std());
        let mut buffer = vec![0; RECEIVE_BUFFER];
        loop {
            let metadata = match timeout_at(deadline, socket.recv(&mut buffer)).await {
                Ok(received) => received?,
                Err(_elapsed) => return Ok(Peeked::Deadline),
            };
            let payload = Bytes::copy_from_slice(&buffer[..metadata.len]);
            retained.push(RetainedDatagram {
                payload: payload.clone(),
                metadata,
            });
            // A cut datagram cannot be inspected, and is replayed as it was received.
            if metadata.truncated {
                return Ok(Peeked::Other);
            }
            for segment in segments(&payload, &metadata) {
                match inspector.inspect(Instant::now().into_std(), segment, &self.keys) {
                    Ok(Some(client_hello)) => return Ok(Peeked::ClientHello(client_hello)),
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(%error, "QUIC ClientHello peek ended without a ClientHello");
                        return Ok(Peeked::Other);
                    }
                }
            }
        }
    }
}

/// The logical datagrams of one receive: GRO coalesces equal-size segments, the last possibly
/// shorter.
fn segments<'a>(payload: &'a [u8], metadata: &DatagramMetadata) -> impl Iterator<Item = &'a [u8]> {
    let size = metadata
        .segment_size
        .map_or(payload.len().max(1), |size| size.get());
    payload
        .chunks(size)
        .chain(payload.is_empty().then_some(&payload[..0]))
}

/// The fallback's default rejection: the association carried no complete QUIC ClientHello.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoQuicRejectError;

impl fmt::Display for NoQuicRejectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("association carried no complete QUIC ClientHello")
    }
}

impl std::error::Error for NoQuicRejectError {}

#[cfg(test)]
#[cfg(any(
    feature = "boring",
    all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
))]
mod tests;
