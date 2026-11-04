//! Peek at a QUIC client's Initial flight before choosing how to handle the association.

use rama_utils::macros::define_inner_service_accessors;
use std::{fmt, time::Duration};

use rama_core::{
    Service,
    bytes::Bytes,
    error::BoxError,
    extensions::{Extension, ExtensionsRef},
    io::{
        BridgeIo,
        peek::{PeekStopReason, PeekTimeoutPolicy},
    },
    service::RejectService,
    telemetry::tracing,
};
use rama_quic_proto::{
    capture::{CaptureError, CaptureLimits, KeyProvider},
    peek::{InitialPeek, PeekError, PeekedClientHello},
};
use rama_tls::client::{ClientHelloPeekStatus, DEFAULT_CLIENT_HELLO_MAX_SIZE, MalformedTlsPolicy};
use rama_udp::{
    DatagramPeekInput, DatagramSocket, DatagramSocketExt as _, PrefixedDatagramSocket,
    RetainedDatagram, proxy::DatagramBridgeInput,
};
use rama_utils::octets::{kib, mib};
use tokio::time::{Instant, timeout_at};

/// The default for [`PeekQuicClientHelloService::with_peek_timeout`]: one handshake flight
/// over a slow path, short enough that a silent client cannot hold an inspection open.
pub const DEFAULT_QUIC_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Default live-inspection budgets. A 256 KiB ClientHello has room for packet
/// overhead, fragmentation and retransmissions within 1 MiB of datagrams.
/// These apply before dispatch; they do not change capture or endpoint admission limits.
pub const DEFAULT_QUIC_PEEK_LIMITS: CaptureLimits = CaptureLimits {
    datagrams: 512,
    bytes: mib(1),
    packets: 1024,
    frames: 8192,
    crypto_fragments: 1024,
    client_hello_bytes: DEFAULT_CLIENT_HELLO_MAX_SIZE,
    parameters: 256,
};

/// Every datagram fits: the largest UDP payload.
const RECEIVE_BUFFER: usize = kib(64);

/// The input handed on after a complete QUIC ClientHello was found in the client's Initials.
#[derive(Debug, ExtensionsRef)]
pub struct InputWithQuicClientHello<Input> {
    #[extensions_ref]
    pub input: Input,
    /// The ClientHello found, with what was learned on the way.
    pub peeked: PeekedClientHello,
}

/// An association peeked before its egress exists keeps its ClientHello once bridged, so the
/// egress is created only for the associations a policy routes on.
impl<S> DatagramBridgeInput for InputWithQuicClientHello<S>
where
    S: DatagramSocket + ExtensionsRef + Send + 'static,
{
    type Ingress = S;
    type Bridged<Egress>
        = InputWithQuicClientHello<BridgeIo<S, Egress>>
    where
        Egress: Send + 'static;

    fn ingress(&self) -> &Self::Ingress {
        &self.input
    }

    fn bridge<Egress: Send + 'static>(self, egress: Egress) -> Self::Bridged<Egress> {
        InputWithQuicClientHello {
            input: BridgeIo(self.input, egress),
            peeked: self.peeked,
        }
    }
}

/// Why a QUIC peek found no complete ClientHello. A fallback receives this detail
/// in its extensions. For the current inspection outcome, including a cleared
/// failure after a later successful or non-QUIC peek, use [`ClientHelloPeekStatus`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Extension)]
#[extension(tags(net, proxy))]
pub enum QuicPeekRejection {
    /// The association does not start with a QUIC client's flight: another protocol, or a
    /// QUIC connection already past its handshake.
    NotQuic,
    /// A client flight of a QUIC version this inspector does not implement.
    UnsupportedVersion,
    /// A client flight that cannot be inspected: malformed, undecryptable, contradictory (such
    /// as conflicting CRYPTO data or mixed attempts), or cut short by its receive.
    Malformed,
    /// The flight exhausted the configured [`CaptureLimits`].
    Budget,
    /// No complete ClientHello arrived before the deadline.
    Deadline,
}

impl fmt::Display for QuicPeekRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotQuic => "not a QUIC client flight",
            Self::UnsupportedVersion => "unsupported QUIC version",
            Self::Malformed => "malformed QUIC client flight",
            Self::Budget => "QUIC peek limits exhausted",
            Self::Deadline => "QUIC peek deadline exceeded",
        })
    }
}

/// Which [`QuicPeekRejection`]s reach the fallback; any other fails the association with
/// [`QuicPeekRejectedError`].
///
/// Defaults to [`Self::ALL`] for best-effort inspection and passthrough. Use
/// [`Self::NOT_QUIC`] when routing requires inspection of every QUIC ClientHello,
/// or configure each class separately. Inspection budgets still stop reading;
/// selecting fallback does not relax them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicPeekFallbackPolicy {
    pub not_quic: bool,
    pub unsupported_version: bool,
    pub malformed: bool,
    pub budget: bool,
    pub deadline: bool,
}

impl QuicPeekFallbackPolicy {
    /// Only associations that are not QUIC reach the fallback.
    pub const NOT_QUIC: Self = Self {
        not_quic: true,
        unsupported_version: false,
        malformed: false,
        budget: false,
        deadline: false,
    };

    /// Every association without a complete ClientHello reaches the fallback.
    pub const ALL: Self = Self {
        not_quic: true,
        unsupported_version: true,
        malformed: true,
        budget: true,
        deadline: true,
    };

    /// Whether `rejection` reaches the fallback.
    #[must_use]
    pub const fn admits(self, rejection: QuicPeekRejection) -> bool {
        match rejection {
            QuicPeekRejection::NotQuic => self.not_quic,
            QuicPeekRejection::UnsupportedVersion => self.unsupported_version,
            QuicPeekRejection::Malformed => self.malformed,
            QuicPeekRejection::Budget => self.budget,
            QuicPeekRejection::Deadline => self.deadline,
        }
    }
}

impl Default for QuicPeekFallbackPolicy {
    fn default() -> Self {
        Self::ALL
    }
}

/// An association refused because its peek ended in a class the fallback policy does not
/// admit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicPeekRejectedError(pub QuicPeekRejection);

impl fmt::Display for QuicPeekRejectedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QUIC ClientHello peek rejected: {}", self.0)
    }
}

impl std::error::Error for QuicPeekRejectedError {}

/// Inspects the first datagrams of a UDP association for a QUIC client's Initial flight and
/// its ClientHello, then hands the association on with those datagrams replayed in front.
///
/// A complete ClientHello goes to the inner service as [`InputWithQuicClientHello`]. Anything
/// else ends in a [`QuicPeekRejection`]: classes the [`QuicPeekFallbackPolicy`] admits go to
/// the fallback with the same datagrams intact and the rejection in the input's extensions, so
/// the fallback can still forward the association untouched; the others fail with
/// [`QuicPeekRejectedError`]. Nothing is ever sent while peeking: the decision is made before
/// any local QUIC output exists. The deadline is absolute from `serve`, and the read ahead is
/// bounded by [`CaptureLimits`]. Defaults use [`DEFAULT_QUIC_PEEK_LIMITS`] and
/// select the configured fallback for every rejection. Use
/// [`Self::with_malformed_tls_policy`] and [`Self::with_peek_timeout_policy`] for
/// the same policy controls as TCP, or [`Self::with_fallback_policy`] for per-class
/// QUIC control. The last applicable setter wins.
///
/// Both successful and fallback dispatch insert [`ClientHelloPeekStatus`], replacing
/// any earlier status. Non-QUIC input has no inspection failure. Unsupported or
/// malformed QUIC maps to `Rejected`, budget exhaustion to `MaxPeekSizeReached`,
/// and deadline expiry to `Timeout`. Receive errors always fail the service.
/// Strict routing should use [`QuicPeekFallbackPolicy::NOT_QUIC`].
///
/// Routing sees the outer ClientHello only: with ECH that is the public name, never the
/// encrypted inner one. 0-RTT in the first flight is never decrypted: it is flagged as
/// [`PeekedClientHello::early_data_observed`] and replayed untouched to a forwarding service,
/// while a terminating relay rejects it and the client resends that data after the handshake.
///
/// The fallback rejects by default; use [`Self::with_fallback`] to forward instead.
#[derive(ExtensionsRef)]
pub struct PeekQuicClientHelloService<K, S, F = RejectService<(), NoQuicRejectError>> {
    keys: K,
    inner: S,
    fallback: F,
    limits: CaptureLimits,
    peek_timeout: Duration,
    fallback_policy: QuicPeekFallbackPolicy,
    retain_first_flight: bool,
}

impl<K, S> PeekQuicClientHelloService<K, S> {
    define_inner_service_accessors!();

    /// Peek with `keys` deriving the Initial keys of the client's offered version. No
    /// certificate or server identity is needed.
    pub fn new(keys: K, inner: S) -> Self {
        Self {
            keys,
            inner,
            fallback: RejectService::new(NoQuicRejectError),
            limits: DEFAULT_QUIC_PEEK_LIMITS,
            peek_timeout: DEFAULT_QUIC_PEEK_TIMEOUT,
            fallback_policy: QuicPeekFallbackPolicy::default(),
            retain_first_flight: true,
        }
    }
}

impl<K, S, F> PeekQuicClientHelloService<K, S, F> {
    /// Hand associations the fallback policy admits to `fallback`.
    pub fn with_fallback<G>(self, fallback: G) -> PeekQuicClientHelloService<K, S, G> {
        PeekQuicClientHelloService {
            keys: self.keys,
            inner: self.inner,
            fallback,
            limits: self.limits,
            peek_timeout: self.peek_timeout,
            fallback_policy: self.fallback_policy,
            retain_first_flight: self.retain_first_flight,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Retain structural facts through the datagram completing ClientHello (default: on).
        /// A native mirror uses these facts for fresh Initial packetization and CID lengths.
        pub fn first_flight_retention(mut self, retain: bool) -> Self {
            self.retain_first_flight = retain;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bounds on datagrams, packets, bytes, CRYPTO fragments and the ClientHello.
        /// Defaults to [`DEFAULT_QUIC_PEEK_LIMITS`]. Reaching a bound stops inspection
        /// and follows the configured fallback policy.
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
        /// Whether malformed, unsupported or over-budget QUIC reaches fallback.
        /// Defaults to [`MalformedTlsPolicy::Fallback`]. This updates those three
        /// classes only; timeout and non-QUIC policy remain independent.
        pub fn malformed_tls_policy(mut self, policy: MalformedTlsPolicy) -> Self {
            let fallback = policy == MalformedTlsPolicy::Fallback;
            self.fallback_policy.malformed = fallback;
            self.fallback_policy.unsupported_version = fallback;
            self.fallback_policy.budget = fallback;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Whether an inconclusive inspection deadline selects fallback.
        /// Defaults to [`PeekTimeoutPolicy::FailOpen`]. This updates only the
        /// deadline class, independently of the malformed-TLS policy.
        pub fn peek_timeout_policy(mut self, policy: PeekTimeoutPolicy) -> Self {
            self.fallback_policy.deadline = policy == PeekTimeoutPolicy::FailOpen;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Which rejections reach the fallback. Defaults to
        /// [`QuicPeekFallbackPolicy::ALL`].
        pub fn fallback_policy(mut self, policy: QuicPeekFallbackPolicy) -> Self {
            self.fallback_policy = policy;
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
            .field("fallback_policy", &self.fallback_policy)
            .field("retain_first_flight", &self.retain_first_flight)
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
            fallback_policy: self.fallback_policy,
            retain_first_flight: self.retain_first_flight,
        }
    }
}

impl<I, K, S, F, O> Service<I> for PeekQuicClientHelloService<K, S, F>
where
    I: DatagramPeekInput,
    I::Mapped<PrefixedDatagramSocket<I::Socket>>: ExtensionsRef,
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
            let failure = peeked.as_ref().err().and_then(|reason| match reason {
                QuicPeekRejection::NotQuic => None,
                QuicPeekRejection::Malformed | QuicPeekRejection::UnsupportedVersion => {
                    Some(PeekStopReason::Rejected)
                }
                QuicPeekRejection::Budget => Some(PeekStopReason::MaxPeekSizeReached),
                QuicPeekRejection::Deadline => Some(PeekStopReason::Timeout),
            });
            match peeked {
                Ok(client_hello) => {
                    input.extensions().insert(ClientHelloPeekStatus::default());
                    self.inner
                        .serve(InputWithQuicClientHello {
                            input,
                            peeked: client_hello,
                        })
                        .await
                        .map_err(Into::into)
                }
                Err(rejection) if self.fallback_policy.admits(rejection) => {
                    input.extensions().insert(ClientHelloPeekStatus { failure });
                    input.extensions().insert(rejection);
                    self.fallback.serve(input).await.map_err(Into::into)
                }
                Err(rejection) => Err(QuicPeekRejectedError(rejection).into()),
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
    ) -> Result<Result<PeekedClientHello, QuicPeekRejection>, BoxError> {
        let mut inspector = if self.retain_first_flight {
            InitialPeek::new_with_first_flight(self.limits, deadline.into_std())
        } else {
            InitialPeek::new(self.limits, deadline.into_std())
        };
        let mut buffer = vec![0; RECEIVE_BUFFER];
        loop {
            let metadata = match timeout_at(deadline, socket.recv(&mut buffer)).await {
                Ok(received) => received?,
                Err(_elapsed) => return Ok(Err(QuicPeekRejection::Deadline)),
            };
            let payload = Bytes::copy_from_slice(&buffer[..metadata.len.min(buffer.len())]);
            retained.push(RetainedDatagram {
                payload: payload.clone(),
                metadata,
            });
            // A cut or inconsistent receive cannot be inspected, and is replayed as received.
            if let Err(error) = metadata.validate(buffer.len()) {
                tracing::debug!(%error, "QUIC ClientHello peek received an uninspectable datagram");
                return Ok(Err(QuicPeekRejection::Malformed));
            }
            for segment in metadata.segments(&payload) {
                match inspector.inspect(Instant::now().into_std(), segment, &self.keys) {
                    Ok(Some(client_hello)) => return Ok(Ok(client_hello)),
                    Ok(None) => {}
                    Err(error) => {
                        tracing::debug!(%error, "QUIC ClientHello peek ended without a ClientHello");
                        return Ok(Err(rejection(&error)));
                    }
                }
            }
        }
    }
}

fn rejection(error: &PeekError) -> QuicPeekRejection {
    match error {
        PeekError::NotClientFlight => QuicPeekRejection::NotQuic,
        PeekError::Deadline => QuicPeekRejection::Deadline,
        PeekError::Capture(CaptureError::UnknownVersion(_)) => {
            QuicPeekRejection::UnsupportedVersion
        }
        PeekError::Capture(CaptureError::LimitExceeded(_)) => QuicPeekRejection::Budget,
        PeekError::Capture(_) | PeekError::Finished => QuicPeekRejection::Malformed,
    }
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
