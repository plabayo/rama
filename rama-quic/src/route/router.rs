use std::{collections::VecDeque, future::Future, num::NonZeroUsize, sync::Arc, time::Duration};

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_net::address::{SocketAddress, ip::IntoCanonicalIpAddr as _};
use rama_quic_proto::{
    capture::{CaptureError, CaptureLimits, KeyProvider},
    peek::{InitialPeek, PeekError, PeekedClientHello},
};
use rama_udp::{
    DatagramError, DatagramFeature, DatagramMetadata, DatagramSocket, DatagramSocketExt as _,
};
use tokio::time::{Instant, timeout_at};

use super::{
    Admission, AssociationKey,
    socket::{AssociationSocket, BufferedDatagram},
};

/// Routing context supplied by the listener/application, never inferred from
/// a ClientHello. The approved egress is independent of the visible SNI.
#[derive(Debug, Clone, Copy)]
pub struct RouteContext {
    /// Fixed local/peer tuple admitted by the listener.
    pub key: AssociationKey,
    /// Original destination supplied by trusted transparent-socket metadata.
    pub original_destination: Option<SocketAddress>,
    /// Independently approved physical destination for the egress leg.
    pub egress: SocketAddress,
}

/// Inspection facts available to policy. An outer ECH ClientHello is not the
/// hidden name, and offered ALPN is not evidence of negotiated HTTP/3.
#[derive(Debug)]
pub enum Inspection {
    /// Complete visible ClientHello from the bounded Initial packet prefix.
    ClientHello(PeekedClientHello),
    /// Inspection could not establish a complete supported ClientHello.
    Inconclusive(PeekError),
}

/// The only point at which interception versus untouched forwarding is chosen.
#[derive(Debug)]
pub enum Decision<Handler> {
    /// Commit this association to interception by the selected handler.
    Intercept(Handler),
    /// Preserve the received datagrams and forward without terminating QUIC.
    Forward,
    /// Close the association without generating QUIC output.
    Reject,
}

/// A committed routing decision. Interception has no fallback transition.
/// Construct the QUIC endpoint only from the selected interception socket.
#[derive(Debug)]
pub enum Routed<S, Handler> {
    Intercept {
        socket: AssociationSocket<S>,
        context: RouteContext,
        handler: Handler,
    },
    Forward {
        socket: AssociationSocket<S>,
        context: RouteContext,
    },
    Rejected,
}

/// Limits for the whole pending decision, and the selected fixed-path socket.
#[derive(Debug, Clone, Copy)]
pub struct RouterConfig {
    /// Bounds on retained Initial bytes, datagrams and decoded handshake data.
    pub capture: CaptureLimits,
    /// Maximum bytes in one receive descriptor, including a possible GRO group.
    pub receive_bytes: NonZeroUsize,
    /// Absolute budget for collecting and inspecting the Initial prefix.
    pub inspect_timeout: Duration,
    /// Additional policy time after the absolute inspection deadline.
    pub policy_timeout: Duration,
    /// Inactivity on the ingress receive path closes the association.
    pub idle_timeout: Duration,
}

/// Opt-in classification before any endpoint-generated QUIC output.
#[derive(Debug, Clone)]
pub struct QuicPeekRouter {
    admission: Admission,
    config: RouterConfig,
}

impl QuicPeekRouter {
    pub fn new(admission: Admission, config: RouterConfig) -> Result<Self, BoxError> {
        let now = Instant::now();
        if config.inspect_timeout.is_zero()
            || config.policy_timeout.is_zero()
            || config.idle_timeout.is_zero()
            || config.receive_bytes.get() > config.capture.bytes
            || now
                .checked_add(config.inspect_timeout)
                .and_then(|end| end.checked_add(config.policy_timeout))
                .is_none()
            || now.checked_add(config.idle_timeout).is_none()
        {
            return Err(BoxError::from_static_str("invalid QUIC router bounds"));
        }
        Ok(Self { admission, config })
    }

    /// Consume one dedicated fixed-peer socket. No sender or QUIC endpoint is
    /// created before policy commits. Cancellation drops the socket, retained
    /// prefix and permit. The policy owns only immutable parsed metadata.
    ///
    /// The listener must isolate this tuple from all other traffic. This router
    /// rejects peer/local-address changes; CID matches never authorize migration.
    /// It does not demultiplex a shared listening socket by untrusted CIDs.
    pub async fn route<S, K, Policy, Pending, Handler>(
        &self,
        mut socket: S,
        mut context: RouteContext,
        keys: &K,
        policy: Policy,
    ) -> Result<Routed<S, Handler>, BoxError>
    where
        S: DatagramSocket,
        K: KeyProvider,
        Policy: FnOnce(Arc<Inspection>, RouteContext) -> Pending,
        Pending: Future<Output = Decision<Handler>>,
    {
        context.key.ingress = context.key.ingress.into_canonical_ip_addr();
        context.key.peer = context.key.peer.into_canonical_ip_addr();
        context.egress = context.egress.into_canonical_ip_addr();
        context.original_destination = context
            .original_destination
            .map(|address| address.into_canonical_ip_addr());
        let local = socket.local_addr()?.into_canonical_ip_addr();
        if context.key.ingress.ip_addr.is_unspecified() || local.port != context.key.ingress.port {
            return Err(BoxError::from_static_str(
                "QUIC route requires a concrete ingress destination",
            ));
        }
        if local.ip_addr != context.key.ingress.ip_addr && !socket.capabilities().send_source_ip {
            return Err(DatagramError::Unsupported(DatagramFeature::SendSourceIp).into());
        }
        let permit = self.admission.try_acquire(context.key)?;
        if !socket.capabilities().receive_truncation {
            return Err(DatagramError::Unsupported(DatagramFeature::ReceiveTruncation).into());
        }
        let now = Instant::now();
        let inspect_end = now
            .checked_add(self.config.inspect_timeout)
            .ok_or_else(|| BoxError::from_static_str("inspection deadline overflow"))?;
        let policy_end = inspect_end
            .checked_add(self.config.policy_timeout)
            .ok_or_else(|| BoxError::from_static_str("policy deadline overflow"))?;
        let mut inspector = InitialPeek::new(self.config.capture, inspect_end.into_std());
        let mut prefix = VecDeque::new();
        let mut retained = 0usize;
        let mut datagrams = 0usize;
        let mut buffer = vec![0; self.config.receive_bytes.get()];

        let inspection = loop {
            if retained >= self.config.capture.bytes || datagrams >= self.config.capture.datagrams {
                break Inspection::Inconclusive(PeekError::Capture(CaptureError::LimitExceeded(
                    "router prefix",
                )));
            }
            let metadata = match timeout_at(inspect_end, socket.recv(&mut buffer)).await {
                Ok(result) => result?,
                Err(_elapsed) => break Inspection::Inconclusive(PeekError::Deadline),
            };
            validate_metadata(&context, &metadata, buffer.len())?;
            let count = metadata.segment_count();
            if metadata.len > self.config.capture.bytes - retained
                || count > self.config.capture.datagrams - datagrams
            {
                // This descriptor cannot be retained faithfully. Do not offer
                // forwarding of only the prefix that happened to fit.
                return Err(BoxError::from_static_str(
                    "QUIC router retained prefix budget exceeded",
                ));
            }
            retained += metadata.len;
            datagrams += count;
            let payload = buffer[..metadata.len].to_vec();
            let stride = metadata
                .segment_size
                .map_or(payload.len().max(1), NonZeroUsize::get);
            let mut outcome = None;
            if payload.is_empty() {
                outcome = Some(Inspection::Inconclusive(PeekError::NotClientFlight));
            } else {
                for datagram in payload.chunks(stride) {
                    match inspector.inspect(Instant::now().into_std(), datagram, keys) {
                        Ok(Some(hello)) => {
                            outcome = Some(Inspection::ClientHello(hello));
                            break;
                        }
                        Ok(None) => {}
                        Err(error) => {
                            outcome = Some(Inspection::Inconclusive(error));
                            break;
                        }
                    }
                }
            }
            prefix.push_back(BufferedDatagram { payload, metadata });
            if let Some(outcome) = outcome {
                break outcome;
            }
        };

        let decision = timeout_at(policy_end, policy(Arc::new(inspection), context))
            .await
            .map_err(|_elapsed| {
                BoxError::from_static_str("QUIC routing policy deadline exceeded")
            })?;
        match decision {
            Decision::Reject => Ok(Routed::Rejected),
            Decision::Forward => Ok(Routed::Forward {
                socket: AssociationSocket::new(
                    socket,
                    context,
                    permit,
                    prefix,
                    self.config.idle_timeout,
                ),
                context,
            }),
            Decision::Intercept(handler) => Ok(Routed::Intercept {
                socket: AssociationSocket::new(
                    socket,
                    context,
                    permit,
                    prefix,
                    self.config.idle_timeout,
                ),
                context,
                handler,
            }),
        }
    }
}

pub(super) fn validate_metadata(
    context: &RouteContext,
    metadata: &DatagramMetadata,
    capacity: usize,
) -> Result<(), BoxError> {
    if metadata.truncated || metadata.len > capacity || metadata.original_len != metadata.len {
        return Err(BoxError::from_static_str(
            "QUIC route received truncated or invalid datagram",
        ));
    }
    if metadata
        .segment_size
        .is_some_and(|size| metadata.len == 0 || size.get() > metadata.len)
    {
        return Err(BoxError::from_static_str(
            "QUIC route received invalid GRO metadata",
        ));
    }
    if metadata.peer.into_canonical_ip_addr() != context.key.peer
        || metadata.local.into_canonical_ip_addr() != context.key.ingress
        || context.original_destination.is_some_and(|expected| {
            metadata
                .original_destination
                .map(|address| address.into_canonical_ip_addr())
                != Some(expected)
        })
    {
        return Err(BoxError::from_static_str(
            "QUIC route trusted association changed",
        ));
    }
    Ok(())
}
