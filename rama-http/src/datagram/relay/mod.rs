//! Bounded, bidirectional forwarding for explicitly selected Capsule Protocol tunnels.

use rama_core::{
    Service,
    extensions::ExtensionsRef,
    io::{AbortIo, BridgeIo, Io},
};
use rama_http_types::proto::capsule::CapsuleType;
use rama_utils::guard::DropGuard;
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    DatagramTransport, HttpDatagramSession, NativeSendError, SessionConfig, SessionError,
    SessionEvent, SessionReceiver, SessionSender, capsule::UnknownCapsules,
};

/// Counts for one completed forwarding direction. Native delivery is unreliable;
/// accepting a send does not prove that the remote application received it.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DatagramRelayDirection {
    /// Datagrams accepted by the next hop, on either carrier.
    pub datagrams: u64,
    /// Non-DATAGRAM capsules forwarded, including unknown streamed types.
    pub capsules: u64,
    /// Native datagrams refused by the next hop's size or queue limit.
    pub dropped: u64,
}

/// Two independent directional outcomes; a clean half-close does not stop its sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramRelayOutcome {
    /// Traffic from the accepted client-side tunnel toward its upstream.
    pub ingress_to_egress: DatagramRelayDirection,
    /// Traffic from the upstream tunnel back toward the accepted client.
    pub egress_to_ingress: DatagramRelayDirection,
}

/// Forward a tunnel whose application explicitly selected HTTP Datagram semantics.
///
/// Reliable DATAGRAM capsules stay reliable. Native datagrams use the next hop's
/// native carrier when available and DATAGRAM capsules otherwise. Unknown capsule
/// values stream within the configured read bound; their integer headers are
/// re-encoded minimally, as by [`SessionSender::start_capsule`].
///
/// While a capsule value is in progress, native input stays in the transport's
/// bounded queue. No additional datagram queue or whole-capsule buffer is added.
/// Errors and cancellation abort both I/Os when they publish their own [`AbortIo`].
/// Ordinary byte tunnels should use `IoForwardService` instead.
#[derive(Debug, Clone)]
pub struct HttpDatagramRelay {
    config: SessionConfig,
}

impl Default for HttpDatagramRelay {
    fn default() -> Self {
        Self::new(SessionConfig::default())
    }
}

impl HttpDatagramRelay {
    /// Use the supplied read/datagram/control limits and native send policy.
    /// Unknown capsules are always forwarded, rather than skipped as at an endpoint.
    #[must_use]
    pub fn new(mut config: SessionConfig) -> Self {
        config.capsules.unknown = UnknownCapsules::Forward;
        Self { config }
    }
}

impl<L, R> Service<BridgeIo<L, R>> for HttpDatagramRelay
where
    L: Io + Unpin + ExtensionsRef,
    R: Io + Unpin + ExtensionsRef,
{
    type Output = DatagramRelayOutcome;
    type Error = SessionError;

    fn serve(
        &self,
        BridgeIo(left, right): BridgeIo<L, R>,
    ) -> impl Future<Output = Result<Self::Output, Self::Error>> + Send {
        // Reserve only each stream's own abort handle, never its parent connection's.
        // Construct the guard before the first poll so cancellation also covers setup.
        let abort_left = left.extensions().self_get_arc::<AbortIo>();
        let abort_right = right.extensions().self_get_arc::<AbortIo>();
        let mut guard = DropGuard::new(move || {
            if let Some(abort) = abort_left {
                abort.abort();
            }
            if let Some(abort) = abort_right {
                abort.abort();
            }
        });
        let config = self.config.clone();
        async move {
            let (left_send, left_receive) =
                HttpDatagramSession::with_config(left, config.clone()).split();
            let (right_send, right_receive) =
                HttpDatagramSession::with_config(right, config).split();
            let (ingress_to_egress, egress_to_ingress) = tokio::try_join!(
                forward(left_receive, right_send),
                forward(right_receive, left_send),
            )?;
            guard.disarm();
            Ok(DatagramRelayOutcome {
                ingress_to_egress,
                egress_to_ingress,
            })
        }
    }
}

async fn forward<L: AsyncRead, R: AsyncWrite>(
    mut receive: SessionReceiver<L>,
    mut send: SessionSender<R>,
) -> Result<DatagramRelayDirection, SessionError> {
    let mut result = DatagramRelayDirection::default();
    let mut remaining = 0_u64;
    loop {
        tokio::task::consume_budget().await;
        let event = if remaining == 0 {
            receive.recv().await?
        } else {
            // Reliable fallback must not splice a datagram into an opaque value.
            receive.recv_reliable().await?
        };
        let Some(event) = event else {
            send.close().await?;
            return Ok(result);
        };
        match event {
            SessionEvent::Datagram {
                payload,
                transport: DatagramTransport::Capsule,
            } => {
                send.send_capsule(CapsuleType::DATAGRAM, payload).await?;
                result.datagrams = result.datagrams.saturating_add(1);
            }
            SessionEvent::Datagram {
                payload,
                transport: DatagramTransport::Native,
            } => {
                match send.send_datagram(payload).await {
                    Ok(_) => result.datagrams = result.datagrams.saturating_add(1),
                    // Native delivery permits loss. Do not convert an oversize
                    // or queue-refused native send into reliable delivery.
                    Err(SessionError::Native(
                        NativeSendError::TooLarge { .. } | NativeSendError::Full,
                    )) => {
                        result.dropped = result.dropped.saturating_add(1);
                    }
                    Err(error) => return Err(error),
                }
            }
            SessionEvent::Capsule { ty, value } => {
                send.send_capsule(ty, value).await?;
                result.capsules = result.capsules.saturating_add(1);
            }
            SessionEvent::UnknownCapsule(header) => {
                remaining = header.length.into_inner();
                send.start_capsule(header).await?;
                result.capsules = result.capsules.saturating_add(1);
            }
            SessionEvent::UnknownCapsuleData(chunk) => {
                remaining = remaining
                    .checked_sub(chunk.len() as u64)
                    .ok_or(SessionError::CapsuleLengthMismatch)?;
                send.send_capsule_data(chunk).await?;
            }
            // Too large for this side to deliver: lost like any oversized datagram.
            SessionEvent::OversizedDatagram { .. } => {
                result.dropped = result.dropped.saturating_add(1);
            }
        }
    }
}

#[cfg(test)]
mod tests;
