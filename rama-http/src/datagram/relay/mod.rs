//! Bounded, bidirectional forwarding for explicitly selected Capsule Protocol tunnels.

use rama_core::{
    Service,
    extensions::ExtensionsRef,
    graceful::{Scope, WeakScope},
    io::{AbortIo, BridgeIo, Io},
};
use rama_http_types::proto::capsule::CapsuleType;
use rama_utils::guard::DropGuard;
use std::{io, pin::pin, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{sync::watch, time::Instant};

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
/// Reliable DATAGRAM capsules stay reliable unless [`Self::with_prefer_native`]
/// is set. Native datagrams use the next hop's native carrier when available and
/// DATAGRAM capsules otherwise. Unknown capsule values stream within the configured
/// read bound; their integer headers are re-encoded minimally, as by
/// [`SessionSender::start_capsule`].
///
/// While a capsule value is in progress, native input stays in the transport's
/// bounded queue. No additional datagram queue or whole-capsule buffer is added.
/// A closed destination ends only its sending direction; its sibling can drain.
/// By default, inactivity ends a relay after two minutes, and once the input of one
/// direction ended the relay has five seconds to finish, the close of that direction
/// included: a peer that never lets a close end does not hold the relay. Both deadlines
/// are configurable.
/// Other errors and cancellation abort both I/Os when they publish their own [`AbortIo`].
/// Ordinary byte tunnels should use `IoForwardService` instead.
#[derive(Debug, Clone)]
pub struct HttpDatagramRelay {
    config: SessionConfig,
    idle_timeout: Option<Duration>,
    close_timeout: Option<Duration>,
    prefer_native: bool,
    scope: WeakScope,
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
        Self {
            config,
            idle_timeout: Some(Duration::from_mins(2)),
            close_timeout: Some(Duration::from_secs(5)),
            prefer_native: false,
            scope: WeakScope::detached(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound inactivity across both directions. Successful forwarding resets it;
        /// discarded datagrams do not. Defaults to two minutes; `None` disables it.
        pub fn idle_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.idle_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound what is left of the relay once the input of one direction ended: the
        /// close of that direction and the remaining one. Defaults to five seconds;
        /// `None` allows it to drain without a close deadline.
        pub fn close_timeout(mut self, timeout: Option<Duration>) -> Self {
            self.close_timeout = timeout;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Forward DATAGRAM capsules on the next hop's native carrier when available,
        /// dropping them like native datagrams when it refuses them. RFC 9297 §3.5
        /// allows this re-encoding, which can lose or reorder datagrams.
        /// Defaults to `false`.
        pub fn prefer_native(mut self, prefer: bool) -> Self {
            self.prefer_native = prefer;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Stop both streams at this scope's hard phase; they keep relaying through its graceful
        /// phase. A relay that is closing holds the scope until it finished.
        pub fn scope(mut self, scope: impl Into<WeakScope>) -> Self {
            self.scope = scope.into();
            self
        }
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
        let idle_timeout = self.idle_timeout;
        let close_timeout = self.close_timeout;
        let prefer_native = self.prefer_native;
        let scope = self.scope.clone();
        async move {
            let (left_send, left_receive) =
                HttpDatagramSession::with_config(left, config.clone()).split();
            let (right_send, right_receive) =
                HttpDatagramSession::with_config(right, config).split();
            let (progress, observed) = if idle_timeout.is_some() {
                let (progress, observed) = watch::channel(Instant::now());
                (Some(progress), Some(observed))
            } else {
                (None, None)
            };
            let exchange = exchange(
                &scope,
                close_timeout,
                forward(left_receive, right_send, prefer_native, progress.clone()),
                forward(right_receive, left_send, prefer_native, progress),
            );
            let (ingress_to_egress, egress_to_ingress) = tokio::select! {
                result = exchange => result?,
                () = idle(observed, idle_timeout) => return Err(SessionError::Io(io::Error::new(io::ErrorKind::TimedOut, "datagram relay idle timeout"))),
                // Datagrams cannot drain: the relay runs through the graceful phase.
                () = scope.aborted() => return Err(SessionError::Io(io::Error::new(io::ErrorKind::Interrupted, "datagram relay shutdown"))),
            };
            guard.disarm();
            Ok(DatagramRelayOutcome {
                ingress_to_egress,
                egress_to_ingress,
            })
        }
    }
}

async fn idle(progress: Option<watch::Receiver<Instant>>, timeout: Option<Duration>) {
    let (Some(mut progress), Some(timeout)) = (progress, timeout) else {
        return std::future::pending().await;
    };
    loop {
        let deadline = *progress.borrow_and_update() + timeout;
        if tokio::time::timeout_at(deadline, progress.changed())
            .await
            .is_err()
        {
            return;
        }
        if progress.has_changed().is_err() {
            return std::future::pending().await;
        }
    }
}

/// The halves of a direction whose input ended, its output still to close.
type Ended<L, R> = Option<(SessionReceiver<L>, SessionSender<R>)>;

/// What a direction forwarded until its input ended.
type Forwarded<L, R> = Result<(DatagramRelayDirection, Ended<L, R>), SessionError>;

/// Run both directions; the first input to end starts the close of the relay.
async fn exchange<L: AsyncWrite, R: AsyncWrite>(
    scope: &WeakScope,
    close_timeout: Option<Duration>,
    ingress: impl Future<Output = Forwarded<L, R>>,
    egress: impl Future<Output = Forwarded<R, L>>,
) -> Result<(DatagramRelayDirection, DatagramRelayDirection), SessionError> {
    let mut ingress = pin!(ingress);
    let mut egress = pin!(egress);
    tokio::select! {
        ended = &mut ingress => {
            let (ingress, ended) = ended?;
            let egress = close(scope, close_timeout, ended, egress).await?;
            Ok((ingress, egress))
        }
        ended = &mut egress => {
            let (egress, ended) = ended?;
            let ingress = close(scope, close_timeout, ended, ingress).await?;
            Ok((ingress, egress))
        }
    }
}

/// Close the direction that `ended` and run the `other` one to its own close, in a scope
/// below `scope` that is aborted once `timeout` passed: whichever hard phase comes first
/// ends what a peer still holds.
async fn close<L, R, OL, OR>(
    scope: &WeakScope,
    timeout: Option<Duration>,
    ended: Ended<L, R>,
    other: impl Future<Output = Forwarded<OL, OR>>,
) -> Result<DatagramRelayDirection, SessionError>
where
    R: AsyncWrite,
    OR: AsyncWrite,
{
    // A closed scope takes no holder: the close then runs below no parent.
    let closing = scope
        .try_hold()
        .unwrap_or_else(|_closed| Scope::detached())
        .child()
        .maybe_with_hard_timeout(timeout);
    let closed = closing
        .run_until_aborted(async {
            tokio::try_join!(finish(ended), async {
                let (direction, ended) = other.await?;
                finish(ended).await?;
                Ok(direction)
            })
        })
        .await;
    match closed {
        Some(closed) => closed.map(|((), direction)| direction),
        None if scope.is_aborted() => Err(SessionError::Io(io::Error::new(
            io::ErrorKind::Interrupted,
            "datagram relay shutdown",
        ))),
        None => Err(SessionError::Io(io::Error::new(
            io::ErrorKind::TimedOut,
            "datagram relay close timeout",
        ))),
    }
}

/// End the output of a direction; a destination that closed before is no error.
async fn finish<L, R: AsyncWrite>(ended: Ended<L, R>) -> Result<(), SessionError> {
    let Some((_receive, mut send)) = ended else {
        return Ok(());
    };
    match send.close().await {
        Ok(()) => Ok(()),
        Err(error) if error.is_send_closed() => Ok(()),
        Err(error) => Err(error),
    }
}

/// Forward one direction until its input ends, which leaves its halves to [`finish`], or
/// its destination closed.
async fn forward<L: AsyncRead, R: AsyncWrite>(
    mut receive: SessionReceiver<L>,
    mut send: SessionSender<R>,
    prefer_native: bool,
    progress: Option<watch::Sender<Instant>>,
) -> Result<(DatagramRelayDirection, Ended<L, R>), SessionError> {
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
            return Ok((result, Some((receive, send))));
        };
        let sent =
            forward_event(&mut send, event, prefer_native, &mut result, &mut remaining).await;
        match sent {
            Ok(false) => continue,
            Ok(true) => (),
            Err(error) if error.is_send_closed() => return Ok((result, None)),
            Err(error) => return Err(error),
        }
        if let Some(progress) = &progress {
            progress.send_replace(Instant::now());
        }
    }
}

async fn forward_event<R: AsyncWrite>(
    send: &mut SessionSender<R>,
    event: SessionEvent,
    prefer_native: bool,
    result: &mut DatagramRelayDirection,
    remaining: &mut u64,
) -> Result<bool, SessionError> {
    match event {
        SessionEvent::Datagram {
            payload,
            transport: DatagramTransport::Capsule,
        } if !prefer_native => {
            send.send_capsule(CapsuleType::DATAGRAM, payload).await?;
            result.datagrams = result.datagrams.saturating_add(1);
        }
        SessionEvent::Datagram { payload, .. } => {
            match send.send_datagram(payload).await {
                Ok(_) => result.datagrams = result.datagrams.saturating_add(1),
                // Native delivery permits loss. Do not convert an oversize
                // or queue-refused native send into reliable delivery.
                Err(SessionError::Native(
                    NativeSendError::TooLarge { .. } | NativeSendError::Full,
                )) => {
                    result.dropped = result.dropped.saturating_add(1);
                    return Ok(false);
                }
                Err(error) => return Err(error),
            }
        }
        SessionEvent::Capsule { ty, value } => {
            send.send_capsule(ty, value).await?;
            result.capsules = result.capsules.saturating_add(1);
        }
        SessionEvent::UnknownCapsule(header) => {
            *remaining = header.length.into_inner();
            send.start_capsule(header).await?;
            result.capsules = result.capsules.saturating_add(1);
        }
        SessionEvent::UnknownCapsuleData(chunk) => {
            *remaining = remaining
                .checked_sub(chunk.len() as u64)
                .ok_or(SessionError::CapsuleLengthMismatch)?;
            send.send_capsule_data(chunk).await?;
        }
        // Too large for this side to deliver: lost like any oversized datagram.
        SessionEvent::OversizedDatagram { .. } => {
            result.dropped = result.dropped.saturating_add(1);
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
