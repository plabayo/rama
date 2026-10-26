//! Bounded, bidirectional forwarding for explicitly selected Capsule Protocol tunnels.

use rama_core::{
    Service,
    extensions::ExtensionsRef,
    io::{AbortIo, BridgeIo, Io},
    rt::Executor,
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
    idle_timeout: Option<Duration>,
    close_timeout: Option<Duration>,
    exec: Executor,
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
            idle_timeout: None,
            close_timeout: None,
            exec: Executor::new(),
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound inactivity across both directions. Successful forwarding resets it;
        /// discarded datagrams do not. By default there is no idle timeout.
        pub fn idle_timeout(mut self, timeout: Duration) -> Self {
            self.idle_timeout = Some(timeout);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound the remaining direction after a clean half-close. By default
        /// both directions may drain independently without a deadline.
        pub fn close_timeout(mut self, timeout: Duration) -> Self {
            self.close_timeout = Some(timeout);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Abort both streams when this executor's graceful shutdown begins.
        pub fn executor(mut self, exec: Executor) -> Self {
            self.exec = exec;
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
        let exec = self.exec.clone();
        async move {
            let (left_send, left_receive) =
                HttpDatagramSession::with_config(left, config.clone()).split();
            let (right_send, right_receive) =
                HttpDatagramSession::with_config(right, config).split();
            let (progress, observed) = watch::channel(Instant::now());
            let exchange = async {
                let mut to_egress = pin!(forward(left_receive, right_send, progress.clone()));
                let mut to_ingress = pin!(forward(right_receive, left_send, progress));
                tokio::select! {
                    result = &mut to_egress => Ok::<_, SessionError>((result?, drain(to_ingress, close_timeout).await?)),
                    result = &mut to_ingress => {
                        let result = result?;
                        Ok((drain(to_egress, close_timeout).await?, result))
                    },
                }
            };
            let (ingress_to_egress, egress_to_ingress) = tokio::select! {
                result = exchange => result?,
                () = idle(observed, idle_timeout) => return Err(SessionError::Io(io::Error::new(io::ErrorKind::TimedOut, "datagram relay idle timeout"))),
                () = async {
                    match exec.guard() {
                        Some(guard) => guard.cancelled().await,
                        None => std::future::pending().await,
                    }
                } => return Err(SessionError::Io(io::Error::new(io::ErrorKind::Interrupted, "datagram relay shutdown"))),
            };
            guard.disarm();
            Ok(DatagramRelayOutcome {
                ingress_to_egress,
                egress_to_ingress,
            })
        }
    }
}

async fn drain<T>(
    future: impl Future<Output = Result<T, SessionError>>,
    timeout: Option<Duration>,
) -> Result<T, SessionError> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, future)
            .await
            .map_err(|_elapsed| {
                SessionError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "datagram relay close timeout",
                ))
            })?,
        None => future.await,
    }
}

async fn idle(mut progress: watch::Receiver<Instant>, timeout: Option<Duration>) {
    let Some(timeout) = timeout else {
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

async fn forward<L: AsyncRead, R: AsyncWrite>(
    mut receive: SessionReceiver<L>,
    mut send: SessionSender<R>,
    progress: watch::Sender<Instant>,
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
                        continue;
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
                continue;
            }
        }
        progress.send_replace(Instant::now());
    }
}

#[cfg(test)]
mod tests;
