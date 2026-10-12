//! Bounded forwarding between two separately authenticated QUIC connections.
//!
//! Each peer can initiate uni- and bidirectional streams. The relay preserves
//! stream bytes, FIN, reset and stop codes; it creates new stream identifiers and
//! does not translate identifiers embedded in application data. Protocols such as
//! HTTP/3 require their own protocol-aware relay. Packet layout, ACKs, secrets,
//! congestion state and timing belong to each independent connection.

use std::{
    future::{Future, pending},
    num::NonZeroUsize,
    pin::pin,
};

use rama_core::{
    error::{BoxError, BoxErrorExt as _},
    futures::{StreamExt as _, stream::FuturesUnordered},
};
use rama_quic_proto::{Side, VarInt};

use crate::{Connection, ConnectionError, ReadError, RecvStream, SendStream, WriteError};

/// Resource and cancellation policy for one pair of dedicated connections.
#[derive(Debug, Clone, Copy)]
pub struct RelayConfig {
    /// Maximum active or opening streams in each initiator/direction class.
    /// There are four classes, so the total is at most four times this value.
    pub streams_per_class: NonZeroUsize,
    /// Maximum bytes retained by each copy direction outside the QUIC engine.
    pub chunk_bytes: NonZeroUsize,
    /// Forward connection datagrams in both directions. Both hops must negotiate
    /// reception; an oversized datagram fails explicitly rather than truncating.
    pub datagrams: bool,
    /// Application error used when the relay itself fails or is cancelled.
    /// A peer's application close is forwarded with its original code and reason.
    pub failure_code: VarInt,
}

impl RelayConfig {
    /// Relay dedicated, established connections until either connection ends.
    ///
    /// `downstream` is a server connection and `upstream` a client connection.
    /// Both hops must negotiate the same nonempty ALPN. Do not consume their
    /// streams or datagrams concurrently elsewhere. Configure receive datagram
    /// advertisements to match this policy before establishing either hop. Neither
    /// hop may have enabled early-data keys: this generic relay does not decide
    /// application replay safety. Configure TLS early data off on both hops.
    ///
    /// Dropping this future closes both connections, including streams waiting
    /// for remote credit. Connection-level transport errors are returned locally
    /// and mapped to `failure_code` on the other hop; they are not fabricated as
    /// transport errors belonging to that independent connection.
    pub fn relay(
        self,
        downstream: Connection,
        upstream: Connection,
    ) -> impl Future<Output = Result<(), BoxError>> + Send {
        let guard = CloseOnDrop {
            downstream,
            upstream,
            code: self.failure_code,
        };
        // Own cancellation before the returned future is polled for the first time.
        async move { self.run(guard).await }
    }

    async fn run(self, guard: CloseOnDrop) -> Result<(), BoxError> {
        let down = &guard.downstream;
        let up = &guard.upstream;
        if down.side() != Side::Server || up.side() != Side::Client {
            return Err(BoxError::from_static_str(
                "QUIC relay needs a server and a client connection",
            ));
        }
        tokio::try_join!(down.handshake_confirmed(), up.handshake_confirmed())?;
        let down_alpn = down
            .handshake_data()
            .and_then(|tls| tls.application_layer_protocol)
            .filter(|protocol| !protocol.as_bytes().is_empty());
        let up_alpn = up
            .handshake_data()
            .and_then(|tls| tls.application_layer_protocol)
            .filter(|protocol| !protocol.as_bytes().is_empty());
        if down_alpn.is_none() || down_alpn != up_alpn {
            return Err(BoxError::from_static_str(
                "QUIC relay negotiated application protocols differ or are absent",
            ));
        }
        if down.early_data_keys_enabled() || up.early_data_keys_enabled() {
            return Err(BoxError::from_static_str(
                "QUIC relay requires early data disabled",
            ));
        }
        if self.datagrams
            && [down, up]
                .iter()
                .any(|conn| !conn.datagram_receive_enabled() || conn.max_datagram_size().is_none())
        {
            return Err(BoxError::from_static_str(
                "QUIC relay datagram capability mismatch",
            ));
        }

        if !self.datagrams
            && [down, up]
                .iter()
                .any(|conn| conn.datagram_receive_enabled())
        {
            return Err(BoxError::from_static_str(
                "QUIC relay disabled datagrams were advertised",
            ));
        }

        // Each stream class has its own bounded work set. Waiting for outbound
        // credit never stops existing copies or the other initiator's accepts.
        tokio::select! {
            result = async {
                tokio::try_join!(
                    self.unidirectional(down, up),
                    self.unidirectional(up, down),
                    self.bidirectional(down, up),
                    self.bidirectional(up, down),
                    self.forward_datagrams(down, up),
                    self.forward_datagrams(up, down),
                )?;
                Ok(())
            } => {
                // A stream can observe the same peer close before closed() is
                // polled. Preserve its application code in either scheduling order.
                if let Some(reason) = down.close_reason() {
                    propagate_close(up, reason, self.failure_code)
                } else if let Some(reason) = up.close_reason() {
                    propagate_close(down, reason, self.failure_code)
                } else {
                    result
                }
            },
            reason = down.closed() => propagate_close(up, reason, self.failure_code),
            reason = up.closed() => propagate_close(down, reason, self.failure_code),
        }
    }

    async fn unidirectional(self, from: &Connection, to: &Connection) -> Result<(), BoxError> {
        let mut work = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = from.accept_uni(), if work.len() < self.streams_per_class.get() => {
                    let mut recv = accepted?;
                    work.push(async move {
                        let send = tokio::select! {
                            opened = to.open_uni() => opened?,
                            reset = recv.received_reset() => {
                                if reset?.is_some() {
                                    return Ok(());
                                }
                                to.open_uni().await?
                            }
                        };
                        copy(recv, send, self.chunk_bytes).await
                    });
                }
                Some(result) = work.next(), if !work.is_empty() => result?,
            }
        }
    }

    async fn bidirectional(self, from: &Connection, to: &Connection) -> Result<(), BoxError> {
        let mut work = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = from.accept_bi(), if work.len() < self.streams_per_class.get() => {
                    let (send, recv) = accepted?;
                    work.push(relay_bidi(recv, send, to, self.chunk_bytes));
                }
                Some(result) = work.next(), if !work.is_empty() => result?,
            }
        }
    }

    async fn forward_datagrams(self, from: &Connection, to: &Connection) -> Result<(), BoxError> {
        if !self.datagrams {
            return pending().await;
        }
        loop {
            let datagram = from.read_datagram().await?;
            // Backpressure retains at most one datagram here; the engine's own
            // negotiated receive budget bounds the remaining unreliable queue.
            to.send_datagram_wait(datagram).await?;
        }
    }
}

struct CloseOnDrop {
    downstream: Connection,
    upstream: Connection,
    code: VarInt,
}

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.downstream.close(self.code, b"QUIC relay ended");
        self.upstream.close(self.code, b"QUIC relay ended");
    }
}

fn propagate_close(
    to: &Connection,
    reason: ConnectionError,
    fallback: VarInt,
) -> Result<(), BoxError> {
    if let ConnectionError::ApplicationClosed(close) = &reason {
        to.close(close.error_code, &close.reason);
    } else {
        to.close(fallback, b"QUIC relay peer failed");
    }
    Err(reason.into())
}

async fn relay_bidi(
    mut recv: RecvStream,
    send: SendStream,
    to: &Connection,
    maximum: NonZeroUsize,
) -> Result<(), BoxError> {
    let mut request_reset = None;
    let mut response_stopped = None;
    let mut watch_reset = true;
    let (mut other_send, mut other_recv) = {
        let mut stopped = pin!(send.stopped());
        loop {
            // A single cancelled direction still leaves the other one meaningful.
            // When both end before credit arrives, release this pending relay slot.
            if request_reset.is_some() && response_stopped.is_some() {
                return Ok(());
            }
            tokio::select! {
                opened = to.open_bi() => break opened?,
                reset = recv.received_reset(), if watch_reset => {
                    request_reset = reset?;
                    watch_reset = false;
                }
                stopped = &mut stopped, if response_stopped.is_none() => {
                    response_stopped = stopped?;
                    if response_stopped.is_none() {
                        return Err(BoxError::from_static_str("relay send ended before opening its peer stream"));
                    }
                }
            }
        }
    };

    // One direction resetting does not discard data still valid in the other.
    tokio::try_join!(
        async {
            if let Some(code) = request_reset {
                let _already_closed = other_send.reset(code);
                Ok(())
            } else {
                copy(recv, other_send, maximum).await
            }
        },
        async {
            if let Some(code) = response_stopped {
                let _already_closed = other_recv.stop(code);
                Ok(())
            } else {
                copy(other_recv, send, maximum).await
            }
        },
    )?;
    Ok(())
}

async fn copy(
    mut from: RecvStream,
    mut to: SendStream,
    maximum: NonZeroUsize,
) -> Result<(), BoxError> {
    // A fixed buffer gives this copy an exact retention bound. A short slice
    // from read_chunk could otherwise keep a larger shared packet allocation alive.
    let mut buffer = vec![0; maximum.get()];
    let mut stopped = pin!(to.stopped());
    loop {
        let next = tokio::select! {
            next = from.read(&mut buffer) => next,
            stopped = &mut stopped => {
                if let Some(code) = stopped? {
                    let _already_closed = from.stop(code);
                }
                return Ok(());
            }
        };
        let read = match next {
            Ok(Some(read)) => read,
            Ok(None) => {
                to.finish()?;
                if let Some(code) = stopped.await? {
                    let _already_closed = from.stop(code);
                }
                return Ok(());
            }
            Err(ReadError::Reset(code)) => {
                let _already_closed = to.reset(code);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };

        // A stop wakes a direction even while no input arrives or its write is
        // blocked by flow control. Forward the peer's code without translation.
        let written = {
            let mut write = pin!(to.write_all(&buffer[..read]));
            let mut watch_reset = true;
            loop {
                tokio::select! {
                    written = &mut write => break Ok(written),
                    reset = from.received_reset(), if watch_reset => {
                        match reset? {
                            Some(code) => break Err(code),
                            None => watch_reset = false,
                        }
                    }
                    stopped = &mut stopped => {
                        if let Some(code) = stopped? {
                            let _already_closed = from.stop(code);
                        }
                        return Ok(());
                    }
                }
            }
        };
        let written = match written {
            Ok(written) => written,
            Err(code) => {
                let _already_closed = to.reset(code);
                return Ok(());
            }
        };
        match written {
            Ok(()) => {}
            Err(WriteError::Stopped(code)) => {
                let _already_closed = from.stop(code);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
    }
}

#[cfg(all(
    test,
    any(
        feature = "boring",
        all(feature = "rustls", any(feature = "aws-lc", feature = "ring"))
    )
))]
mod tests;
