//! HTTP/3 datagram association and demultiplexing (RFC 9297 §2.1).
//!
//! The connection driver is the only reader of QUIC DATAGRAM frames. It splits the Quarter
//! Stream ID prefix (sharing the frame's storage) and files each payload under its request
//! stream: a claimed association's bounded queue, a short-lived pending ring for streams that
//! are not associated yet, or nowhere once the stream's receive side closed.

use super::{Error, connection::Shared};
use ahash::HashMap;
use rama_core::bytes::{BufMut as _, Bytes, BytesMut};
use rama_http::datagram::{
    NativeDatagramChannel, NativeRecvError, NativeSendError, NativeSendPolicy,
};
use rama_http_types::proto::{
    ext::Protocol,
    h3::{Code, QuarterStreamId},
};
use rama_quic::{Connection as QuicConnection, SendDatagramError};
use rama_quic_proto::{Dir, Side, StreamId, VarInt};
use rama_utils::octets::kib;
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::Instant;

/// Buffering budgets for received HTTP/3 datagrams.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramLimits {
    /// Datagrams queued per association; the oldest is discarded when it is full.
    pub queue_len: usize,
    /// Datagrams held briefly for request streams that are not associated yet.
    pub pending_len: usize,
    /// Received payload bytes buffered per connection across all associations.
    pub max_buffered_bytes: usize,
}

impl Default for DatagramLimits {
    fn default() -> Self {
        Self {
            queue_len: 32,
            pending_len: 16,
            max_buffered_bytes: kib(256),
        }
    }
}

/// Pending datagrams wait "on the order of a round trip" (RFC 9297 §2.1); this floor keeps
/// very short RTT estimates from discarding datagrams that merely beat their HEADERS.
const PENDING_LIFETIME_FLOOR: Duration = Duration::from_millis(100);
const PENDING_LIFETIME_RTTS: u32 = 3;

/// Whether an Extended CONNECT protocol can own datagrams. RFC 9220 WebSockets define no
/// datagram semantics; ordinary requests and plain CONNECT never get an association.
pub(crate) fn claims_datagrams(protocol: &Protocol) -> bool {
    *protocol != Protocol::WEBSOCKET
}

struct Slot {
    queue: VecDeque<Bytes>,
    waker: Option<Waker>,
    dropped: u64,
    receive_open: bool,
}

struct Pending {
    stream: u64,
    payload: Bytes,
    expires: Instant,
}

/// Connection-wide datagram routing state, guarded by one short-held lock.
#[derive(Default)]
pub(crate) struct Demux {
    slots: HashMap<u64, Slot>,
    pending: VecDeque<Pending>,
    buffered: usize,
    dropped: u64,
    closed: bool,
}

impl Demux {
    /// File a received payload. Returns a waker to wake after releasing the lock.
    pub(crate) fn deliver(
        &mut self,
        limits: &DatagramLimits,
        stream: u64,
        payload: Bytes,
        now: Instant,
        lifetime: Duration,
    ) -> Option<Waker> {
        self.expire(now);
        if self.closed {
            self.dropped += 1;
            return None;
        }
        if let Some(slot) = self.slots.get_mut(&stream) {
            if !slot.receive_open {
                // RFC 9297 §2.1: silently drop after the receive side closed.
                slot.dropped += 1;
                return None;
            }
            if slot.queue.len() >= limits.queue_len
                && let Some(oldest) = slot.queue.pop_front()
            {
                self.buffered -= oldest.len();
                slot.dropped += 1;
            }
            if self.buffered + payload.len() > limits.max_buffered_bytes {
                slot.dropped += 1;
                return None;
            }
            self.buffered += payload.len();
            slot.queue.push_back(payload);
            return slot.waker.take();
        }
        if limits.pending_len == 0 {
            self.dropped += 1;
            return None;
        }
        if self.pending.len() >= limits.pending_len
            && let Some(oldest) = self.pending.pop_front()
        {
            self.buffered -= oldest.payload.len();
            self.dropped += 1;
        }
        if self.buffered + payload.len() > limits.max_buffered_bytes {
            self.dropped += 1;
            return None;
        }
        self.buffered += payload.len();
        self.pending.push_back(Pending {
            stream,
            payload,
            expires: now + lifetime,
        });
        None
    }

    /// Claim a stream's datagrams, adopting any that arrived before the association.
    pub(crate) fn register(&mut self, limits: &DatagramLimits, stream: u64, now: Instant) {
        self.expire(now);
        let mut slot = Slot {
            queue: VecDeque::new(),
            waker: None,
            dropped: 0,
            receive_open: true,
        };
        let buffered = &mut self.buffered;
        self.pending.retain(|pending| {
            if pending.stream != stream {
                return true;
            }
            if slot.queue.len() >= limits.queue_len
                && let Some(oldest) = slot.queue.pop_front()
            {
                *buffered -= oldest.len();
                slot.dropped += 1;
            }
            slot.queue.push_back(pending.payload.clone());
            false
        });
        self.slots.insert(stream, slot);
    }

    /// Release an association and anything still buffered for it.
    pub(crate) fn unregister(&mut self, stream: u64) -> Option<Waker> {
        let slot = self.slots.remove(&stream)?;
        self.buffered -= slot.queue.iter().map(Bytes::len).sum::<usize>();
        self.purge_pending(stream);
        slot.waker
    }

    /// The stream's receive side closed: later datagrams are dropped (RFC 9297 §2.1).
    pub(crate) fn receive_closed(&mut self, stream: u64) -> Option<Waker> {
        self.purge_pending(stream);
        let slot = self.slots.get_mut(&stream)?;
        slot.receive_open = false;
        slot.waker.take()
    }

    /// Whether a stream without datagram semantics received any, releasing them.
    pub(crate) fn take_unclaimed(&mut self, stream: u64) -> bool {
        self.purge_pending(stream)
    }

    pub(crate) fn poll_recv(&mut self, stream: u64, cx: &Context<'_>) -> Poll<Option<Bytes>> {
        let Some(slot) = self.slots.get_mut(&stream) else {
            return Poll::Ready(None);
        };
        if let Some(payload) = slot.queue.pop_front() {
            self.buffered -= payload.len();
            return Poll::Ready(Some(payload));
        }
        if self.closed || !slot.receive_open {
            return Poll::Ready(None);
        }
        if !slot
            .waker
            .as_ref()
            .is_some_and(|waker| waker.will_wake(cx.waker()))
        {
            slot.waker = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    pub(crate) fn slot_dropped(&self, stream: u64) -> u64 {
        self.slots.get(&stream).map_or(0, |slot| slot.dropped)
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Connection closed: wake every consumer; buffered datagrams stay readable.
    pub(crate) fn close(&mut self) -> Vec<Waker> {
        self.closed = true;
        self.pending.clear();
        self.slots
            .values_mut()
            .filter_map(|slot| slot.waker.take())
            .collect()
    }

    fn purge_pending(&mut self, stream: u64) -> bool {
        let before = self.pending.len();
        let buffered = &mut self.buffered;
        self.pending.retain(|pending| {
            let keep = pending.stream != stream;
            if !keep {
                *buffered -= pending.payload.len();
            }
            keep
        });
        before != self.pending.len()
    }

    fn expire(&mut self, now: Instant) {
        while let Some(front) = self.pending.front()
            && front.expires <= now
        {
            self.buffered -= front.payload.len();
            self.dropped += 1;
            self.pending.pop_front();
        }
    }
}

/// How long a datagram for a not-yet-associated stream is kept.
pub(crate) fn pending_lifetime(rtt: Duration) -> Duration {
    (rtt * PENDING_LIFETIME_RTTS).max(PENDING_LIFETIME_FLOOR)
}

/// Validate and split a received QUIC DATAGRAM payload (RFC 9297 §2.1).
pub(crate) fn split(
    datagram: Bytes,
    role_is_server: bool,
    remote_bidi_limit: u64,
) -> Result<(u64, Bytes), Error> {
    let (id, payload) = QuarterStreamId::split_datagram(datagram).map_err(|_error| {
        Error::connection(
            Code::H3_DATAGRAM_ERROR,
            "invalid datagram quarter stream ID",
        )
    })?;
    // SHOULD: a stream beyond the advertised client bidirectional limit cannot exist.
    if role_is_server && id.value() >= remote_bidi_limit {
        return Err(Error::connection(
            Code::H3_ID_ERROR,
            "datagram for a stream beyond the stream limit",
        ));
    }
    Ok((u64::from(VarInt::from(id.request_stream())), payload))
}

/// Per-request association state shared by the tunnel and its native channel.
pub(crate) struct Association {
    shared: Arc<Shared>,
    stream: u64,
    send_open: AtomicBool,
}

impl Association {
    pub(crate) fn register(shared: Arc<Shared>, stream: u64) -> Arc<Self> {
        shared.register_datagrams(stream);
        Arc::new(Self {
            shared,
            stream,
            send_open: AtomicBool::new(true),
        })
    }

    /// The stream's send side finished or reset: no datagrams may follow (RFC 9297 §2.1).
    pub(crate) fn close_send(&self) {
        self.send_open.store(false, Ordering::Release);
    }

    /// The tunnel is gone: neither direction carries datagrams any more.
    pub(crate) fn close(&self) {
        self.close_send();
        self.shared.close_datagram_receive(self.stream);
    }
}

impl Drop for Association {
    fn drop(&mut self) {
        self.shared.unregister_datagrams(self.stream);
    }
}

/// [`NativeDatagramChannel`] over the connection's QUIC DATAGRAM frames.
pub(crate) struct H3DatagramChannel {
    association: Arc<Association>,
    connection: QuicConnection,
    prefix: Bytes,
}

impl H3DatagramChannel {
    pub(crate) fn new(association: Arc<Association>, connection: QuicConnection) -> Option<Self> {
        let stream = StreamId::from(VarInt::from_u64(association.stream).ok()?);
        let id = QuarterStreamId::from_request_stream(stream).ok()?;
        debug_assert!(stream.initiator() == Side::Client && stream.dir() == Dir::Bi);
        let mut prefix = BytesMut::with_capacity(id.size());
        id.encode(&mut prefix);
        Some(Self {
            association,
            connection,
            prefix: prefix.freeze(),
        })
    }

    fn available(&self) -> bool {
        self.association.send_open.load(Ordering::Acquire)
            && self.association.shared.native_datagrams()
    }
}

impl NativeDatagramChannel for H3DatagramChannel {
    fn max_payload_size(&self) -> Option<usize> {
        if !self.available() {
            return None;
        }
        self.connection
            .max_datagram_size()?
            .checked_sub(self.prefix.len())
    }

    fn send(&self, payload: Bytes, policy: NativeSendPolicy) -> Result<(), NativeSendError> {
        let max = self
            .max_payload_size()
            .ok_or(NativeSendError::Unavailable)?;
        if payload.len() > max {
            return Err(NativeSendError::TooLarge { max });
        }
        let mut datagram = BytesMut::with_capacity(self.prefix.len() + payload.len());
        datagram.put_slice(&self.prefix);
        datagram.put_slice(&payload);
        let datagram = datagram.freeze();
        let result = match policy {
            NativeSendPolicy::DropOldest => self.connection.send_datagram(datagram),
            NativeSendPolicy::RejectWhenFull => self.connection.try_send_datagram(datagram),
        };
        result.map_err(|error| match error {
            SendDatagramError::TooLarge => NativeSendError::TooLarge { max },
            SendDatagramError::Blocked => NativeSendError::Full,
            SendDatagramError::ConnectionLost(_) => NativeSendError::Closed,
            _ => NativeSendError::Unavailable,
        })
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        self.association
            .shared
            .poll_datagram(self.association.stream, cx)
            .map(Ok)
    }

    fn dropped(&self) -> u64 {
        self.association
            .shared
            .datagrams_dropped(self.association.stream)
    }
}
