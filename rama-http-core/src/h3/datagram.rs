//! HTTP/3 datagram association and demultiplexing (RFC 9297 §2.1).
//!
//! The connection driver is the only reader of QUIC DATAGRAM frames. It splits the Quarter
//! Stream ID prefix (sharing the frame's storage) and files each payload under its request
//! stream. Every request stream is registered while datagrams are enabled, so the driver
//! alone decides, without any application poll, whether a datagram is queued, dropped or a
//! violation of the request's datagram semantics.

use super::{Error, connection::Shared};
use ahash::HashMap;
use rama_core::bytes::{BufMut as _, Bytes, BytesMut};
use rama_http::datagram::{
    NativeDatagramChannel, NativeRecvError, NativeSendError, NativeSendPolicy, ViolationPolicy,
};
use rama_http_types::proto::h3::{Code, QuarterStreamId};
use rama_quic::{Connection as QuicConnection, SendDatagramError, StreamAbortHandle};
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

/// HTTP/3 datagram support of a connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DatagramConfig {
    /// Buffering budgets for received datagrams.
    pub limits: DatagramLimits,
    /// Reaction to peer violations of the datagram rules that do not affect framing.
    ///
    /// [`ViolationPolicy::Ignore`] (default) drops and counts: a datagram for a request
    /// without datagram semantics, an invalid Quarter Stream ID, or one beyond the client
    /// bidirectional stream limit. [`ViolationPolicy::Reject`] aborts the request with
    /// `H3_DATAGRAM_ERROR`, or closes the connection with `H3_DATAGRAM_ERROR` and
    /// `H3_ID_ERROR` respectively (RFC 9297 §2, §2.1).
    pub violations: ViolationPolicy,
}

/// Buffering budgets for received HTTP/3 datagrams. A zero `queue_len` or `pending_len` drops
/// (and counts) every datagram it would hold; a zero `max_buffered_bytes` still admits empty
/// payloads, bounded by the entry counts. The request semantics are enforced regardless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatagramLimits {
    /// Datagrams queued per request; the oldest is discarded when it is full.
    pub queue_len: usize,
    /// Datagrams held briefly for request streams that do not exist yet.
    pub pending_len: usize,
    /// Received payload bytes buffered per connection across all requests.
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

/// Received HTTP/3 datagrams a connection discarded, by reason.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DatagramDrops {
    /// For a request without datagram semantics.
    pub no_semantics: u64,
    /// With a truncated or out-of-range Quarter Stream ID.
    pub invalid_id: u64,
    /// For a stream beyond the client bidirectional stream limit.
    pub beyond_limit: u64,
    /// For a stream that was released (or never used).
    pub unknown_stream: u64,
    /// After the request's receive side, its consumer or the connection ended.
    pub receive_closed: u64,
    /// Displaced from a full request queue.
    pub queue_full: u64,
    /// Over the connection's buffered byte budget.
    pub over_budget: u64,
    /// Held for a future stream that did not appear in time.
    pub expired: u64,
    /// Received while this endpoint did not advertise `SETTINGS_H3_DATAGRAM`.
    pub unadvertised: u64,
}

/// Pending datagrams wait "on the order of a round trip" (RFC 9297 §2.1); this floor keeps
/// very short RTT estimates from discarding datagrams that merely beat their HEADERS.
const PENDING_LIFETIME_FLOOR: Duration = Duration::from_millis(100);
const PENDING_LIFETIME_RTTS: u32 = 3;

/// Whether a request has datagram semantics (RFC 9297 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Semantics {
    /// A server's Extended CONNECT awaiting its response; datagrams are held.
    Provisional,
    /// Declared with [`HttpDatagrams`](rama_http_types::proto::ext::HttpDatagrams).
    Claimed,
    /// Datagrams for it are violations.
    None,
}

/// How a request's receive side ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReceiveEnd {
    /// The peer finished the stream.
    Finished,
    /// The peer reset the stream with this code.
    Reset(u64),
    /// This endpoint aborted the stream with this code.
    Aborted(u64),
    /// Nobody consumes its datagrams any more.
    Released,
}

/// Aborts a request that violated its datagram semantics.
pub(crate) trait AbortRequest: Clone {
    fn abort_request(&self);
}

impl AbortRequest for StreamAbortHandle {
    fn abort_request(&self) {
        self.abort(VarInt::from_u32(Code::H3_DATAGRAM_ERROR.value() as u32));
    }
}

struct Slot<A> {
    semantics: Semantics,
    queue: VecDeque<Bytes>,
    // Payload bytes in `queue`, so an over-budget admission can find the largest queue.
    bytes: usize,
    waker: Option<Waker>,
    dropped: u64,
    receive: Option<ReceiveEnd>,
    // Set by every datagram routed here before the semantics are final, even one discarded.
    observed: bool,
    abort: A,
    violated: Arc<AtomicBool>,
}

struct Pending {
    stream: u64,
    payload: Bytes,
    expires: Instant,
}

/// Work to do once the demux lock is released.
#[must_use]
pub(crate) struct Action<A = StreamAbortHandle> {
    wake: Option<Waker>,
    abort: Option<A>,
}

impl<A> Default for Action<A> {
    fn default() -> Self {
        Self {
            wake: None,
            abort: None,
        }
    }
}

impl<A: AbortRequest> Action<A> {
    pub(crate) fn run(self) {
        if let Some(abort) = self.abort {
            abort.abort_request();
        }
        if let Some(waker) = self.wake {
            waker.wake();
        }
    }
}

/// Connection-wide datagram routing state, guarded by one short-held lock.
pub(crate) struct Demux<A = StreamAbortHandle> {
    slots: HashMap<u64, Slot<A>>,
    pending: VecDeque<Pending>,
    buffered: usize,
    // The lowest request stream id never registered: below it an unknown id was released.
    watermark: u64,
    drops: DatagramDrops,
    closed: bool,
}

impl<A> Default for Demux<A> {
    fn default() -> Self {
        Self {
            slots: HashMap::default(),
            pending: VecDeque::new(),
            buffered: 0,
            watermark: 0,
            drops: DatagramDrops::default(),
            closed: false,
        }
    }
}

impl<A: AbortRequest> Demux<A> {
    /// File a received payload.
    pub(crate) fn deliver(
        &mut self,
        config: &DatagramConfig,
        stream: u64,
        payload: Bytes,
        now: Instant,
        lifetime: Duration,
    ) -> Action<A> {
        self.expire(now);
        if self.closed {
            self.drops.receive_closed += 1;
            return Action::default();
        }
        let Some(slot) = self.slots.get_mut(&stream) else {
            if stream < self.watermark {
                // RFC 9297 §2.1: a released stream's receive side is closed.
                self.drops.unknown_stream += 1;
            } else {
                self.hold(&config.limits, stream, payload, now + lifetime);
            }
            return Action::default();
        };
        if slot.receive.is_some() {
            slot.dropped += 1;
            self.drops.receive_closed += 1;
            return Action::default();
        }
        match slot.semantics {
            Semantics::None => violation(slot, config.violations, &mut self.drops),
            // A client claim can still become None on a refused response.
            Semantics::Provisional | Semantics::Claimed => {
                slot.observed = true;
                self.enqueue(&config.limits, stream, payload)
            }
        }
    }

    /// Register a request stream, adopting datagrams that arrived before it existed.
    pub(crate) fn register(
        &mut self,
        config: &DatagramConfig,
        stream: u64,
        semantics: Semantics,
        abort: A,
        violated: Arc<AtomicBool>,
        now: Instant,
    ) -> Action<A> {
        self.expire(now);
        self.watermark = self.watermark.max(stream.saturating_add(4));
        self.slots.insert(
            stream,
            Slot {
                semantics,
                queue: VecDeque::new(),
                bytes: 0,
                waker: None,
                dropped: 0,
                receive: None,
                observed: false,
                abort,
                violated,
            },
        );
        let mut action = Action::default();
        let mut held = Vec::new();
        let mut expired = 0;
        let mut released = 0;
        self.pending.retain(|pending| {
            let keep = pending.stream != stream;
            if !keep {
                released += pending.payload.len();
                // Lifetimes follow the RTT at arrival, so a later entry can expire first.
                if pending.expires > now {
                    held.push(pending.payload.clone());
                } else {
                    expired += 1;
                }
            }
            keep
        });
        self.drops.expired += expired;
        self.buffered -= released;
        for payload in held {
            let Some(slot) = self.slots.get_mut(&stream) else {
                break;
            };
            slot.observed = true;
            let next = match slot.semantics {
                Semantics::None => violation(slot, config.violations, &mut self.drops),
                Semantics::Provisional | Semantics::Claimed => {
                    self.enqueue(&config.limits, stream, payload)
                }
            };
            action.merge(next);
        }
        action
    }

    /// Make a request's datagram semantics final.
    pub(crate) fn decide(
        &mut self,
        config: &DatagramConfig,
        stream: u64,
        claimed: bool,
    ) -> Action<A> {
        let Some(slot) = self.slots.get_mut(&stream) else {
            return Action::default();
        };
        if claimed {
            slot.semantics = Semantics::Claimed;
            return Action::default();
        }
        slot.semantics = Semantics::None;
        self.drops.no_semantics += slot.queue.len() as u64;
        slot.queue.clear();
        self.buffered -= std::mem::take(&mut slot.bytes);
        if !slot.observed {
            return Action::default();
        }
        reject(slot, config.violations)
    }

    /// Release a stream and anything still buffered for it.
    pub(crate) fn unregister(&mut self, stream: u64) -> Option<Waker> {
        let slot = self.slots.remove(&stream)?;
        self.buffered -= slot.bytes;
        slot.waker
    }

    /// The stream's receive side or its consumer ended: later datagrams are dropped
    /// (RFC 9297 §2.1). A local end (released consumer, local abort) also discards the queue.
    pub(crate) fn receive_ended(&mut self, stream: u64, end: ReceiveEnd) -> Option<Waker> {
        let slot = self.slots.get_mut(&stream)?;
        let local = matches!(end, ReceiveEnd::Released | ReceiveEnd::Aborted(_));
        if slot.receive.is_none()
            || (local && !matches!(slot.receive, Some(ReceiveEnd::Aborted(_))))
        {
            slot.receive = Some(end);
        }
        if local {
            self.drops.receive_closed += slot.queue.len() as u64;
            slot.queue.clear();
            self.buffered -= std::mem::take(&mut slot.bytes);
        }
        slot.waker.take()
    }

    pub(crate) fn poll_recv(
        &mut self,
        stream: u64,
        cx: &Context<'_>,
    ) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        let Some(slot) = self.slots.get_mut(&stream) else {
            return Poll::Ready(Ok(None));
        };
        if let Some(payload) = slot.queue.pop_front() {
            slot.bytes -= payload.len();
            self.buffered -= payload.len();
            return Poll::Ready(Ok(Some(payload)));
        }
        match slot.receive {
            Some(ReceiveEnd::Finished | ReceiveEnd::Released) => return Poll::Ready(Ok(None)),
            Some(ReceiveEnd::Reset(code)) => {
                return Poll::Ready(Err(NativeRecvError::Reset(code)));
            }
            Some(ReceiveEnd::Aborted(code)) => {
                return Poll::Ready(Err(NativeRecvError::Aborted(code)));
            }
            None if self.closed => return Poll::Ready(Err(NativeRecvError::Lost)),
            None => (),
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

    pub(crate) fn drops(&self) -> DatagramDrops {
        self.drops
    }

    pub(crate) fn count_unadvertised(&mut self) {
        self.drops.unadvertised += 1;
    }

    pub(crate) fn count_invalid(&mut self, beyond_limit: bool) {
        if beyond_limit {
            self.drops.beyond_limit += 1;
        } else {
            self.drops.invalid_id += 1;
        }
    }

    #[cfg(any(test, feature = "fuzz-utils"))]
    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    #[cfg(test)]
    pub(crate) fn buffered(&self) -> usize {
        self.buffered
    }

    #[cfg(test)]
    pub(crate) fn slot_count(&self) -> usize {
        self.slots.len()
    }

    /// Backing capacities: the slot map, the pending queue and all per-request queues.
    #[cfg(test)]
    pub(crate) fn capacities(&self) -> (usize, usize, usize) {
        let queues = self.slots.values().map(|slot| slot.queue.capacity()).sum();
        (self.slots.capacity(), self.pending.capacity(), queues)
    }

    #[cfg(feature = "fuzz-utils")]
    pub(crate) fn queued(&self, stream: u64) -> usize {
        self.slots.get(&stream).map_or(0, |slot| slot.queue.len())
    }

    /// The byte accounting matches what is held, within the configured bounds.
    #[cfg(feature = "fuzz-utils")]
    pub(crate) fn assert_consistent(&self, limits: &DatagramLimits) {
        let queued: usize = self
            .slots
            .values()
            .flat_map(|slot| slot.queue.iter())
            .map(Bytes::len)
            .sum();
        let pending: usize = self
            .pending
            .iter()
            .map(|pending| pending.payload.len())
            .sum();
        assert_eq!(self.buffered, queued + pending);
        assert!(self.buffered <= limits.max_buffered_bytes);
        assert!(self.pending.len() <= limits.pending_len);
        for slot in self.slots.values() {
            assert!(slot.queue.len() <= limits.queue_len);
            assert_eq!(slot.bytes, slot.queue.iter().map(Bytes::len).sum::<usize>());
        }
    }

    /// Connection closed: wake every consumer; queued datagrams stay readable.
    pub(crate) fn close(&mut self) -> Vec<Waker> {
        self.closed = true;
        self.drops.receive_closed += self.pending.len() as u64;
        self.buffered -= self
            .pending
            .drain(..)
            .map(|pending| pending.payload.len())
            .sum::<usize>();
        self.slots
            .values_mut()
            .filter_map(|slot| slot.waker.take())
            .collect()
    }

    /// Queue a payload for a registered stream. Over the byte budget the oldest datagram of
    /// the largest queue makes room, so stalled consumers cannot starve the others.
    fn enqueue(&mut self, limits: &DatagramLimits, stream: u64, payload: Bytes) -> Action<A> {
        let Some(slot) = self.slots.get_mut(&stream) else {
            return Action::default();
        };
        if limits.queue_len == 0 {
            slot.dropped += 1;
            self.drops.queue_full += 1;
            return Action::default();
        }
        if self.buffered + payload.len() > limits.max_buffered_bytes {
            // Held datagrams cannot make room: when they alone crowd the payload out, or it
            // can never fit, drop it before any queued datagram is given up for it.
            let held: usize = self
                .pending
                .iter()
                .map(|pending| pending.payload.len())
                .sum();
            if held + payload.len() > limits.max_buffered_bytes {
                slot.dropped += 1;
                self.drops.over_budget += 1;
                return Action::default();
            }
        }
        if slot.queue.len() >= limits.queue_len
            && let Some(oldest) = slot.queue.pop_front()
        {
            slot.bytes -= oldest.len();
            self.buffered -= oldest.len();
            slot.dropped += 1;
            self.drops.queue_full += 1;
        }
        while self.buffered + payload.len() > limits.max_buffered_bytes {
            let Some(largest) = self
                .slots
                .values_mut()
                .filter(|slot| slot.bytes > 0)
                .max_by_key(|slot| slot.bytes)
            else {
                if let Some(slot) = self.slots.get_mut(&stream) {
                    slot.dropped += 1;
                }
                self.drops.over_budget += 1;
                return Action::default();
            };
            // Empty datagrams free nothing, so they are kept.
            if let Some(oldest) = largest
                .queue
                .iter()
                .position(|datagram| !datagram.is_empty())
                .and_then(|at| largest.queue.remove(at))
            {
                largest.bytes -= oldest.len();
                self.buffered -= oldest.len();
                largest.dropped += 1;
                self.drops.over_budget += 1;
            }
        }
        let Some(slot) = self.slots.get_mut(&stream) else {
            return Action::default();
        };
        self.buffered += payload.len();
        slot.bytes += payload.len();
        slot.queue.push_back(payload);
        Action {
            wake: slot.waker.take(),
            abort: None,
        }
    }

    fn hold(&mut self, limits: &DatagramLimits, stream: u64, payload: Bytes, expires: Instant) {
        if limits.pending_len == 0 {
            self.drops.expired += 1;
            return;
        }
        if self.pending.len() >= limits.pending_len
            && let Some(oldest) = self.pending.pop_front()
        {
            self.buffered -= oldest.payload.len();
            self.drops.expired += 1;
        }
        if self.buffered + payload.len() > limits.max_buffered_bytes {
            self.drops.over_budget += 1;
            return;
        }
        self.buffered += payload.len();
        self.pending.push_back(Pending {
            stream,
            payload,
            expires,
        });
    }

    fn expire(&mut self, now: Instant) {
        while let Some(front) = self.pending.front()
            && front.expires <= now
        {
            self.buffered -= front.payload.len();
            self.drops.expired += 1;
            self.pending.pop_front();
        }
    }
}

impl<A> Action<A> {
    fn merge(&mut self, other: Self) {
        self.wake = self.wake.take().or(other.wake);
        self.abort = self.abort.take().or(other.abort);
    }
}

/// A datagram for a request without datagram semantics (RFC 9297 §2).
fn violation<A: Clone>(
    slot: &mut Slot<A>,
    policy: ViolationPolicy,
    drops: &mut DatagramDrops,
) -> Action<A> {
    drops.no_semantics += 1;
    reject(slot, policy)
}

/// Under [`ViolationPolicy::Reject`], abort the request once (sticky).
fn reject<A: Clone>(slot: &mut Slot<A>, policy: ViolationPolicy) -> Action<A> {
    if policy == ViolationPolicy::Reject && !slot.violated.swap(true, Ordering::AcqRel) {
        return Action {
            wake: slot.waker.take(),
            abort: Some(slot.abort.clone()),
        };
    }
    Action::default()
}

/// How long a datagram for a stream that does not exist yet is kept.
pub(crate) fn pending_lifetime(rtt: Duration) -> Duration {
    (rtt * PENDING_LIFETIME_RTTS).max(PENDING_LIFETIME_FLOOR)
}

/// A received QUIC DATAGRAM payload, split per RFC 9297 §2.1.
pub(crate) enum Split {
    Datagram(u64, Bytes),
    InvalidId,
    BeyondLimit,
}

pub(crate) fn split(datagram: Bytes, role_is_server: bool, remote_bidi_limit: u64) -> Split {
    let Ok((id, payload)) = QuarterStreamId::split_datagram(datagram) else {
        return Split::InvalidId;
    };
    // A stream beyond the advertised client bidirectional limit cannot exist.
    if role_is_server && id.value() >= remote_bidi_limit {
        return Split::BeyondLimit;
    }
    Split::Datagram(u64::from(VarInt::from(id.request_stream())), payload)
}

/// The connection error [`ViolationPolicy::Reject`] applies to an invalid prefix.
pub(crate) fn invalid_prefix_error(beyond_limit: bool) -> Error {
    // Both are the peer's datagrams, like every other received-input violation.
    if beyond_limit {
        Error::connection(
            Code::H3_ID_ERROR,
            "datagram for a stream beyond the stream limit",
        )
        .remote()
    } else {
        Error::connection(
            Code::H3_DATAGRAM_ERROR,
            "invalid datagram quarter stream ID",
        )
        .remote()
    }
}

/// A request stream's entry in the connection demux, released when its last owner drops.
pub(crate) struct Registration {
    shared: Arc<Shared>,
    stream: u64,
    violated: Arc<AtomicBool>,
}

impl Registration {
    pub(crate) fn new(shared: Arc<Shared>, stream: u64, violated: Arc<AtomicBool>) -> Self {
        Self {
            shared,
            stream,
            violated,
        }
    }

    /// The driver aborted the request for a datagram without semantics.
    pub(crate) fn violated(&self) -> bool {
        self.violated.load(Ordering::Acquire)
    }

    pub(crate) fn decide(&self, claimed: bool) {
        self.shared.decide_datagrams(self.stream, claimed);
    }

    pub(crate) fn receive_ended(&self, end: ReceiveEnd) {
        self.shared.datagram_receive_ended(self.stream, end);
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        self.shared.unregister_datagrams(self.stream);
    }
}

/// A claimed request's datagram association, shared by its tunnel and native channel.
pub(crate) struct Association {
    registration: Arc<Registration>,
    send: StreamAbortHandle,
    send_open: AtomicBool,
}

impl Association {
    pub(crate) fn new(registration: Arc<Registration>, send: StreamAbortHandle) -> Arc<Self> {
        Arc::new(Self {
            registration,
            send,
            send_open: AtomicBool::new(true),
        })
    }

    /// The stream's send side is finishing or reset: no datagrams may follow (RFC 9297 §2.1).
    pub(crate) fn close_send(&self) {
        self.send_open.store(false, Ordering::Release);
    }

    /// The tunnel is gone: neither direction carries datagrams any more.
    pub(crate) fn close(&self) {
        self.close_send();
        self.registration.receive_ended(ReceiveEnd::Released);
    }

    fn stream(&self) -> u64 {
        self.registration.stream
    }

    fn shared(&self) -> &Shared {
        &self.registration.shared
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
        let stream = StreamId::from(VarInt::from_u64(association.stream()).ok()?);
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
}

impl NativeDatagramChannel for H3DatagramChannel {
    fn max_payload_size(&self) -> Option<usize> {
        if !self.association.shared().native_datagrams() {
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
        if !self.association.send_open.load(Ordering::Acquire) {
            return Err(NativeSendError::Closed);
        }
        if payload.len() > max {
            return Err(NativeSendError::TooLarge { max });
        }
        let mut datagram = BytesMut::with_capacity(self.prefix.len() + payload.len());
        datagram.put_slice(&self.prefix);
        datagram.put_slice(&payload);
        let datagram = datagram.freeze();
        // The transport checks the stream's send state under the lock that queues it.
        let result = match policy {
            NativeSendPolicy::DropOldest => self.association.send.send_datagram(datagram),
            NativeSendPolicy::RejectWhenFull => self.association.send.try_send_datagram(datagram),
        };
        result.map_err(|error| match error {
            SendDatagramError::TooLarge => NativeSendError::TooLarge { max },
            SendDatagramError::Blocked => NativeSendError::Full,
            SendDatagramError::StreamClosed | SendDatagramError::ConnectionLost(_) => {
                self.association.close_send();
                NativeSendError::Closed
            }
            SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
                NativeSendError::Unavailable
            }
        })
    }

    fn poll_recv(&self, cx: &mut Context<'_>) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        self.association
            .shared()
            .poll_datagram(self.association.stream(), cx)
    }

    fn dropped(&self) -> u64 {
        self.association
            .shared()
            .datagrams_dropped(self.association.stream())
    }

    fn release_recv(&self) {
        self.association
            .registration
            .receive_ended(ReceiveEnd::Released);
    }
}
