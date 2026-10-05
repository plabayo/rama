//! A pending attempt's ClientHello, reassembled from the Initial packets of its first flight
//! before the attempt is accepted.

use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    task::Waker,
};

use parking_lot::Mutex;
use rama_core::bytes::Bytes;
use rama_tls::client::{ClientHelloHandshakePrefix, parse_client_hello_message_prefix};

use crate::proto::crypto::ClientHelloMessage;

/// A ClientHello larger than this is not looked at.
pub(crate) const LIMIT: usize = 16 * 1024;

/// CRYPTO data held beyond a gap is kept for at most this many offsets.
const AHEAD_LIMIT: usize = 32;

/// How much of a client's ClientHello its first flight has delivered so far.
pub(crate) enum ClientHelloPeek {
    /// The whole ClientHello.
    Complete(ClientHelloMessage),
    /// The start of a ClientHello whose remainder has not arrived.
    Incomplete,
    /// Bytes that are not, and cannot become, a ClientHello of at most [`LIMIT`] bytes.
    Invalid,
}

/// The start of a pending attempt's CRYPTO stream, taken in packet by packet.
///
/// Every packet is opened once, whatever the number of looks.
#[derive(Debug, Default)]
pub(crate) struct HelloAssembly {
    /// The first packet, and what was coalesced behind it, are taken in.
    pub(crate) started: bool,
    /// Buffered datagrams already taken in.
    pub(crate) taken: usize,
    /// The contiguous start of the stream.
    stream: Vec<u8>,
    /// Data beyond a gap, by offset.
    ahead: BTreeMap<usize, Bytes>,
}

impl HelloAssembly {
    /// Take in CRYPTO data at `offset`; anything at or past [`LIMIT`] is dropped.
    pub(crate) fn take_in(&mut self, offset: u64, data: Bytes) {
        let Some(offset) = usize::try_from(offset)
            .ok()
            .filter(|offset| *offset < LIMIT)
        else {
            return;
        };
        let mut data = data;
        data.truncate(LIMIT - offset);
        if offset > self.stream.len() {
            let longer = self
                .ahead
                .get(&offset)
                .is_none_or(|held| held.len() < data.len());
            if longer && (self.ahead.len() < AHEAD_LIMIT || self.ahead.contains_key(&offset)) {
                self.ahead.insert(offset, data);
            }
            return;
        }
        self.append(offset, &data);
        while let Some(entry) = self.ahead.first_entry() {
            if *entry.key() > self.stream.len() {
                break;
            }
            let (offset, data) = entry.remove_entry();
            self.append(offset, &data);
        }
    }

    fn append(&mut self, offset: usize, data: &[u8]) {
        if let Some(fresh) = data.get(self.stream.len() - offset..) {
            self.stream.extend_from_slice(fresh);
        }
    }

    /// What the stream holds of the ClientHello so far.
    pub(crate) fn peek(&self) -> ClientHelloPeek {
        // A handshake message: one type byte and a three-byte body length (RFC 8446 §4).
        let Some(&[_, a, b, c]) = self.stream.get(..4) else {
            return ClientHelloPeek::Incomplete;
        };
        let len = 4 + (usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c));
        if len > LIMIT {
            return ClientHelloPeek::Invalid;
        }
        let Some(message) = self.stream.get(..len) else {
            return match parse_client_hello_message_prefix(&self.stream) {
                ClientHelloHandshakePrefix::Invalid => ClientHelloPeek::Invalid,
                _ => ClientHelloPeek::Incomplete,
            };
        };
        match parse_client_hello_message_prefix(message) {
            ClientHelloHandshakePrefix::Complete(hello) => ClientHelloPeek::Complete(
                ClientHelloMessage::new(Bytes::copy_from_slice(message), hello),
            ),
            ClientHelloHandshakePrefix::Incomplete | ClientHelloHandshakePrefix::Invalid => {
                ClientHelloPeek::Invalid
            }
        }
    }
}

/// Wakes the application waiting on a pending attempt: more of its first flight arrived,
/// or it will not progress any further.
#[derive(Debug, Default)]
pub(crate) struct IncomingProgress {
    generation: AtomicU64,
    waker: Mutex<Option<Waker>>,
}

impl IncomingProgress {
    /// Changes whenever the attempt progresses.
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Record progress and wake the application waiting for it.
    pub(crate) fn advance(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(waker) = self.waker.lock().take() {
            waker.wake();
        }
    }

    /// Wake `waker` on the next progress.
    pub(crate) fn register(&self, waker: &Waker) {
        let mut slot = self.waker.lock();
        match slot.as_mut() {
            Some(held) if held.will_wake(waker) => {}
            _ => *slot = Some(waker.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello handshake message with `extensions` bytes of opaque extension payload.
    fn client_hello(extensions: usize) -> Vec<u8> {
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // legacy session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        let ext_len = 4 + extensions;
        body.extend_from_slice(&(ext_len as u16).to_be_bytes());
        body.extend_from_slice(&[0xfe, 0x00]); // a private extension id
        body.extend_from_slice(&(extensions as u16).to_be_bytes());
        body.extend(std::iter::repeat_n(0x5a, extensions));
        let mut message = vec![0x01];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(&body);
        message
    }

    fn complete(assembly: &HelloAssembly) -> Vec<u8> {
        match assembly.peek() {
            ClientHelloPeek::Complete(message) => message.message().to_vec(),
            ClientHelloPeek::Incomplete => panic!("incomplete"),
            ClientHelloPeek::Invalid => panic!("invalid"),
        }
    }

    fn chunks(message: &[u8], size: usize) -> Vec<(u64, Bytes)> {
        message
            .chunks(size)
            .enumerate()
            .map(|(n, chunk)| ((n * size) as u64, Bytes::copy_from_slice(chunk)))
            .collect()
    }

    #[test]
    fn a_message_in_order_completes() {
        let message = client_hello(2000);
        let mut assembly = HelloAssembly::default();
        let parts = chunks(&message, 1100);
        for (offset, data) in &parts[..parts.len() - 1] {
            assembly.take_in(*offset, data.clone());
            assert!(matches!(assembly.peek(), ClientHelloPeek::Incomplete));
        }
        let (offset, data) = parts.last().unwrap().clone();
        assembly.take_in(offset, data);
        assert_eq!(complete(&assembly), message);
    }

    #[test]
    fn reordered_duplicated_and_overlapping_data_completes() {
        let message = client_hello(3000);
        let mut assembly = HelloAssembly::default();
        let mut parts = chunks(&message, 700);
        parts.reverse();
        // A retransmission covering already received data, and one overlapping two chunks.
        parts.push((0, Bytes::copy_from_slice(&message[..300])));
        parts.push((650, Bytes::copy_from_slice(&message[650..1500])));
        for (offset, data) in parts.iter().chain(parts.iter()) {
            assembly.take_in(*offset, data.clone());
        }
        assert_eq!(complete(&assembly), message);
    }

    #[test]
    fn a_gap_keeps_it_incomplete() {
        let message = client_hello(2000);
        let mut assembly = HelloAssembly::default();
        assembly.take_in(0, Bytes::copy_from_slice(&message[..1000]));
        assembly.take_in(1500, Bytes::copy_from_slice(&message[1500..]));
        assert!(matches!(assembly.peek(), ClientHelloPeek::Incomplete));
        assembly.take_in(1000, Bytes::copy_from_slice(&message[1000..1500]));
        assert_eq!(complete(&assembly), message);
    }

    #[test]
    fn trailing_data_is_not_part_of_the_message() {
        let message = client_hello(10);
        let mut stream = message.clone();
        stream.extend_from_slice(&[0xaa; 64]);
        let mut assembly = HelloAssembly::default();
        assembly.take_in(0, stream.into());
        assert_eq!(complete(&assembly), message);
    }

    #[test]
    fn a_declared_length_past_the_limit_is_invalid_at_once() {
        let mut assembly = HelloAssembly::default();
        let declared = (LIMIT as u32).to_be_bytes();
        assembly.take_in(
            0,
            Bytes::copy_from_slice(&[0x01, declared[1], declared[2], declared[3]]),
        );
        assert!(matches!(assembly.peek(), ClientHelloPeek::Invalid));
    }

    #[test]
    fn a_message_up_to_the_limit_completes() {
        let message = client_hello(LIMIT - client_hello(0).len());
        assert_eq!(message.len(), LIMIT);
        let mut assembly = HelloAssembly::default();
        for (offset, data) in chunks(&message, 1100) {
            assembly.take_in(offset, data);
        }
        assert_eq!(complete(&assembly), message);
    }

    #[test]
    fn data_past_the_limit_is_dropped() {
        let mut assembly = HelloAssembly::default();
        assembly.take_in(LIMIT as u64, Bytes::from_static(&[0; 100]));
        assembly.take_in(u64::MAX, Bytes::from_static(&[0; 100]));
        assert!(assembly.ahead.is_empty());
        assembly.take_in(LIMIT as u64 - 10, Bytes::from_static(&[0; 100]));
        assert_eq!(assembly.ahead.values().map(Bytes::len).sum::<usize>(), 10);
    }

    #[test]
    fn data_ahead_of_a_gap_is_bounded() {
        let mut assembly = HelloAssembly::default();
        for offset in 1..=(AHEAD_LIMIT as u64 * 2) {
            assembly.take_in(offset * 10, Bytes::from_static(&[0; 5]));
        }
        assert_eq!(assembly.ahead.len(), AHEAD_LIMIT);
    }

    #[test]
    fn a_message_of_another_type_is_invalid() {
        let mut message = client_hello(10);
        message[0] = 0x02; // ServerHello
        let mut assembly = HelloAssembly::default();
        assembly.take_in(0, message.into());
        assert!(matches!(assembly.peek(), ClientHelloPeek::Invalid));
    }

    #[test]
    fn progress_wakes_the_registered_waker() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::task::Wake;

        struct Count(AtomicUsize);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let progress = IncomingProgress::default();
        let before = progress.generation();
        progress.advance();
        assert_eq!(count.0.load(Ordering::SeqCst), 0, "nothing registered yet");
        progress.register(&waker);
        progress.advance();
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(progress.generation(), before + 2);
    }
}
