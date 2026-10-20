//! The start of a client's CRYPTO stream, reassembled up to its ClientHello.

use alloc::vec::Vec;

use super::{CaptureError, CaptureLimits, within};
use crate::range_set::ArrayRangeSet;

/// A TLS handshake message header: one type byte and a three-byte length (RFC 8446 §4).
const HEADER: usize = 4;

/// Reassembles a client's ClientHello from CRYPTO data taken in fragment by fragment, in any
/// order and with any retransmissions.
///
/// Each fragment is written straight to its place in one buffer; only which offsets arrived is
/// tracked beside it, so reassembly costs no allocation per fragment, and the buffer is sized
/// to the message exactly once its header arrived. Every byte seen twice must agree, including
/// retransmissions after the ClientHello is complete: an inspector and the endpoint that later
/// accepts the attempt cannot be shown different names or protocol offers.
///
/// The message, and with it the buffer, is bounded by [`CaptureLimits::client_hello_bytes`];
/// the disjoint ranges received by [`CaptureLimits::crypto_fragments`]. Data past the end of
/// the ClientHello is not needed and is ignored.
#[derive(Debug)]
pub struct ClientHelloAssembly {
    max_message: usize,
    max_ranges: usize,
    /// Received bytes at their stream offsets; unreceived gaps are zero.
    buffer: Vec<u8>,
    /// The stream offsets received so far.
    received: ArrayRangeSet,
    /// The handshake message length, once its header arrived.
    expected: Option<usize>,
}

impl ClientHelloAssembly {
    #[must_use]
    pub fn new(limits: &CaptureLimits) -> Self {
        Self {
            max_message: limits.client_hello_bytes,
            max_ranges: limits.crypto_fragments,
            buffer: Vec::new(),
            received: ArrayRangeSet::new(),
            expected: None,
        }
    }

    /// Take in CRYPTO data at `offset`.
    pub fn take_in(&mut self, offset: u64, data: &[u8]) -> Result<(), CaptureError> {
        let offset =
            usize::try_from(offset).map_err(|_error| CaptureError::Malformed("CRYPTO offset"))?;
        let end = match self.expected {
            Some(length) => length,
            // A message whose header cannot even fit can never be read.
            None if self.max_message < HEADER => {
                return Err(CaptureError::LimitExceeded("ClientHello bytes"));
            }
            None => self.max_message,
        };
        if offset >= end || data.is_empty() {
            return Ok(());
        }
        let data = &data[..data.len().min(end - offset)];
        let range = offset..offset + data.len();
        for held in self.received.iter() {
            let start = (held.start as usize).max(range.start);
            let stop = (held.end as usize).min(range.end);
            if start < stop && self.buffer[start..stop] != data[start - offset..stop - offset] {
                return Err(CaptureError::Malformed("conflicting CRYPTO overlap"));
            }
        }
        if self.buffer.len() < range.end {
            self.buffer.reserve_exact(range.end - self.buffer.len());
            self.buffer.resize(range.end, 0);
        }
        // Bytes already held are equal, so writing them again changes nothing.
        self.buffer[range.clone()].copy_from_slice(data);
        self.received.insert(range.start as u64..range.end as u64);
        within(self.received.len(), self.max_ranges, "CRYPTO fragments")?;
        if self.expected.is_none() && self.received().len() >= HEADER {
            self.read_header()?;
        }
        Ok(())
    }

    /// The complete ClientHello handshake message, once every byte of it arrived.
    #[must_use]
    pub fn client_hello(&self) -> Option<&[u8]> {
        let length = self.expected?;
        (self.received().len() == length).then(|| &self.buffer[..length])
    }

    /// The contiguous start of the ClientHello received so far.
    #[must_use]
    pub fn received(&self) -> &[u8] {
        match self.received.iter().next() {
            Some(first) if first.start == 0 => &self.buffer[..first.end as usize],
            _ => &[],
        }
    }

    fn read_header(&mut self) -> Result<(), CaptureError> {
        let &[kind, a, b, c] = &self.buffer[..HEADER] else {
            return Err(CaptureError::Malformed("ClientHello header"));
        };
        // TLS HandshakeType client_hello is 1 (RFC 8446 §4).
        if kind != 0x01 {
            return Err(CaptureError::Malformed("expected ClientHello"));
        }
        let length = HEADER + (usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c));
        within(length, self.max_message, "ClientHello bytes")?;
        self.expected = Some(length);
        if self.buffer.len() > length {
            self.buffer.truncate(length);
            let _trimmed = self.received.remove(length as u64..u64::MAX);
        } else {
            self.buffer.reserve_exact(length - self.buffer.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
