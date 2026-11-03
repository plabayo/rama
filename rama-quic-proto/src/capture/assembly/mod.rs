//! The start of a client's CRYPTO stream, reassembled up to its ClientHello.

use alloc::vec::Vec;
use rama_tls::client::{ClientHelloMessageError, client_hello_message_size};

use super::{CaptureError, CaptureLimits, within};
use crate::range_set::ArrayRangeSet;

/// A TLS handshake message header: one type byte and a three-byte length (RFC 8446 §4).
const HEADER: usize = 4;

/// Reassembles a client's ClientHello from CRYPTO data taken in fragment by fragment, in any
/// order and with any retransmissions.
///
/// Before the header arrives, only received bytes are retained in bounded sparse fragments;
/// a high offset cannot force a large allocation. Once the header arrives, fragments are
/// copied into one buffer sized to the bounded message, and later data is written in place. Every byte seen twice must agree, including
/// retransmissions after the ClientHello is complete: an inspector and the endpoint that later
/// accepts the attempt cannot be shown different names or protocol offers.
///
/// The message, and with it the buffer, is bounded by [`CaptureLimits::client_hello_bytes`];
/// the disjoint ranges and pre-header fragments by [`CaptureLimits::crypto_fragments`]. Data past the end of
/// the ClientHello is not needed and is ignored.
#[derive(Debug)]
pub struct ClientHelloAssembly {
    max_message: usize,
    max_ranges: usize,
    /// Received bytes at their stream offsets; unreceived gaps are zero.
    buffer: Vec<u8>,
    /// Non-overlapping received pieces before the header is complete. Fully repeated
    /// bytes allocate nothing; fragment count and total bytes are bounded.
    pending: Vec<(usize, Vec<u8>)>,
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
            pending: Vec::new(),
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
        if self.expected.is_none() {
            return self.take_in_pending(range, data);
        }
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
        Ok(())
    }

    fn take_in_pending(
        &mut self,
        range: core::ops::Range<usize>,
        data: &[u8],
    ) -> Result<(), CaptureError> {
        for (offset, held) in &self.pending {
            let start = (*offset).max(range.start);
            let stop = (offset + held.len()).min(range.end);
            if start < stop
                && held[start - offset..stop - offset]
                    != data[start - range.start..stop - range.start]
            {
                return Err(CaptureError::Malformed("conflicting CRYPTO overlap"));
            }
        }
        if (0..HEADER).all(|byte| range.contains(&byte) || self.received.contains(byte as u64)) {
            // The header-completing fragment can be copied straight into the final
            // buffer, even when all sparse slots are already occupied.
            let end = range.end.min(HEADER);
            if range.start < end {
                self.buffer.resize(self.buffer.len().max(end), 0);
                self.buffer[range.start..end].copy_from_slice(&data[..end - range.start]);
            }
            self.received.insert(range.start as u64..range.end as u64);
            within(self.received.len(), self.max_ranges, "CRYPTO fragments")?;
            self.read_header()?;
            let end = range.end.min(self.buffer.len());
            if range.start < end {
                self.buffer[range.start..end].copy_from_slice(&data[..end - range.start]);
            }
            return Ok(());
        }
        // Retain only uncovered pieces. Retransmissions cannot amplify allocations,
        // and the sparse metadata has its own fragment bound, including adjacent pieces.
        let mut uncovered = Vec::new();
        let mut start = range.start;
        for held in self.received.iter() {
            let held_start = held.start as usize;
            let held_end = held.end as usize;
            if held_end <= start {
                continue;
            }
            if held_start >= range.end {
                break;
            }
            if start < held_start {
                uncovered.push(start..held_start);
            }
            start = start.max(held_end);
            if start >= range.end {
                break;
            }
        }
        if start < range.end {
            uncovered.push(start..range.end);
        }
        within(
            self.pending.len().saturating_add(uncovered.len()),
            self.max_ranges,
            "CRYPTO fragments",
        )?;
        for piece in uncovered {
            self.pending.push((
                piece.start,
                data[piece.start - range.start..piece.end - range.start].to_vec(),
            ));
        }
        // Keep only the four header bytes contiguous until every one has arrived.
        if range.start < HEADER {
            let end = range.end.min(HEADER);
            self.buffer.resize(self.buffer.len().max(end), 0);
            self.buffer[range.start..end].copy_from_slice(&data[..end - range.start]);
        }
        self.received.insert(range.start as u64..range.end as u64);
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
            Some(first) if first.start == 0 => {
                &self.buffer[..(first.end as usize).min(self.buffer.len())]
            }
            _ => &[],
        }
    }

    fn read_header(&mut self) -> Result<(), CaptureError> {
        let length = client_hello_message_size(&self.buffer[..HEADER], self.max_message)
            .map_err(|error| match error {
                ClientHelloMessageError::Invalid => CaptureError::Malformed("expected ClientHello"),
                ClientHelloMessageError::TooLarge => {
                    CaptureError::LimitExceeded("ClientHello bytes")
                }
            })?
            .ok_or(CaptureError::Malformed("ClientHello header"))?;
        self.expected = Some(length);
        let held_end = self
            .received
            .iter()
            .next_back()
            .map_or(0, |held| held.end as usize)
            .min(length);
        let mut buffer = Vec::with_capacity(length);
        buffer.resize(held_end, 0);
        for (offset, data) in core::mem::take(&mut self.pending) {
            if offset < held_end {
                let end = (offset + data.len()).min(held_end);
                buffer[offset..end].copy_from_slice(&data[..end - offset]);
            }
        }
        self.buffer = buffer;
        let _trimmed = self.received.remove(length as u64..u64::MAX);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
