//! Bounded, incremental Capsule Protocol decoding (RFC 9297 §3).
//!
//! Input arrives in arbitrary [`Bytes`] chunks, exactly as a data stream delivers it. Capsule
//! Values are never collected unless the application asked for them: DATAGRAM payloads up to
//! [`CapsuleConfig::max_datagram_size`] and registered control capsules up to
//! [`CapsuleConfig::max_capsule_size`]. Everything else is skipped or, for intermediaries,
//! streamed as it arrives, so flow-control credit is always released (RFC 9297 §3.2, §3.5).

use rama_core::bytes::{Buf, BufMut, Bytes, BytesMut};
use rama_http_types::proto::{
    capsule::{CapsuleHeader, CapsuleType, InvalidCapsule},
    h3::{VarInt, VarIntDecoder},
};
use rama_utils::octets::kib;
use std::fmt;

/// Limits and policy for [`CapsuleDecoder`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsuleConfig {
    /// Largest DATAGRAM capsule payload delivered. Larger ones are discarded without
    /// buffering (RFC 9297 §3.5) and counted.
    pub max_datagram_size: usize,
    /// Largest registered control capsule value; exceeding it is a protocol error.
    pub max_capsule_size: usize,
    /// Control capsule types delivered to the application, buffered whole.
    pub capsule_types: Box<[CapsuleType]>,
    /// What happens to other capsule types.
    pub unknown: UnknownCapsules,
}

impl Default for CapsuleConfig {
    fn default() -> Self {
        Self {
            // RFC 9221 recommends accepting DATAGRAM frames of up to 65535 bytes.
            max_datagram_size: kib(64),
            max_capsule_size: kib(16),
            capsule_types: Box::default(),
            unknown: UnknownCapsules::Skip,
        }
    }
}

/// Handling of capsule types the application did not register.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownCapsules {
    /// Silently skip them, as endpoints must (RFC 9297 §3.2).
    #[default]
    Skip,
    /// Emit them unmodified and incrementally, as forwarding intermediaries should.
    Forward,
}

/// An event produced by [`CapsuleDecoder::poll`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CapsuleEvent {
    /// A complete DATAGRAM capsule payload.
    Datagram(Bytes),
    /// A complete registered control capsule.
    Capsule {
        /// The capsule type.
        ty: CapsuleType,
        /// The complete capsule value.
        value: Bytes,
    },
    /// The header of an unregistered capsule in [`UnknownCapsules::Forward`] mode.
    /// `length` value bytes follow as [`CapsuleEvent::UnknownData`].
    Unknown(CapsuleHeader),
    /// A chunk of the current forwarded capsule value.
    UnknownData(Bytes),
}

/// A Capsule Protocol violation. The data stream must be treated as a malformed or
/// incomplete message (RFC 9297 §3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleError {
    /// A registered control capsule exceeded [`CapsuleConfig::max_capsule_size`].
    TooLarge {
        /// The capsule type.
        ty: CapsuleType,
        /// The advertised value length.
        length: u64,
    },
    /// The data stream ended inside a capsule.
    Truncated,
    /// The previous input has not been drained with [`CapsuleDecoder::poll`]. This is a
    /// local usage error, not a peer violation.
    InputNotDrained,
}

impl fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { ty, length } => write!(f, "capsule {ty:?} too large ({length} bytes)"),
            Self::Truncated => f.write_str("data stream ended inside a capsule"),
            Self::InputNotDrained => f.write_str("capsule decoder input not drained"),
        }
    }
}

impl std::error::Error for CapsuleError {}

enum State {
    Type,
    Length(CapsuleType),
    Buffer { ty: CapsuleType, length: usize },
    Skip(u64),
    Forward(u64),
}

/// An incremental Capsule Protocol decoder.
pub struct CapsuleDecoder {
    config: CapsuleConfig,
    inbox: Bytes,
    state: State,
    varint: VarIntDecoder,
    value: BytesMut,
    dropped_datagrams: u64,
}

impl fmt::Debug for CapsuleDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapsuleDecoder")
            .field("config", &self.config)
            .field("buffered", &(self.inbox.len() + self.value.len()))
            .field("dropped_datagrams", &self.dropped_datagrams)
            .finish_non_exhaustive()
    }
}

impl CapsuleDecoder {
    /// Create a decoder with the given limits and policy.
    #[must_use]
    pub fn new(config: CapsuleConfig) -> Self {
        Self {
            config,
            inbox: Bytes::new(),
            state: State::Type,
            varint: VarIntDecoder::new(),
            value: BytesMut::new(),
            dropped_datagrams: 0,
        }
    }

    /// Supply the next chunk of the data stream. Drain [`Self::poll`] first.
    pub fn feed(&mut self, input: Bytes) -> Result<(), CapsuleError> {
        if !self.inbox.is_empty() {
            return Err(CapsuleError::InputNotDrained);
        }
        self.inbox = input;
        Ok(())
    }

    /// Whether all fed input has been consumed.
    #[must_use]
    pub fn is_drained(&self) -> bool {
        self.inbox.is_empty()
    }

    /// Oversized DATAGRAM capsules discarded so far.
    #[must_use]
    pub fn dropped_datagrams(&self) -> u64 {
        self.dropped_datagrams
    }

    /// Check that a cleanly ended data stream did not end inside a capsule (RFC 9297 §3.3).
    pub fn finish(&self) -> Result<(), CapsuleError> {
        if self.inbox.is_empty() && matches!(self.state, State::Type) && !self.varint.in_progress()
        {
            Ok(())
        } else {
            Err(CapsuleError::Truncated)
        }
    }

    /// Decode the next event, or `None` once more input is needed.
    pub fn poll(&mut self) -> Result<Option<CapsuleEvent>, CapsuleError> {
        loop {
            match self.state {
                State::Type => {
                    let Some(value) = self.varint.decode(&mut self.inbox) else {
                        return Ok(None);
                    };
                    self.state = State::Length(CapsuleType::from(value));
                }
                State::Length(ty) => {
                    let Some(length) = self.varint.decode(&mut self.inbox) else {
                        return Ok(None);
                    };
                    if let Some(event) = self.begin(ty, length)? {
                        return Ok(Some(event));
                    }
                }
                State::Buffer { ty, length } => {
                    // Contiguous values share input storage; fragments are coalesced.
                    if self.value.is_empty() && self.inbox.len() >= length {
                        let value = self.inbox.split_to(length);
                        self.state = State::Type;
                        return Ok(Some(Self::complete(ty, value)));
                    }
                    let take = (length - self.value.len()).min(self.inbox.len());
                    if take == 0 {
                        return Ok(None);
                    }
                    self.value.put(self.inbox.split_to(take));
                    if self.value.len() == length {
                        let value = self.value.split().freeze();
                        self.state = State::Type;
                        return Ok(Some(Self::complete(ty, value)));
                    }
                }
                State::Skip(remaining) => {
                    let take = remaining.min(self.inbox.len() as u64);
                    self.inbox.advance(take as usize);
                    if take == remaining {
                        self.state = State::Type;
                    } else {
                        self.state = State::Skip(remaining - take);
                        return Ok(None);
                    }
                }
                State::Forward(remaining) => {
                    if remaining == 0 {
                        self.state = State::Type;
                        continue;
                    }
                    let take = remaining.min(self.inbox.len() as u64);
                    if take == 0 {
                        return Ok(None);
                    }
                    self.state = State::Forward(remaining - take);
                    return Ok(Some(CapsuleEvent::UnknownData(
                        self.inbox.split_to(take as usize),
                    )));
                }
            }
        }
    }

    fn begin(
        &mut self,
        ty: CapsuleType,
        length: VarInt,
    ) -> Result<Option<CapsuleEvent>, CapsuleError> {
        let size = length.into_inner();
        if ty == CapsuleType::DATAGRAM {
            if size > self.config.max_datagram_size as u64 {
                self.dropped_datagrams += 1;
                self.state = State::Skip(size);
            } else {
                self.state = State::Buffer {
                    ty,
                    length: size as usize,
                };
            }
            return Ok(None);
        }
        if self.config.capsule_types.contains(&ty) {
            if size > self.config.max_capsule_size as u64 {
                return Err(CapsuleError::TooLarge { ty, length: size });
            }
            self.state = State::Buffer {
                ty,
                length: size as usize,
            };
            return Ok(None);
        }
        match self.config.unknown {
            UnknownCapsules::Skip => {
                self.state = State::Skip(size);
                Ok(None)
            }
            UnknownCapsules::Forward => {
                self.state = State::Forward(size);
                Ok(Some(CapsuleEvent::Unknown(CapsuleHeader { ty, length })))
            }
        }
    }

    fn complete(ty: CapsuleType, value: Bytes) -> CapsuleEvent {
        if ty == CapsuleType::DATAGRAM {
            CapsuleEvent::Datagram(value)
        } else {
            CapsuleEvent::Capsule { ty, value }
        }
    }
}

/// Encode a complete capsule into one buffer.
pub fn encode_capsule(ty: CapsuleType, value: &[u8]) -> Result<Bytes, InvalidCapsule> {
    let header = CapsuleHeader::new(ty, value.len() as u64)?;
    let mut encoded = BytesMut::with_capacity(header.size() + value.len());
    header.encode(&mut encoded);
    encoded.extend_from_slice(value);
    Ok(encoded.freeze())
}

#[cfg(test)]
mod tests;
