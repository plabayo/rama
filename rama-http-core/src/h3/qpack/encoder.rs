//! The stateful QPACK encoder (RFC 9204 §2.1): builds encoded field sections, optionally inserting
//! into its dynamic table and referencing it, while never referencing an entry the decoder may not
//! have and never evicting one still referenced by an unacknowledged section.
//!
//! The insertion policy is deliberately simple rather than optimal: it inserts a full match when
//! space and the blocking budget allow, and otherwise falls back to a name reference or a literal.
//! It always produces correct, decodable output, including with a zero-capacity table (static and
//! literal only), and processes the decoder stream to release references and advance its Known
//! Received Count.

use std::collections::{BTreeMap, VecDeque};

use rama_core::bytes::{Bytes, BytesMut};
use rama_http_types::proto::h3::qpack::{
    DecoderInstruction, EncoderInstruction, FieldLine, HeaderPrefix, PrefixError, static_table,
};

use super::dynamic_table::{DynamicTable, InsertError, entry_size};
use super::error::QpackError;

/// Configuration for an [`Encoder`].
#[derive(Clone, Copy, Debug)]
pub struct EncoderConfig {
    /// The peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: the largest table the peer will keep.
    pub max_table_capacity: u64,
    /// The peer's `SETTINGS_QPACK_BLOCKED_STREAMS`: how many streams may block the decoder.
    pub max_blocked_streams: u64,
    /// The capacity to actually use, clamped to `max_table_capacity`. Zero disables the dynamic
    /// table (static + literal only).
    pub target_capacity: u64,
    /// Whether to Huffman-encode literal strings.
    pub huffman: bool,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: 4096,
            max_blocked_streams: 16,
            target_capacity: 4096,
            huffman: true,
        }
    }
}

struct Section {
    refs: Vec<u64>,
    required_insert_count: u64,
}

/// A stateful QPACK encoder for one connection.
pub struct Encoder {
    config: EncoderConfig,
    table: DynamicTable,
    encoder_output: BytesMut,
    known_received_count: u64,
    capacity_initialized: bool,
    /// Outstanding sections per stream, oldest first (Section Acknowledgments arrive in order).
    sections: BTreeMap<u64, VecDeque<Section>>,
}

impl Encoder {
    /// Create an encoder with the given configuration.
    #[must_use]
    pub fn new(config: EncoderConfig) -> Self {
        let capacity = config.target_capacity.min(config.max_table_capacity);
        Self {
            config: EncoderConfig {
                target_capacity: capacity,
                ..config
            },
            table: DynamicTable::new(config.max_table_capacity),
            encoder_output: BytesMut::new(),
            known_received_count: 0,
            capacity_initialized: false,
            sections: BTreeMap::new(),
        }
    }

    /// The encoder's Known Received Count: how many inserts the decoder has acknowledged.
    #[must_use]
    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }

    /// The encoder's dynamic-table insert count.
    #[must_use]
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count()
    }

    /// The number of field sections currently tracked awaiting acknowledgment (test-only; a section
    /// with no dynamic references is not tracked, so this stays bounded under static-only traffic).
    #[cfg(test)]
    pub(crate) fn tracked_section_count(&self) -> usize {
        self.sections.values().map(VecDeque::len).sum()
    }

    /// Take the queued encoder-stream bytes to send to the peer, leaving the queue empty.
    pub fn take_encoder_stream(&mut self) -> Bytes {
        self.encoder_output.split().freeze()
    }

    /// The number of streams currently blocking the decoder (a section with RIC above KRC).
    fn blocking_stream_count(&self) -> u64 {
        self.sections
            .values()
            .filter(|q| {
                q.iter()
                    .any(|s| s.required_insert_count > self.known_received_count)
            })
            .count() as u64
    }

    fn is_stream_blocking(&self, stream_id: u64) -> bool {
        self.sections.get(&stream_id).is_some_and(|q| {
            q.iter()
                .any(|s| s.required_insert_count > self.known_received_count)
        })
    }

    fn ensure_capacity(&mut self) {
        if self.capacity_initialized {
            return;
        }
        self.capacity_initialized = true;
        if self.config.target_capacity > 0 {
            let ok = self.table.set_capacity(self.config.target_capacity);
            debug_assert!(ok);
            EncoderInstruction::SetDynamicTableCapacity {
                capacity: self.config.target_capacity,
            }
            .encode(&mut self.encoder_output);
        }
    }

    /// Whether making (or keeping) `stream_id` a blocking stream is within the peer's budget.
    fn may_block(&self, stream_id: u64) -> bool {
        if self.is_stream_blocking(stream_id) {
            return true;
        }
        self.blocking_stream_count() < self.config.max_blocked_streams
    }

    /// Encode a field section for `stream_id` from `fields` (name/value byte pairs).
    ///
    /// Returns the encoded field section to place in a HEADERS frame; any dynamic-table inserts are
    /// queued on the encoder stream (retrieve with [`Encoder::take_encoder_stream`]).
    pub fn encode<I, N, V>(&mut self, stream_id: u64, fields: I) -> Bytes
    where
        I: IntoIterator<Item = (N, V)>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.ensure_capacity();

        let mut lines: Vec<FieldLine> = Vec::new();
        let mut refs: Vec<u64> = Vec::new();
        let mut max_ref_abs: Option<u64> = None;

        for (name, value) in fields {
            let name = name.as_ref();
            let value = value.as_ref();
            let line = self.encode_field(stream_id, name, value, &mut refs, &mut max_ref_abs);
            lines.push(line);
        }

        // Base = current insert count; all dynamic references are pre-Base relative indices.
        let base = self.table.insert_count();
        let required_insert_count = max_ref_abs.map_or(0, |abs| abs + 1);

        let mut out = BytesMut::new();
        HeaderPrefix::new(required_insert_count, base).encode(&mut out, self.table.max_entries());
        for line in &lines {
            // rewrite dynamic references now that Base is known
            encode_line(&mut out, line, base);
        }

        // Only sections that reference the dynamic table are acknowledged (RFC 9204 §4.4.1), so
        // only those are tracked; a static/literal section (RIC=0) holds no references to release.
        if required_insert_count > 0 {
            self.sections
                .entry(stream_id)
                .or_default()
                .push_back(Section {
                    refs,
                    required_insert_count,
                });
        }

        out.freeze()
    }

    /// Record and immediately protect a reference to dynamic entry `abs` for the section being
    /// built, so a later insert in the same section cannot evict it (RFC 9204 §2.1.1.1).
    fn reference(&mut self, abs: u64, refs: &mut Vec<u64>, max_ref_abs: &mut Option<u64>) {
        refs.push(abs);
        *max_ref_abs = Some(max_ref_abs.map_or(abs, |m| m.max(abs)));
        self.table.add_ref(abs);
    }

    /// Choose a representation for one field, possibly inserting into the dynamic table.
    fn encode_field(
        &mut self,
        stream_id: u64,
        name: &[u8],
        value: &[u8],
        refs: &mut Vec<u64>,
        max_ref_abs: &mut Option<u64>,
    ) -> FieldLine {
        // 1) exact static match
        if let Some(index) = static_table::find(name, value) {
            return FieldLine::Indexed {
                is_static: true,
                index: index as u64,
            };
        }

        // 2) exact dynamic match, if referenceable
        if let Some(abs) = self.table.find(name, value)
            && self.can_reference(stream_id, abs)
        {
            self.reference(abs, refs, max_ref_abs);
            // stored as absolute; rewritten to a relative index at Base time
            return FieldLine::Indexed {
                is_static: false,
                index: abs,
            };
        }

        // 3) try to insert an exact entry and reference it
        if self.try_insert(stream_id, name, value) {
            let abs = self.table.insert_count() - 1;
            self.reference(abs, refs, max_ref_abs);
            return FieldLine::Indexed {
                is_static: false,
                index: abs,
            };
        }

        // 4) name reference: static, then dynamic
        if let Some(index) = static_table::find_name(name) {
            return FieldLine::LiteralWithNameRef {
                never_index: false,
                is_static: true,
                name_index: index as u64,
                value: Bytes::copy_from_slice(value),
                value_huffman: self.config.huffman,
            };
        }
        if let Some(abs) = self.table.find_name(name)
            && self.can_reference(stream_id, abs)
        {
            self.reference(abs, refs, max_ref_abs);
            return FieldLine::LiteralWithNameRef {
                never_index: false,
                is_static: false,
                name_index: abs,
                value: Bytes::copy_from_slice(value),
                value_huffman: self.config.huffman,
            };
        }

        // 5) literal name and value
        FieldLine::LiteralWithLiteralName {
            never_index: false,
            name: Bytes::copy_from_slice(name),
            name_huffman: self.config.huffman,
            value: Bytes::copy_from_slice(value),
            value_huffman: self.config.huffman,
        }
    }

    /// Whether referencing dynamic entry `abs` from `stream_id` is safe and within budget.
    fn can_reference(&self, stream_id: u64, abs: u64) -> bool {
        if abs < self.known_received_count {
            // decoder already has it; never blocks
            return true;
        }
        // referencing an unacknowledged entry makes the stream blocking
        self.may_block(stream_id)
    }

    /// Attempt to insert `(name, value)`; returns whether it was inserted (and an instruction was
    /// queued). Fails safely (returns false) when the table cannot take it or blocking is exhausted.
    fn try_insert(&mut self, stream_id: u64, name: &[u8], value: &[u8]) -> bool {
        if self.config.target_capacity == 0 {
            return false;
        }
        if entry_size(name, value) > self.table.capacity() {
            return false;
        }
        // a fresh entry is above KRC, so referencing it will make the stream blocking
        if !self.may_block(stream_id) {
            return false;
        }

        // Prefer inserting with a static name reference when the name exists statically.
        let name_bytes = Bytes::copy_from_slice(name);
        let value_bytes = Bytes::copy_from_slice(value);
        match self
            .table
            .insert(name_bytes.clone(), value_bytes.clone(), true)
        {
            Ok(_) => {
                let instruction = if let Some(index) = static_table::find_name(name) {
                    EncoderInstruction::InsertWithNameRef {
                        is_static: true,
                        name_index: index as u64,
                        value: value_bytes,
                        value_huffman: self.config.huffman,
                    }
                } else {
                    EncoderInstruction::InsertWithLiteralName {
                        name: name_bytes,
                        name_huffman: self.config.huffman,
                        value: value_bytes,
                        value_huffman: self.config.huffman,
                    }
                };
                instruction.encode(&mut self.encoder_output);
                true
            }
            Err(InsertError::TooLarge | InsertError::Blocked) => false,
        }
    }

    /// Process one instruction received on the peer's decoder stream (RFC 9204 §4.4).
    pub fn on_decoder_instruction(&mut self, inst: DecoderInstruction) -> Result<(), QpackError> {
        match inst {
            DecoderInstruction::InsertCountIncrement { increment } => {
                let new = self.known_received_count.checked_add(increment).ok_or(
                    QpackError::DecoderStreamError("insert count increment overflow"),
                )?;
                if new > self.table.insert_count() {
                    return Err(QpackError::DecoderStreamError(
                        "insert count increment exceeds inserts",
                    ));
                }
                self.known_received_count = new;
                Ok(())
            }
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                let queue =
                    self.sections
                        .get_mut(&stream_id)
                        .ok_or(QpackError::DecoderStreamError(
                            "acknowledgment for unknown section",
                        ))?;
                let section = queue.pop_front().ok_or(QpackError::DecoderStreamError(
                    "acknowledgment for unknown section",
                ))?;
                if queue.is_empty() {
                    self.sections.remove(&stream_id);
                }
                // Section Acknowledgment implies the decoder reached this section's RIC.
                self.known_received_count =
                    self.known_received_count.max(section.required_insert_count);
                for abs in section.refs {
                    self.table.release_ref(abs);
                }
                Ok(())
            }
            DecoderInstruction::StreamCancellation { stream_id } => {
                if let Some(queue) = self.sections.remove(&stream_id) {
                    for section in queue {
                        for abs in section.refs {
                            self.table.release_ref(abs);
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Feed raw decoder-stream bytes, applying every complete instruction (transactional).
    pub fn feed_decoder_stream(&mut self, input: &[u8]) -> Result<(), QpackError> {
        let mut buf = input;
        loop {
            let mut cursor = buf;
            match DecoderInstruction::decode(&mut cursor) {
                Ok(inst) => {
                    buf = cursor;
                    self.on_decoder_instruction(inst)?;
                }
                Err(PrefixError::UnexpectedEnd) => break,
                Err(_) => {
                    return Err(QpackError::DecoderStreamError(
                        "malformed decoder-stream instruction",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Serialize one field line, rewriting an absolute dynamic index into the Base-relative or
/// post-Base form.
fn encode_line(out: &mut BytesMut, line: &FieldLine, base: u64) {
    let rewritten = match line {
        FieldLine::Indexed {
            is_static: false,
            index: abs,
        } => dynamic_indexed(*abs, base),
        FieldLine::LiteralWithNameRef {
            never_index,
            is_static: false,
            name_index: abs,
            value,
            value_huffman,
        } => dynamic_literal_name_ref(*abs, base, *never_index, value.clone(), *value_huffman),
        other => other.clone(),
    };
    rewritten.encode(out);
}

/// Encode an Indexed dynamic field line for absolute index `abs` under `base`.
fn dynamic_indexed(abs: u64, base: u64) -> FieldLine {
    if abs < base {
        FieldLine::Indexed {
            is_static: false,
            index: base - abs - 1,
        }
    } else {
        FieldLine::IndexedPostBase { index: abs - base }
    }
}

fn dynamic_literal_name_ref(
    abs: u64,
    base: u64,
    never_index: bool,
    value: Bytes,
    value_huffman: bool,
) -> FieldLine {
    if abs < base {
        FieldLine::LiteralWithNameRef {
            never_index,
            is_static: false,
            name_index: base - abs - 1,
            value,
            value_huffman,
        }
    } else {
        FieldLine::LiteralWithPostBaseNameRef {
            never_index,
            name_index: abs - base,
            value,
            value_huffman,
        }
    }
}
