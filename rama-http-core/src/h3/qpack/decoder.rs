//! The stateful QPACK decoder (RFC 9204 §2.2): applies encoder-stream instructions to a dynamic
//! table, decodes field sections against it, tracks blocked streams within a budget, and produces
//! the decoder-stream acknowledgements the peer's encoder needs.
//!
//! HTTP semantic validation is deliberately *not* performed here: the decoder emits raw field lines
//! and always advances its compression state, so a message that is later rejected for HTTP reasons
//! cannot desynchronize QPACK (RFC 9204 §2.2, and the sprint's separation requirement).

use std::collections::{BTreeMap, VecDeque};

use rama_core::bytes::{Buf, Bytes, BytesMut};
use rama_http_types::proto::h3::qpack::{
    DecoderInstruction, EncoderInstruction, FieldLine, HeaderPrefix, PrefixError, static_table,
};

use super::dynamic_table::{DynamicTable, InsertError};
use super::error::QpackError;

/// A decoded field line (raw bytes; HTTP validation happens elsewhere).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldPair {
    /// The field name.
    pub name: Bytes,
    /// The field value.
    pub value: Bytes,
}

/// Configuration limits for a [`Decoder`].
#[derive(Clone, Copy, Debug)]
pub struct DecoderConfig {
    /// The maximum dynamic-table capacity to advertise (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`).
    pub max_table_capacity: u64,
    /// The maximum number of streams that may be blocked at once (`SETTINGS_QPACK_BLOCKED_STREAMS`).
    pub max_blocked_streams: u64,
    /// The maximum decoded field-section size, and the bound on any single decoded string.
    pub max_field_section_size: usize,
    /// The maximum bytes of blocked field sections retained across all blocked streams.
    pub max_blocked_bytes: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: 4096,
            max_blocked_streams: 16,
            max_field_section_size: 64 * 1024,
            max_blocked_bytes: 256 * 1024,
        }
    }
}

struct BlockedSection {
    /// The prefix reconstructed when the section first arrived. It is kept rather than recomputed on
    /// resume: reconstruction (RFC 9204 §4.5.1.1) depends on the insert count at read time, which
    /// grows before the section unblocks, so re-decoding it later would yield a different value.
    prefix: HeaderPrefix,
    /// The field-line bytes (the section after its prefix).
    body: Bytes,
    /// The retained byte size, for the blocked-storage budget.
    size: usize,
}

/// A stateful QPACK decoder for one connection.
pub struct Decoder {
    config: DecoderConfig,
    table: DynamicTable,
    /// Retained, not-yet-complete bytes of the peer's encoder stream.
    encoder_stream: BytesMut,
    /// Queued decoder-stream instructions to send to the peer's encoder.
    decoder_output: BytesMut,
    /// Field sections waiting for the Required Insert Count to be reached, in arrival order per
    /// stream so a stream's sections are still delivered in order.
    blocked: BTreeMap<u64, VecDeque<BlockedSection>>,
    /// Total bytes retained in `blocked`.
    blocked_bytes: usize,
}

impl Decoder {
    /// Create a decoder with the given limits.
    #[must_use]
    pub fn new(config: DecoderConfig) -> Self {
        Self {
            table: DynamicTable::new(config.max_table_capacity),
            config,
            encoder_stream: BytesMut::new(),
            decoder_output: BytesMut::new(),
            blocked: BTreeMap::new(),
            blocked_bytes: 0,
        }
    }

    /// The decoder's current dynamic-table insert count.
    #[must_use]
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count()
    }

    /// The number of currently blocked streams.
    #[must_use]
    pub fn blocked_stream_count(&self) -> usize {
        self.blocked.len()
    }

    /// Take the queued decoder-stream bytes to send to the peer, leaving the queue empty.
    pub fn take_decoder_stream(&mut self) -> Bytes {
        self.decoder_output.split().freeze()
    }

    /// The maximum size a full encoder-stream instruction may occupy before it is rejected as a
    /// resource-exhaustion attempt. Strings within an instruction are bounded by the field-section
    /// limit, so a complete instruction cannot legitimately exceed roughly twice that plus headers.
    fn max_instruction_bytes(&self) -> usize {
        self.config
            .max_field_section_size
            .saturating_mul(2)
            .saturating_add(64)
    }

    /// Feed bytes received on the peer's encoder stream, applying every complete instruction.
    ///
    /// Retains a trailing partial instruction for the next call (transactional), and emits Insert
    /// Count Increment for entries inserted. Any newly unblocked streams should then be collected
    /// with [`Decoder::resume_blocked`].
    pub fn feed_encoder_stream(&mut self, input: &[u8]) -> Result<(), QpackError> {
        self.encoder_stream.extend_from_slice(input);
        let mut inserted = 0u64;
        loop {
            let mut cursor: &[u8] = &self.encoder_stream;
            match EncoderInstruction::decode(&mut cursor, self.config.max_field_section_size) {
                Ok(inst) => {
                    let consumed = self.encoder_stream.len() - cursor.len();
                    if self.apply_encoder_instruction(inst)? {
                        inserted += 1;
                    }
                    self.encoder_stream.advance(consumed);
                }
                Err(PrefixError::UnexpectedEnd) => break,
                Err(PrefixError::LengthLimitExceeded) => {
                    return Err(QpackError::EncoderStreamError(
                        "encoder-stream string too large",
                    ));
                }
                Err(_) => {
                    return Err(QpackError::EncoderStreamError(
                        "malformed encoder-stream instruction",
                    ));
                }
            }
        }
        if self.encoder_stream.len() > self.max_instruction_bytes() {
            return Err(QpackError::EncoderStreamError(
                "encoder-stream instruction too large",
            ));
        }
        if inserted > 0 {
            DecoderInstruction::InsertCountIncrement {
                increment: inserted,
            }
            .encode(&mut self.decoder_output);
        }
        Ok(())
    }

    /// Apply one encoder-stream instruction. Returns whether it inserted an entry.
    fn apply_encoder_instruction(&mut self, inst: EncoderInstruction) -> Result<bool, QpackError> {
        match inst {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                if !self.table.set_capacity(capacity) {
                    return Err(QpackError::EncoderStreamError(
                        "dynamic table capacity exceeds the advertised maximum",
                    ));
                }
                Ok(false)
            }
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                ..
            } => {
                let name = if is_static {
                    static_table::get(usize_index(name_index)?)
                        .ok_or(QpackError::EncoderStreamError("bad static name index"))?
                        .0
                        .into()
                } else {
                    // encoder-stream relative index: abs = insert_count - 1 - rel
                    let abs = self.encoder_relative_to_abs(name_index)?;
                    self.table
                        .get(abs)
                        .ok_or(QpackError::EncoderStreamError("bad dynamic name index"))?
                        .0
                };
                self.insert(name, value)
            }
            EncoderInstruction::InsertWithLiteralName { name, value, .. } => {
                self.insert(name, value)
            }
            EncoderInstruction::Duplicate { index } => {
                let abs = self.encoder_relative_to_abs(index)?;
                let (name, value) = self
                    .table
                    .get(abs)
                    .ok_or(QpackError::EncoderStreamError("bad duplicate index"))?;
                self.insert(name, value)
            }
        }
    }

    fn encoder_relative_to_abs(&self, rel: u64) -> Result<u64, QpackError> {
        // abs = insert_count - 1 - rel (RFC 9204 §3.2.5)
        self.table
            .insert_count()
            .checked_sub(1)
            .and_then(|top| top.checked_sub(rel))
            .ok_or(QpackError::EncoderStreamError("dynamic index out of range"))
    }

    fn insert(&mut self, name: Bytes, value: Bytes) -> Result<bool, QpackError> {
        match self.table.insert(name, value, false) {
            Ok(_) => Ok(true),
            Err(InsertError::TooLarge) => Err(QpackError::EncoderStreamError(
                "inserted entry exceeds table capacity",
            )),
            // the decoder never withholds eviction, so Blocked cannot occur
            Err(InsertError::Blocked) => Err(QpackError::EncoderStreamError("eviction blocked")),
        }
    }

    /// Decode a complete encoded field section received on stream `stream_id`.
    ///
    /// The full section must be buffered by the caller (the frame layer bounds its length first).
    /// Returns `Ok(Some(fields))` when it decodes immediately, or `Ok(None)` when it is blocked on
    /// the Required Insert Count, in which case it is retained (subject to the blocked budget) and
    /// returned later by [`Decoder::resume_blocked`].
    ///
    /// Takes the section by value so a blocked section is retained as a zero-copy slice of the same
    /// allocation rather than a copy.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "ownership lets a blocked section be retained as a zero-copy slice"
    )]
    pub fn decode_field_section(
        &mut self,
        stream_id: u64,
        encoded: Bytes,
    ) -> Result<Option<Vec<FieldPair>>, QpackError> {
        let mut cursor: &[u8] = &encoded;
        let insert_count = self.table.insert_count();
        let prefix = HeaderPrefix::decode(&mut cursor, self.table.max_entries(), insert_count)?;
        let consumed = encoded.len() - cursor.len();
        let body = encoded.slice(consumed..);

        // If earlier sections on this stream are still blocked, this one queues behind them even if
        // its own Required Insert Count is already met, so the stream's sections stay in order.
        let already_blocked = self.blocked.get(&stream_id).is_some_and(|q| !q.is_empty());

        if !already_blocked && prefix.required_insert_count <= insert_count {
            return Ok(Some(self.decode_body(stream_id, &prefix, &body)?));
        }

        // blocked: enforce budgets before retaining
        if !already_blocked && self.blocked.len() as u64 >= self.config.max_blocked_streams {
            return Err(QpackError::DecompressionFailed("too many blocked streams"));
        }
        let size = encoded.len();
        if self.blocked_bytes.saturating_add(size) > self.config.max_blocked_bytes {
            return Err(QpackError::DecompressionFailed(
                "blocked field-section storage exceeded",
            ));
        }
        self.blocked_bytes += size;
        self.blocked
            .entry(stream_id)
            .or_default()
            .push_back(BlockedSection { prefix, body, size });
        Ok(None)
    }

    /// Decode and remove blocked sections whose Required Insert Count is now satisfied.
    ///
    /// Each stream's sections are resumed front-first and only while the front is ready, so a
    /// stream's sections are never delivered out of order. A decode failure is reported per stream.
    pub fn resume_blocked(&mut self) -> Vec<(u64, Result<Vec<FieldPair>, QpackError>)> {
        let insert_count = self.table.insert_count();
        let mut out = Vec::new();
        let stream_ids: Vec<u64> = self.blocked.keys().copied().collect();
        for stream_id in stream_ids {
            while let Some(section) = self.pop_ready_front(stream_id, insert_count) {
                self.blocked_bytes -= section.size;
                let result = self.decode_body(stream_id, &section.prefix, &section.body);
                out.push((stream_id, result));
            }
        }
        out
    }

    /// Remove and return the front blocked section of `stream_id` when its Required Insert Count is
    /// satisfied, cleaning up the stream's queue when it empties.
    fn pop_ready_front(&mut self, stream_id: u64, insert_count: u64) -> Option<BlockedSection> {
        let queue = self.blocked.get_mut(&stream_id)?;
        let ready = queue
            .front()
            .is_some_and(|s| s.prefix.required_insert_count <= insert_count);
        if !ready {
            return None;
        }
        let section = queue.pop_front();
        if queue.is_empty() {
            self.blocked.remove(&stream_id);
        }
        section
    }

    /// Decode a section's field lines against the current table and acknowledge it if it referenced
    /// the dynamic table (RFC 9204 §4.4.1).
    fn decode_body(
        &mut self,
        stream_id: u64,
        prefix: &HeaderPrefix,
        body: &[u8],
    ) -> Result<Vec<FieldPair>, QpackError> {
        let fields = self.decode_lines(body, prefix)?;
        if prefix.required_insert_count > 0 {
            DecoderInstruction::SectionAcknowledgment { stream_id }
                .encode(&mut self.decoder_output);
        }
        Ok(fields)
    }

    /// Cancel a stream: drop any blocked sections and emit Stream Cancellation (RFC 9204 §4.4.2).
    pub fn cancel_stream(&mut self, stream_id: u64) {
        if let Some(queue) = self.blocked.remove(&stream_id) {
            for section in queue {
                self.blocked_bytes -= section.size;
            }
        }
        DecoderInstruction::StreamCancellation { stream_id }.encode(&mut self.decoder_output);
    }

    fn decode_lines(
        &self,
        mut body: &[u8],
        prefix: &HeaderPrefix,
    ) -> Result<Vec<FieldPair>, QpackError> {
        let mut fields = Vec::new();
        let mut section_size: u64 = 0;
        while body.has_remaining() {
            let line = FieldLine::decode(&mut body, self.config.max_field_section_size)?;
            let pair = self.resolve_line(line, prefix.base)?;
            // account the uncompressed size (RFC 9114 §4.2.2: name + value + 32).
            section_size =
                section_size.saturating_add(pair.name.len() as u64 + pair.value.len() as u64 + 32);
            if section_size > self.config.max_field_section_size as u64 {
                return Err(QpackError::DecompressionFailed("field section too large"));
            }
            fields.push(pair);
        }
        Ok(fields)
    }

    fn resolve_line(&self, line: FieldLine, base: u64) -> Result<FieldPair, QpackError> {
        match line {
            FieldLine::Indexed { is_static, index } => {
                if is_static {
                    let (name, value) = static_get(index)?;
                    Ok(FieldPair {
                        name: name.into(),
                        value: value.into(),
                    })
                } else {
                    let abs = pre_base_abs(base, index)?;
                    let (name, value) = self.dynamic_get(abs)?;
                    Ok(FieldPair { name, value })
                }
            }
            FieldLine::IndexedPostBase { index } => {
                let abs = post_base_abs(base, index)?;
                let (name, value) = self.dynamic_get(abs)?;
                Ok(FieldPair { name, value })
            }
            FieldLine::LiteralWithNameRef {
                is_static,
                name_index,
                value,
                ..
            } => {
                let name = if is_static {
                    static_get(name_index)?.0.into()
                } else {
                    self.dynamic_get(pre_base_abs(base, name_index)?)?.0
                };
                Ok(FieldPair { name, value })
            }
            FieldLine::LiteralWithPostBaseNameRef {
                name_index, value, ..
            } => {
                let name = self.dynamic_get(post_base_abs(base, name_index)?)?.0;
                Ok(FieldPair { name, value })
            }
            FieldLine::LiteralWithLiteralName { name, value, .. } => Ok(FieldPair { name, value }),
        }
    }

    fn dynamic_get(&self, abs: u64) -> Result<(Bytes, Bytes), QpackError> {
        self.table.get(abs).ok_or(QpackError::DecompressionFailed(
            "reference to missing dynamic entry",
        ))
    }
}

fn static_get(index: u64) -> Result<(&'static [u8], &'static [u8]), QpackError> {
    static_table::get(usize_index(index)?)
        .ok_or(QpackError::DecompressionFailed("static index out of range"))
}

/// Absolute index for a Base-relative dynamic reference (RFC 9204 §3.2.4): `Base - Index - 1`.
fn pre_base_abs(base: u64, index: u64) -> Result<u64, QpackError> {
    base.checked_sub(index)
        .and_then(|v| v.checked_sub(1))
        .ok_or(QpackError::DecompressionFailed(
            "dynamic index out of range",
        ))
}

/// Absolute index for a post-Base dynamic reference (RFC 9204 §3.2.6): `Base + Index`.
fn post_base_abs(base: u64, index: u64) -> Result<u64, QpackError> {
    base.checked_add(index)
        .ok_or(QpackError::DecompressionFailed("post-base index overflow"))
}

fn usize_index(index: u64) -> Result<usize, QpackError> {
    match usize::try_from(index) {
        Ok(i) => Ok(i),
        Err(_) => Err(QpackError::DecompressionFailed("index out of range")),
    }
}
