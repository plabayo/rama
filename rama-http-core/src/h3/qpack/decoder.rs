//! The stateful QPACK decoder (RFC 9204 §2.2): applies encoder-stream instructions to a dynamic
//! table, decodes field sections against it, tracks blocked streams within a budget, and produces
//! the decoder-stream acknowledgements the peer's encoder needs.
//!
//! HTTP semantic validation is deliberately *not* performed here: the decoder emits raw field lines
//! and always advances its compression state, so a message that is later rejected for HTTP reasons
//! cannot desynchronize QPACK (RFC 9204 §2.2, and the sprint's separation requirement).

use std::collections::{BTreeMap, VecDeque};

use rama_core::bytes::{Buf, Bytes, BytesMut};
use rama_http_types::proto::h3::VarInt;
use rama_http_types::proto::h3::qpack::prefix::int_encoded_len;
use rama_http_types::proto::h3::qpack::{
    DecoderInstruction, EncoderInstruction, FieldLine, HeaderPrefix, PrefixError, static_table,
};

use rama_utils::octets::{kib, kib_u64};

use super::dynamic_table::{DynamicTable, ENTRY_OVERHEAD, InsertError};
use super::error::QpackError;

/// A decoded field line (raw bytes; HTTP validation happens elsewhere).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldPair {
    /// The field name.
    pub name: Bytes,
    /// The field value.
    pub value: Bytes,
    /// Whether intermediaries must preserve the never-index (N) bit when forwarding.
    pub never_index: bool,
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
    /// Maximum retained field-section payload plus `size_of::<BlockedSection>()` per section.
    /// Collection capacity has bounded constant-factor overhead beyond this accounting.
    pub max_blocked_bytes: usize,
    /// Maximum queued decoder-stream bytes; drain output before retrying `OutputBlocked`.
    /// A zero budget disables output. Small budgets require smaller encoder-stream input batches.
    /// An acknowledgment or cancellation that cannot fit even an empty queue returns
    /// `ResourceLimit`; ten bytes suffice for any valid QUIC stream identifier.
    pub max_decoder_stream_bytes: usize,
}

impl Default for DecoderConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: kib_u64(4),
            max_blocked_streams: 16,
            max_field_section_size: kib(64),
            max_blocked_bytes: kib(256),
            max_decoder_stream_bytes: kib(64),
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
    output_in_flight: usize,
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
            output_in_flight: 0,
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
        self.blocked
            .values()
            .filter(|queue| {
                queue
                    .iter()
                    .any(|section| section.prefix.required_insert_count > self.table.insert_count())
            })
            .count()
    }

    /// Take the queued decoder-stream bytes to send to the peer, leaving the queue empty.
    pub fn take_decoder_stream(&mut self) -> Bytes {
        self.decoder_output.split().freeze()
    }

    pub(crate) fn take_output_for_write(&mut self) -> Bytes {
        let output = self.take_decoder_stream();
        self.output_in_flight += output.len();
        output
    }

    pub(crate) fn output_written(&mut self, bytes: usize) {
        self.output_in_flight -= bytes;
    }

    /// The maximum size a full encoder-stream instruction may occupy before it is rejected as a
    /// resource-exhaustion attempt. Strings are bounded by both the field-section limit and
    /// the current dynamic-table capacity. Huffman codes occupy up to 30 bits per byte, so two strings need
    /// at most eight times that limit plus integer headers.
    fn max_instruction_bytes(&self) -> usize {
        self.max_insert_string_len()
            .saturating_mul(8)
            .saturating_add(64)
    }

    /// No inserted string can exceed the current table capacity minus entry overhead.
    /// Reject impossible inserts before retaining or decoding their literal payloads.
    fn max_insert_string_len(&self) -> usize {
        self.config.max_field_section_size.min(
            usize::try_from(self.table.capacity().saturating_sub(ENTRY_OVERHEAD))
                .unwrap_or(usize::MAX),
        )
    }

    /// Feed bytes received on the peer's encoder stream, applying every complete instruction.
    ///
    /// Retains a trailing partial instruction for the next call (transactional), and emits Insert
    /// Count Increment for entries inserted. Any newly unblocked streams should then be collected
    /// with [`Decoder::resume_blocked`]. `OutputBlocked` consumes no input: drain the decoder
    /// stream and retry. If the queue is already empty, split the input into smaller batches:
    /// reservation bounds the increment by the input byte count. Other errors are fatal connection
    /// errors; do not retry them.
    pub fn feed_encoder_stream(&mut self, input: &[u8]) -> Result<(), QpackError> {
        // Every completed insertion needs at least one newly supplied byte, including completion
        // of a retained instruction. Reserve the resulting upper bound before consuming input.
        if input.is_empty() {
            return Ok(());
        }
        self.reserve_output(int_encoded_len(input.len() as u64, 6))?;
        let mut input = input;
        let mut inserted = 0u64;
        loop {
            if self.encoder_stream.is_empty() {
                match EncoderInstruction::encoded_len(input, self.max_insert_string_len()) {
                    Ok(len) => {
                        let mut cursor = &input[..len];
                        let inst =
                            EncoderInstruction::decode(&mut cursor, self.max_insert_string_len())
                                .map_err(encoder_parse_error)?;
                        if self.apply_encoder_instruction(inst)? {
                            inserted += 1;
                        }
                        input = &input[len..];
                        if input.is_empty() {
                            break;
                        }
                        continue;
                    }
                    Err(PrefixError::UnexpectedEnd) => {}
                    Err(error) => return Err(encoder_parse_error(error)),
                }
            }
            let available = self
                .max_instruction_bytes()
                .saturating_sub(self.encoder_stream.len());
            let append = input.len().min(available);
            self.encoder_stream.extend_from_slice(&input[..append]);
            input = &input[append..];
            loop {
                match EncoderInstruction::encoded_len(
                    &self.encoder_stream,
                    self.max_insert_string_len(),
                ) {
                    Ok(len) => {
                        // Table entries must own compact literals rather than pinning the whole
                        // staging buffer through a tiny Bytes slice.
                        let mut cursor = &self.encoder_stream[..len];
                        let inst =
                            EncoderInstruction::decode(&mut cursor, self.max_insert_string_len())
                                .map_err(encoder_parse_error)?;
                        if self.apply_encoder_instruction(inst)? {
                            inserted += 1;
                        }
                        self.encoder_stream.advance(len);
                    }
                    Err(PrefixError::UnexpectedEnd) => break,
                    Err(error) => return Err(encoder_parse_error(error)),
                }
            }
            if self.encoder_stream.len() == self.max_instruction_bytes() {
                return Err(QpackError::ResourceLimit(
                    "encoder-stream instruction too large",
                ));
            }
            if input.is_empty() {
                break;
            }
        }
        if inserted > 0 {
            DecoderInstruction::InsertCountIncrement {
                increment: inserted,
            }
            .encode(&mut self.decoder_output);
        }
        Ok(())
    }

    fn reserve_output(&self, bytes: usize) -> Result<(), QpackError> {
        if bytes
            > self
                .config
                .max_decoder_stream_bytes
                .saturating_sub(self.decoder_output.len())
                .saturating_sub(self.output_in_flight)
        {
            return Err(QpackError::OutputBlocked);
        }
        Ok(())
    }

    fn reserve_instruction(&self, instruction: DecoderInstruction) -> Result<(), QpackError> {
        // A prefixed u64 occupies at most eleven bytes, so measuring it needs no heap allocation.
        let mut encoded = [0; 11];
        let mut dst = &mut encoded[..];
        instruction.encode(&mut dst);
        let len = 11 - dst.len();
        if len > self.config.max_decoder_stream_bytes {
            return Err(QpackError::ResourceLimit(
                "decoder instruction exceeds output budget",
            ));
        }
        self.reserve_output(len)
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
                    usize::try_from(name_index)
                        .ok()
                        .and_then(static_table::get)
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
        match self.table.insert(name, value, None) {
            Ok(_) => Ok(true),
            Err(InsertError::TooLarge) => Err(QpackError::EncoderStreamError(
                "inserted entry exceeds table capacity",
            )),
            Err(InsertError::InsertCountOverflow) => {
                Err(QpackError::EncoderStreamError("insert count overflow"))
            }
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
    /// Immediately decoded literals share the supplied allocation. Queued sections are compacted
    /// to avoid retaining an arbitrarily large backing allocation through a small slice. Retain a
    /// cheap `Bytes` clone until success: `OutputBlocked` leaves state unchanged, so drain and retry.
    /// On `FieldSectionLimit` or `StreamResourceLimit`, queued sections for this stream are released.
    /// The caller must reset
    /// the stream and call [`Decoder::cancel_stream`] (draining and retrying if necessary) to notify
    /// the peer and release its references.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "ownership shares immediately decoded literals with the supplied allocation"
    )]
    pub fn decode_field_section(
        &mut self,
        stream_id: u64,
        encoded: Bytes,
    ) -> Result<Option<Vec<FieldPair>>, QpackError> {
        validate_stream_id(stream_id)?;
        let mut cursor: &[u8] = &encoded;
        let insert_count = self.table.insert_count();
        let prefix = match HeaderPrefix::decode(&mut cursor, self.table.max_entries(), insert_count)
        {
            Ok(prefix) => prefix,
            Err(error) => {
                let error = QpackError::from(error);
                if matches!(error, QpackError::FieldSectionLimit(_)) {
                    self.drop_blocked_stream(stream_id);
                }
                return Err(error);
            }
        };
        let consumed = encoded.len() - cursor.len();
        let body = encoded.slice(consumed..);

        // If earlier sections on this stream are still blocked, this one queues behind them even if
        // its own Required Insert Count is already met, so the stream's sections stay in order.
        let already_blocked = self.blocked.get(&stream_id).is_some_and(|q| !q.is_empty());

        if !already_blocked && prefix.required_insert_count <= insert_count {
            return Ok(Some(self.decode_body(stream_id, &prefix, &body)?));
        }

        // blocked: enforce budgets before retaining
        let already_waiting_for_inserts = self.blocked.get(&stream_id).is_some_and(|queue| {
            queue
                .iter()
                .any(|section| section.prefix.required_insert_count > insert_count)
        });
        if prefix.required_insert_count > insert_count
            && !already_waiting_for_inserts
            && self.blocked_stream_count() as u64 >= self.config.max_blocked_streams
        {
            return Err(QpackError::DecompressionFailed("too many blocked streams"));
        }
        let size = encoded.len().saturating_add(size_of::<BlockedSection>());
        if self.blocked_bytes.saturating_add(size) > self.config.max_blocked_bytes {
            self.drop_blocked_stream(stream_id);
            return Err(QpackError::StreamResourceLimit(
                "blocked field-section storage exceeded",
            ));
        }
        let body = Bytes::copy_from_slice(&body);
        self.blocked_bytes += size;
        self.blocked
            .entry(stream_id)
            .or_default()
            .push_back(BlockedSection { prefix, body, size });
        Ok(None)
    }

    /// Decode buffered fields after connection close, when feedback can no longer be sent.
    /// Missing inserts remain terminal: do not retain a section that can never resume.
    pub(crate) fn decode_field_section_after_close(
        &mut self,
        stream_id: u64,
        encoded: Bytes,
    ) -> Result<Option<Vec<FieldPair>>, QpackError> {
        self.decoder_output.clear();
        let output_in_flight = std::mem::take(&mut self.output_in_flight);
        self.drop_blocked_stream(stream_id);
        let result = self.decode_field_section(stream_id, encoded);
        // A writer may complete an earlier write after this synchronous decode.
        // Preserve its reservation so that completion cannot underflow accounting.
        self.output_in_flight = output_in_flight;
        self.drop_blocked_stream(stream_id);
        self.decoder_output.clear();
        result
    }

    /// Decode and remove blocked sections whose Required Insert Count is now satisfied.
    ///
    /// Each stream's sections are resumed front-first and only while the front is ready, so a
    /// stream's sections are never delivered out of order. A decode failure is reported per stream.
    /// `OutputBlocked` leaves the section queued; drain output before resuming again. A
    /// `FieldSectionLimit` and `StreamResourceLimit` release all queued sections for that stream; reset it and call
    /// [`Decoder::cancel_stream`] to release the peer's references.
    pub fn resume_blocked(&mut self) -> Vec<(u64, Result<Vec<FieldPair>, QpackError>)> {
        let insert_count = self.table.insert_count();
        let mut out = Vec::new();
        let stream_ids: Vec<u64> = self.blocked.keys().copied().collect();
        for stream_id in stream_ids {
            while let Some(section) = self.blocked.get(&stream_id).and_then(|q| q.front()) {
                if section.prefix.required_insert_count > insert_count {
                    break;
                }
                if section.prefix.required_insert_count > 0
                    && let Err(error) =
                        self.reserve_instruction(DecoderInstruction::SectionAcknowledgment {
                            stream_id,
                        })
                {
                    out.push((stream_id, Err(error)));
                    break;
                }
                let Some(section) = self.pop_ready_front(stream_id, insert_count) else {
                    break;
                };
                self.blocked_bytes -= section.size;
                let result = self.decode_body(stream_id, &section.prefix, &section.body);
                if matches!(
                    result,
                    Err(QpackError::FieldSectionLimit(_) | QpackError::StreamResourceLimit(_))
                ) {
                    self.drop_blocked_stream(stream_id);
                }
                out.push((stream_id, result));
            }
        }
        out
    }

    /// Resume at most one ready section without allocating a temporary result list.
    ///
    /// Call within the connection's work budget. `OutputBlocked` retains the section;
    /// drain decoder output before retrying. Ordering within each stream is preserved.
    pub fn resume_next(&mut self) -> Option<(u64, Result<Vec<FieldPair>, QpackError>)> {
        let insert_count = self.table.insert_count();
        let (&stream_id, queue) = self.blocked.iter().find(|(_, queue)| {
            queue
                .front()
                .is_some_and(|s| s.prefix.required_insert_count <= insert_count)
        })?;
        if queue.front()?.prefix.required_insert_count > 0
            && let Err(error) =
                self.reserve_instruction(DecoderInstruction::SectionAcknowledgment { stream_id })
        {
            return Some((stream_id, Err(error)));
        }
        let section = self.pop_ready_front(stream_id, insert_count)?;
        self.blocked_bytes -= section.size;
        let result = self.decode_body(stream_id, &section.prefix, &section.body);
        if matches!(
            result,
            Err(QpackError::FieldSectionLimit(_) | QpackError::StreamResourceLimit(_))
        ) {
            self.drop_blocked_stream(stream_id);
        }
        Some((stream_id, result))
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
        body: &Bytes,
    ) -> Result<Vec<FieldPair>, QpackError> {
        if prefix.required_insert_count > 0 {
            self.reserve_instruction(DecoderInstruction::SectionAcknowledgment { stream_id })?;
        }
        let fields = self.decode_lines(body.clone(), prefix)?;
        if prefix.required_insert_count > 0 {
            DecoderInstruction::SectionAcknowledgment { stream_id }
                .encode(&mut self.decoder_output);
        }
        Ok(fields)
    }

    /// Cancel a stream: drop any blocked sections and emit Stream Cancellation (RFC 9204 §4.4.2).
    /// `OutputBlocked` leaves blocked sections intact; drain output and retry.
    pub fn cancel_stream(&mut self, stream_id: u64) -> Result<(), QpackError> {
        validate_stream_id(stream_id)?;
        self.reserve_instruction(DecoderInstruction::StreamCancellation { stream_id })?;
        self.drop_blocked_stream(stream_id);
        DecoderInstruction::StreamCancellation { stream_id }.encode(&mut self.decoder_output);
        Ok(())
    }

    pub(crate) fn drop_blocked_stream(&mut self, stream_id: u64) {
        if let Some(queue) = self.blocked.remove(&stream_id) {
            for section in queue {
                self.blocked_bytes -= section.size;
            }
        }
    }

    fn decode_lines(
        &self,
        mut body: Bytes,
        prefix: &HeaderPrefix,
    ) -> Result<Vec<FieldPair>, QpackError> {
        let mut fields = Vec::new();
        let mut section_size: u64 = 0;
        while body.has_remaining() {
            let line = FieldLine::decode_bytes(&mut body, self.config.max_field_section_size)?;
            let pair = self.resolve_line(line, prefix)?;
            // account the uncompressed size (RFC 9114 §4.2.2: name + value + 32).
            section_size =
                section_size.saturating_add(pair.name.len() as u64 + pair.value.len() as u64 + 32);
            if section_size > self.config.max_field_section_size as u64 {
                return Err(QpackError::StreamResourceLimit("field section too large"));
            }
            fields.push(pair);
        }
        Ok(fields)
    }

    fn resolve_line(
        &self,
        line: FieldLine,
        prefix: &HeaderPrefix,
    ) -> Result<FieldPair, QpackError> {
        let base = prefix.base;
        let ric = prefix.required_insert_count;
        match line {
            FieldLine::Indexed { is_static, index } => {
                if is_static {
                    let (name, value) = static_get(index)?;
                    Ok(FieldPair {
                        name: name.into(),
                        value: value.into(),
                        never_index: false,
                    })
                } else {
                    let abs = pre_base_abs(base, index)?;
                    let (name, value) = self.dynamic_get(abs, ric)?;
                    Ok(FieldPair {
                        name,
                        value,
                        never_index: false,
                    })
                }
            }
            FieldLine::IndexedPostBase { index } => {
                let abs = post_base_abs(base, index)?;
                let (name, value) = self.dynamic_get(abs, ric)?;
                Ok(FieldPair {
                    name,
                    value,
                    never_index: false,
                })
            }
            FieldLine::LiteralWithNameRef {
                is_static,
                name_index,
                value,
                never_index,
                ..
            } => {
                let name = if is_static {
                    static_get(name_index)?.0.into()
                } else {
                    self.dynamic_get(pre_base_abs(base, name_index)?, ric)?.0
                };
                Ok(FieldPair {
                    name,
                    value,
                    never_index,
                })
            }
            FieldLine::LiteralWithPostBaseNameRef {
                name_index,
                value,
                never_index,
                ..
            } => {
                let name = self.dynamic_get(post_base_abs(base, name_index)?, ric)?.0;
                Ok(FieldPair {
                    name,
                    value,
                    never_index,
                })
            }
            FieldLine::LiteralWithLiteralName {
                name,
                value,
                never_index,
                ..
            } => Ok(FieldPair {
                name,
                value,
                never_index,
            }),
        }
    }

    fn dynamic_get(&self, abs: u64, ric: u64) -> Result<(Bytes, Bytes), QpackError> {
        if abs >= ric {
            return Err(QpackError::DecompressionFailed(
                "dynamic reference exceeds required insert count",
            ));
        }
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

fn encoder_parse_error(error: PrefixError) -> QpackError {
    match error {
        PrefixError::LengthLimitExceeded => {
            QpackError::EncoderStreamError("encoder-stream string too large")
        }
        _ => QpackError::EncoderStreamError("malformed encoder-stream instruction"),
    }
}

fn validate_stream_id(stream_id: u64) -> Result<(), QpackError> {
    VarInt::from_u64(stream_id)
        .map(|_| ())
        .map_err(|_error| QpackError::ResourceLimit("stream ID exceeds QUIC integer range"))
}

#[cfg(test)]
mod regression_tests {
    use super::*;
    use crate::h3::qpack::ErrorScope;
    use rama_http_types::proto::h3::Code;

    fn section(ric: u64, base: u64, line: &FieldLine) -> Bytes {
        let mut bytes = BytesMut::new();
        HeaderPrefix::new(ric, base)
            .encode(&mut bytes, DecoderConfig::default().max_table_capacity / 32);
        line.encode(&mut bytes);
        bytes.freeze()
    }

    fn insertion() -> Bytes {
        let mut bytes = BytesMut::new();
        EncoderInstruction::SetDynamicTableCapacity {
            capacity: kib_u64(4),
        }
        .encode(&mut bytes);
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"a"),
            value: Bytes::from_static(b"b"),
            name_huffman: false,
            value_huffman: false,
        }
        .encode(&mut bytes);
        bytes.freeze()
    }

    #[test]
    fn clean_close_decode_preserves_outstanding_write_accounting() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        decoder.feed_encoder_stream(&insertion()).unwrap();
        let output = decoder.take_output_for_write();
        let bytes = section(1, 0, &FieldLine::IndexedPostBase { index: 0 });
        assert!(
            decoder
                .decode_field_section_after_close(0, bytes)
                .unwrap()
                .is_some()
        );
        assert_eq!(decoder.output_in_flight, output.len());
        assert!(decoder.decoder_output.is_empty());
        decoder.output_written(output.len());
        assert_eq!(decoder.output_in_flight, 0);
    }

    #[test]
    fn local_storage_limit_releases_only_affected_stream() {
        let bytes = section(1, 0, &FieldLine::IndexedPostBase { index: 0 });
        let mut decoder = Decoder::new(DecoderConfig {
            max_blocked_bytes: 2 * (bytes.len() + size_of::<BlockedSection>()),
            ..DecoderConfig::default()
        });
        decoder.decode_field_section(0, bytes.clone()).unwrap();
        decoder.decode_field_section(4, bytes.clone()).unwrap();
        let error = decoder.decode_field_section(0, bytes.clone()).unwrap_err();
        assert_eq!(error.code(), Some(Code::H3_EXCESSIVE_LOAD));
        assert_eq!(error.scope(), Some(ErrorScope::Stream));
        assert_eq!(decoder.blocked_stream_count(), 1);
        decoder.cancel_stream(0).unwrap();
        decoder.decode_field_section(8, bytes).unwrap();
        decoder.feed_encoder_stream(&insertion()).unwrap();
        let decoded = decoder.resume_blocked();
        assert_eq!(
            decoded.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            [4, 8]
        );
        assert!(decoded.into_iter().all(|(_, fields)| fields.is_ok()));
        assert_eq!(decoder.blocked_bytes, 0);
    }

    #[test]
    fn aggregate_field_size_limit_has_http_stream_scope() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_field_section_size: 32,
            ..DecoderConfig::default()
        });
        let bytes = section(
            0,
            0,
            &FieldLine::Indexed {
                is_static: true,
                index: 17,
            },
        );
        let error = decoder.decode_field_section(0, bytes).unwrap_err();
        assert_eq!(error.code(), Some(Code::H3_EXCESSIVE_LOAD));
        assert_eq!(error.scope(), Some(ErrorScope::Stream));
        assert_eq!(
            decoder
                .decode_field_section(4, Bytes::from_static(&[0, 0]))
                .unwrap(),
            Some(vec![])
        );
    }

    #[test]
    fn encoder_literal_budget_tracks_current_table_capacity() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        let mut capacity = BytesMut::new();
        EncoderInstruction::SetDynamicTableCapacity { capacity: 64 }.encode(&mut capacity);
        decoder.feed_encoder_stream(&capacity).unwrap();
        assert_eq!(decoder.max_insert_string_len(), 32);
        let mut instruction = BytesMut::new();
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from_static(b"x"),
            value: Bytes::from(vec![b'a'; kib(64)]),
            name_huffman: false,
            value_huffman: false,
        }
        .encode(&mut instruction);
        // The length prefix is sufficient to reject this impossible insertion;
        // no full literal or half-megabyte staging allocation is needed.
        assert!(matches!(
            decoder.feed_encoder_stream(&instruction[..8]),
            Err(QpackError::EncoderStreamError(_))
        ));
        assert!(decoder.encoder_stream.capacity() < kib(1));
    }

    #[test]
    fn large_huffman_insert_fragmented_bytewise_decodes_only_when_complete() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        let mut bytes = BytesMut::new();
        EncoderInstruction::SetDynamicTableCapacity {
            capacity: kib_u64(4),
        }
        .encode(&mut bytes);
        decoder.feed_encoder_stream(&bytes).unwrap();
        bytes.clear();
        EncoderInstruction::InsertWithLiteralName {
            name: Bytes::from(vec![b'a'; kib(1)]),
            value: Bytes::from(vec![0xff; kib(2)]),
            name_huffman: true,
            value_huffman: true,
        }
        .encode(&mut bytes);
        let last = bytes.len() - 1;
        for (index, byte) in bytes.iter().enumerate() {
            decoder.feed_encoder_stream(&[*byte]).unwrap();
            assert_eq!(decoder.insert_count(), u64::from(index == last));
            assert!(decoder.encoder_stream.len() <= decoder.max_instruction_bytes());
        }
        assert!(decoder.encoder_stream.is_empty());
        assert_eq!(decoder.table.get(0).unwrap().1.as_ref(), vec![0xff; kib(2)]);
    }

    #[test]
    fn detached_output_remains_charged_until_written() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_decoder_stream_bytes: 10,
            ..DecoderConfig::default()
        });
        decoder.decoder_output.extend_from_slice(&[0; 10]);
        let output = decoder.take_output_for_write();
        assert_eq!(output.len(), 10);
        assert_eq!(decoder.reserve_output(1), Err(QpackError::OutputBlocked));
        decoder.output_written(4);
        decoder.reserve_output(4).unwrap();
        assert_eq!(decoder.reserve_output(5), Err(QpackError::OutputBlocked));
        decoder.decoder_output.extend_from_slice(&[0; 4]);
        assert_eq!(decoder.reserve_output(1), Err(QpackError::OutputBlocked));
        decoder.output_written(6);
        decoder.reserve_output(6).unwrap();
    }
    #[test]
    fn every_dynamic_reference_must_be_below_ric() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        decoder.feed_encoder_stream(&insertion()).unwrap();
        for (base, line) in [
            (
                1,
                FieldLine::Indexed {
                    is_static: false,
                    index: 0,
                },
            ),
            (0, FieldLine::IndexedPostBase { index: 0 }),
            (
                1,
                FieldLine::LiteralWithNameRef {
                    is_static: false,
                    name_index: 0,
                    value: Bytes::new(),
                    value_huffman: false,
                    never_index: false,
                },
            ),
            (
                0,
                FieldLine::LiteralWithPostBaseNameRef {
                    name_index: 0,
                    value: Bytes::new(),
                    value_huffman: false,
                    never_index: false,
                },
            ),
        ] {
            assert!(matches!(
                decoder.decode_field_section(0, section(0, base, &line)),
                Err(QpackError::DecompressionFailed(
                    "dynamic reference exceeds required insert count"
                ))
            ));
        }
    }

    #[test]
    fn literal_is_shared_and_preserves_never_index() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        let bytes = section(
            0,
            0,
            &FieldLine::LiteralWithLiteralName {
                name: Bytes::from_static(b"secret"),
                value: Bytes::from_static(b"value"),
                name_huffman: false,
                value_huffman: false,
                never_index: true,
            },
        );
        let start = bytes.as_ptr() as usize;
        let end = start + bytes.len();
        let fields = decoder.decode_field_section(0, bytes).unwrap().unwrap();
        assert!(fields[0].never_index);
        for bytes in [&fields[0].name, &fields[0].value] {
            assert!((start..end).contains(&(bytes.as_ptr() as usize)));
        }
    }

    #[test]
    fn fragmented_instruction_matches_whole_and_inbox_is_bounded() {
        let bytes = insertion();
        for split in 0..=bytes.len() {
            let mut decoder = Decoder::new(DecoderConfig::default());
            decoder.feed_encoder_stream(&bytes[..split]).unwrap();
            decoder.feed_encoder_stream(&bytes[split..]).unwrap();
            assert_eq!(decoder.insert_count(), 1);
            assert!(decoder.encoder_stream.is_empty());
        }
        let mut decoder = Decoder::new(DecoderConfig {
            max_field_section_size: 1,
            ..DecoderConfig::default()
        });
        // Literal name length 31 plus a continuation encoding an over-limit length, then huge input.
        let mut malicious = vec![0; kib(256)];
        malicious[0] = 0x5f;
        malicious[1] = 1;
        assert!(decoder.feed_encoder_stream(&malicious).is_err());
        assert!(decoder.encoder_stream.len() <= decoder.max_instruction_bytes());
    }

    #[test]
    fn blocked_output_retries_preserve_sections_and_accounting() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_decoder_stream_bytes: 11,
            max_blocked_bytes: 3 + size_of::<BlockedSection>(),
            ..DecoderConfig::default()
        });
        let bytes = section(1, 0, &FieldLine::IndexedPostBase { index: 0 });
        assert_eq!(bytes.len(), 3);
        assert_eq!(
            decoder.decode_field_section(4, bytes.clone()).unwrap(),
            None
        );
        decoder.decode_field_section(8, bytes).unwrap_err();
        decoder.feed_encoder_stream(&insertion()).unwrap();
        // Fill the remaining ten bytes with one-byte cancellations.
        for _ in 0..10 {
            decoder.cancel_stream(0).unwrap();
        }
        assert_eq!(
            decoder.resume_blocked(),
            vec![(4, Err(QpackError::OutputBlocked))]
        );
        assert_eq!(decoder.blocked_bytes, 3 + size_of::<BlockedSection>());
        assert_eq!(decoder.cancel_stream(4), Err(QpackError::OutputBlocked));
        assert_eq!(decoder.blocked_bytes, 3 + size_of::<BlockedSection>());
        assert_eq!(
            decoder.feed_encoder_stream(&[0]),
            Err(QpackError::OutputBlocked)
        );
        assert_eq!(decoder.insert_count(), 1);
        decoder.take_decoder_stream();
        let resumed = decoder.resume_blocked();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].1.as_ref().unwrap()[0].value, b"b"[..]);
        assert_eq!(decoder.blocked_bytes, 0);
        assert_eq!(decoder.blocked_stream_count(), 0);
        decoder.take_decoder_stream();
        decoder.feed_encoder_stream(&[0]).unwrap();
        assert_eq!(decoder.insert_count(), 2);
    }

    #[test]
    fn malformed_resumed_section_releases_storage() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_blocked_bytes: 3 + size_of::<BlockedSection>(),
            ..DecoderConfig::default()
        });
        // RIC=1 makes this wait, but post-base index 1 illegally exceeds that RIC.
        let bytes = section(1, 0, &FieldLine::IndexedPostBase { index: 1 });
        decoder.decode_field_section(4, bytes).unwrap();
        decoder.feed_encoder_stream(&insertion()).unwrap();
        let resumed = decoder.resume_blocked();
        assert!(matches!(
            resumed[0].1,
            Err(QpackError::DecompressionFailed(_))
        ));
        assert_eq!(decoder.blocked_bytes, 0);
        assert_eq!(decoder.blocked_stream_count(), 0);
    }

    #[test]
    fn never_index_survives_all_literal_reference_forms() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        decoder.feed_encoder_stream(&insertion()).unwrap();
        for (base, line) in [
            (
                1,
                FieldLine::LiteralWithNameRef {
                    is_static: true,
                    name_index: 0,
                    value: Bytes::new(),
                    value_huffman: false,
                    never_index: true,
                },
            ),
            (
                1,
                FieldLine::LiteralWithNameRef {
                    is_static: false,
                    name_index: 0,
                    value: Bytes::new(),
                    value_huffman: false,
                    never_index: true,
                },
            ),
            (
                0,
                FieldLine::LiteralWithPostBaseNameRef {
                    name_index: 0,
                    value: Bytes::new(),
                    value_huffman: false,
                    never_index: true,
                },
            ),
        ] {
            let fields = decoder
                .decode_field_section(0, section(1, base, &line))
                .unwrap()
                .unwrap();
            assert!(fields[0].never_index);
        }
    }

    #[test]
    fn stream_ids_are_validated_before_mutation() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        let invalid = VarInt::MAX.into_inner() + 1;
        decoder
            .decode_field_section(invalid, Bytes::from_static(&[0, 0]))
            .unwrap_err();
        decoder.cancel_stream(invalid).unwrap_err();
        assert_eq!(decoder.blocked_bytes, 0);
        assert!(decoder.take_decoder_stream().is_empty());
        decoder.cancel_stream(VarInt::MAX.into_inner()).unwrap();
    }

    #[test]
    fn retained_sections_and_table_literals_do_not_pin_staging_allocations() {
        let mut decoder = Decoder::new(DecoderConfig::default());
        let mut allocation = vec![0; kib(256)];
        allocation[..3].copy_from_slice(&[2, 0x80, 0x10]);
        let allocation = Bytes::from(allocation);
        let start = allocation.as_ptr() as usize;
        let end = start + allocation.len();
        decoder
            .decode_field_section(0, allocation.slice(..3))
            .unwrap();
        let retained = &decoder.blocked[&0][0].body;
        assert!(!(start..end).contains(&(retained.as_ptr() as usize)));
        let instructions = insertion();
        decoder
            .feed_encoder_stream(&instructions[..instructions.len() - 1])
            .unwrap();
        let start = decoder.encoder_stream.as_ptr() as usize;
        let end = start + decoder.encoder_stream.capacity();
        decoder
            .feed_encoder_stream(&instructions[instructions.len() - 1..])
            .unwrap();
        let (name, value) = decoder.table.get(0).unwrap();
        assert!(!(start..end).contains(&(name.as_ptr() as usize)));
        assert!(!(start..end).contains(&(value.as_ptr() as usize)));
    }

    #[test]
    fn blocked_stream_limit_counts_only_unreceived_insertions() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_blocked_streams: 1,
            ..DecoderConfig::default()
        });
        decoder
            .decode_field_section(0, section(1, 0, &FieldLine::IndexedPostBase { index: 0 }))
            .unwrap();
        assert_eq!(decoder.blocked_stream_count(), 1);
        decoder.feed_encoder_stream(&insertion()).unwrap();
        // Stream 0 remains queued, but is now ready and does not consume the protocol budget.
        assert_eq!(decoder.blocked_stream_count(), 0);
        decoder
            .decode_field_section(4, section(2, 0, &FieldLine::IndexedPostBase { index: 1 }))
            .unwrap();
        assert_eq!(decoder.blocked_stream_count(), 1);
        assert_eq!(
            decoder
                .decode_field_section(0, section(2, 0, &FieldLine::IndexedPostBase { index: 1 })),
            Err(QpackError::DecompressionFailed("too many blocked streams"))
        );
        // A ready section can queue for ordering without consuming another blocked-stream slot.
        decoder
            .decode_field_section(0, Bytes::from_static(&[0, 0]))
            .unwrap();
        assert_eq!(decoder.blocked_stream_count(), 1);
    }

    #[test]
    fn one_byte_output_budget_can_progress_by_splitting_input() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_decoder_stream_bytes: 1,
            ..DecoderConfig::default()
        });
        for byte in insertion() {
            decoder.feed_encoder_stream(&[byte]).unwrap();
            decoder.take_decoder_stream();
        }
        assert_eq!(decoder.insert_count(), 1);
        // Sixty-three potential insertions need a two-byte increment reservation.
        assert_eq!(
            decoder.feed_encoder_stream(&[0; 63]),
            Err(QpackError::OutputBlocked)
        );
        assert_eq!(decoder.insert_count(), 1);
        for _ in 0..63 {
            decoder.feed_encoder_stream(&[0]).unwrap();
            assert_eq!(decoder.take_decoder_stream(), [1][..]);
        }
        assert_eq!(decoder.insert_count(), 64);
    }

    #[test]
    fn impossible_atomic_output_is_terminal_instead_of_retryable() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_decoder_stream_bytes: 1,
            ..DecoderConfig::default()
        });
        let expected = QpackError::ResourceLimit("decoder instruction exceeds output budget");
        assert_eq!(decoder.cancel_stream(64), Err(expected));
        assert!(decoder.take_decoder_stream().is_empty());

        let bytes = section(1, 0, &FieldLine::IndexedPostBase { index: 0 });
        decoder.decode_field_section(128, bytes.clone()).unwrap();
        for byte in insertion() {
            decoder.feed_encoder_stream(&[byte]).unwrap();
            decoder.take_decoder_stream();
        }
        let retained = decoder.blocked_bytes;
        assert_eq!(decoder.resume_blocked(), vec![(128, Err(expected))]);
        assert_eq!(decoder.blocked_bytes, retained);
        assert_eq!(decoder.decode_field_section(132, bytes), Err(expected));
        assert_eq!(decoder.blocked_bytes, retained);
        assert!(decoder.take_decoder_stream().is_empty());
    }

    #[test]
    fn individual_limits_have_rfc_7_4_scope_and_recover_stream_storage() {
        let config = DecoderConfig {
            max_field_section_size: 1,
            ..DecoderConfig::default()
        };
        let mut decoder = Decoder::new(config);
        let oversized = section(
            1,
            0,
            &FieldLine::LiteralWithLiteralName {
                name: Bytes::from_static(b"ab"),
                value: Bytes::new(),
                never_index: true,
                name_huffman: false,
                value_huffman: false,
            },
        );
        decoder.decode_field_section(0, oversized).unwrap();
        decoder
            .decode_field_section(0, Bytes::from_static(&[0, 0]))
            .unwrap();
        decoder.feed_encoder_stream(&insertion()).unwrap();
        let results = decoder.resume_blocked();
        assert_eq!(results.len(), 1);
        let error = results[0].1.as_ref().unwrap_err();
        assert_eq!(error.scope(), Some(ErrorScope::Stream));
        assert_eq!(error.code(), Some(Code::QPACK_DECOMPRESSION_FAILED));
        assert_eq!(decoder.blocked_bytes, 0);
        assert!(decoder.blocked.is_empty());
        decoder.cancel_stream(0).unwrap();
        assert_eq!(
            decoder
                .decode_field_section(4, Bytes::from_static(&[0, 0]))
                .unwrap(),
            Some(vec![])
        );
        let mut other = Decoder::new(config);
        let error = other
            .feed_encoder_stream(&[0x42, b'a', b'b', 0])
            .unwrap_err();
        assert_eq!(error.scope(), Some(ErrorScope::Connection));
        assert_eq!(error.code(), Some(Code::QPACK_ENCODER_STREAM_ERROR));
    }

    #[test]
    fn cancellation_recovers_exact_blocked_byte_budget() {
        let mut decoder = Decoder::new(DecoderConfig {
            max_blocked_bytes: 3 + size_of::<BlockedSection>(),
            ..DecoderConfig::default()
        });
        let bytes = section(1, 0, &FieldLine::IndexedPostBase { index: 0 });
        decoder.decode_field_section(4, bytes.clone()).unwrap();
        decoder.cancel_stream(4).unwrap();
        assert_eq!(decoder.blocked_bytes, 0);
        assert_eq!(decoder.decode_field_section(8, bytes).unwrap(), None);
        assert_eq!(decoder.blocked_bytes, 3 + size_of::<BlockedSection>());
    }
}
