//! Connection-scoped QPACK encoding, bounded reference tracking and decoder-stream feedback.

use std::{
    borrow::Cow,
    collections::{BTreeMap, VecDeque},
};

use rama_core::bytes::{Bytes, BytesMut};
use rama_http_types::proto::h3::qpack::prefix::{StringEncoder, encode_int, int_encoded_len};
use rama_http_types::proto::h3::{
    VarInt,
    qpack::{DecoderInstruction, HeaderPrefix, PrefixError, static_table},
};
use rama_utils::octets::{kib, kib_u64};

use super::dynamic_table::{DynamicTable, ENTRY_OVERHEAD, entry_size};
use super::{FieldPair, QpackError};

/// Encoder input preserving the never-index requirement across intermediary hops.
#[derive(Clone, Debug)]
pub struct EncodeField<N, V> {
    /// Field name bytes.
    pub name: N,
    /// Field value bytes.
    pub value: V,
    /// Always emit a literal with N=1; never insert or fully index this field.
    pub never_index: bool,
}

impl<'a> EncodeField<Cow<'a, [u8]>, &'a [u8]> {
    /// Encode a lowercase name and preserve [`rama_http_types::HeaderValue::is_sensitive`].
    /// Values and already-lowercase names remain borrowed. Mixed-case custom names
    /// are normalized only for the wire, without changing the original header map.
    #[must_use]
    pub fn from_header(
        name: &'a rama_http_types::HeaderName,
        value: &'a rama_http_types::HeaderValue,
    ) -> Self {
        Self {
            name: match name.as_lower_str() {
                Cow::Borrowed(name) => Cow::Borrowed(name.as_bytes()),
                Cow::Owned(name) => Cow::Owned(name.into_bytes()),
            },
            value: value.as_bytes(),
            never_index: value.is_sensitive(),
        }
    }
}

impl<N, V> From<(N, V)> for EncodeField<N, V> {
    fn from((name, value): (N, V)) -> Self {
        Self {
            name,
            value,
            never_index: false,
        }
    }
}

impl From<FieldPair> for EncodeField<Bytes, Bytes> {
    fn from(field: FieldPair) -> Self {
        Self {
            name: field.name,
            value: field.value,
            never_index: field.never_index,
        }
    }
}

/// Configuration and local resource budgets for an [`Encoder`].
#[derive(Clone, Copy, Debug)]
pub struct EncoderConfig {
    /// The peer's SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    pub max_table_capacity: u64,
    /// The peer's SETTINGS_QPACK_BLOCKED_STREAMS.
    pub max_blocked_streams: u64,
    /// Capacity to use, clamped to the peer maximum.
    pub target_capacity: u64,
    /// Allow Huffman encoding when it reduces a literal's wire size; plain encoding wins ties.
    pub huffman: bool,
    /// Maximum uncompressed section size, including 32 bytes per field.
    pub max_field_section_size: usize,
    /// Maximum queued encoder-stream bytes. When full, encoding falls back to literals.
    pub max_encoder_stream_bytes: usize,
    /// Maximum sections awaiting Section Acknowledgment. Further sections use literals.
    pub max_outstanding_sections: usize,
    /// Maximum outstanding dynamic references, including repeated references within sections.
    pub max_outstanding_references: usize,
}

impl Default for EncoderConfig {
    fn default() -> Self {
        Self {
            max_table_capacity: kib_u64(4),
            max_blocked_streams: 16,
            target_capacity: kib_u64(4),
            huffman: true,
            max_field_section_size: kib(64),
            max_encoder_stream_bytes: kib(64),
            max_outstanding_sections: 1024,
            max_outstanding_references: 16_384,
        }
    }
}

struct Section {
    refs: Vec<u64>,
    required_insert_count: u64,
}

#[derive(Default)]
struct StreamSections {
    queue: VecDeque<Section>,
    blocking: usize,
}

/// Stateful encoder for one connection. Dynamic insertion and references fall back to literals
/// when budgets are exhausted; invalid/oversized input fails before any state changes.
pub struct Encoder {
    config: EncoderConfig,
    table: DynamicTable,
    encoder_output: BytesMut,
    known_received_count: u64,
    capacity_initialized: bool,
    sections: BTreeMap<u64, StreamSections>,
    // Counts sections by (Required Insert Count, stream). Advancing the Known
    // Received Count visits only newly unblocked sections, never unrelated ones.
    blocking_sections: BTreeMap<(u64, u64), usize>,
    section_count: usize,
    reference_count: usize,
    blocking_streams: u64,
    decoder_partial: [u8; 11],
    decoder_partial_len: usize,
    pending_target_capacity: Option<u64>,
}

impl Encoder {
    /// Create an encoder with the peer settings and local budgets.
    #[must_use]
    pub fn new(mut config: EncoderConfig) -> Self {
        config.max_table_capacity = config.max_table_capacity.min(VarInt::MAX.into_inner());
        config.target_capacity = config.target_capacity.min(config.max_table_capacity);
        Self {
            table: DynamicTable::new(config.max_table_capacity),
            config,
            encoder_output: BytesMut::new(),
            known_received_count: 0,
            capacity_initialized: false,
            sections: BTreeMap::new(),
            blocking_sections: BTreeMap::new(),
            section_count: 0,
            reference_count: 0,
            blocking_streams: 0,
            decoder_partial: [0; 11],
            decoder_partial_len: 0,
            pending_target_capacity: None,
        }
    }

    /// Create a connection encoder before receiving peer SETTINGS.
    ///
    /// Only static and literal representations are used until [`Self::apply_peer_settings`].
    /// The configured target capacity and local budgets are retained for negotiation.
    #[must_use]
    pub fn before_peer_settings(mut config: EncoderConfig) -> Self {
        let target = config.target_capacity;
        config.max_table_capacity = 0;
        config.max_blocked_streams = 0;
        let mut encoder = Self::new(config);
        encoder.pending_target_capacity = Some(target);
        encoder
    }

    /// Apply the first peer SETTINGS without replacing decoder-stream parser state.
    ///
    /// This is valid exactly once on an encoder created with [`Self::before_peer_settings`].
    /// The connection driver must reject subsequent SETTINGS as H3_FRAME_UNEXPECTED.
    pub fn apply_peer_settings(
        &mut self,
        settings: &rama_http_types::proto::h3::Settings,
    ) -> Result<(), QpackError> {
        let target = self
            .pending_target_capacity
            .take()
            .ok_or(QpackError::ResourceLimit(
                "peer settings already configured",
            ))?;
        self.config.max_table_capacity = settings.qpack_max_table_capacity();
        self.config.max_blocked_streams = settings.qpack_blocked_streams();
        self.config.target_capacity = target.min(self.config.max_table_capacity);
        if let Some(limit) = settings.max_field_section_size() {
            self.config.max_field_section_size = self
                .config
                .max_field_section_size
                .min(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        // Before SETTINGS no insertion or dynamic reference was permitted.
        debug_assert_eq!(self.table.insert_count(), 0);
        self.table = DynamicTable::new(self.config.max_table_capacity);
        Ok(())
    }

    /// Number of insertions acknowledged by the peer.
    #[must_use]
    pub fn known_received_count(&self) -> u64 {
        self.known_received_count
    }
    /// Number of dynamic entries inserted over the connection lifetime.
    #[must_use]
    pub fn insert_count(&self) -> u64 {
        self.table.insert_count()
    }
    /// Number of sections awaiting acknowledgment.
    #[must_use]
    pub fn tracked_section_count(&self) -> usize {
        self.section_count
    }
    /// Number of outstanding references retained for acknowledgment/cancellation.
    #[must_use]
    pub fn tracked_reference_count(&self) -> usize {
        self.reference_count
    }
    /// Number of queued encoder-stream bytes.
    #[must_use]
    pub fn encoder_stream_len(&self) -> usize {
        self.encoder_output.len()
    }
    /// Take queued encoder-stream bytes in order.
    pub fn take_encoder_stream(&mut self) -> Bytes {
        self.encoder_output.split().freeze()
    }

    fn is_stream_blocking(&self, stream_id: u64) -> bool {
        self.sections
            .get(&stream_id)
            .is_some_and(|sections| sections.blocking > 0)
    }

    fn advance_known_received_count(&mut self, count: u64) {
        self.known_received_count = self.known_received_count.max(count);
        while self
            .blocking_sections
            .first_key_value()
            .is_some_and(|((required, _), _)| *required <= self.known_received_count)
        {
            let Some(((_, stream_id), count)) = self.blocking_sections.pop_first() else {
                break;
            };
            if let Some(sections) = self.sections.get_mut(&stream_id) {
                sections.blocking -= count;
                if sections.blocking == 0 {
                    self.blocking_streams -= 1;
                }
            }
        }
    }

    fn remove_blocking_section(&mut self, stream_id: u64, required: u64) {
        if required <= self.known_received_count {
            return;
        }
        let key = (required, stream_id);
        if let Some(count) = self.blocking_sections.get_mut(&key) {
            *count -= 1;
            if *count == 0 {
                self.blocking_sections.remove(&key);
            }
        }
    }

    /// Bound newly generated instructions by credit atomically reserved by the transport.
    /// Existing synchronous users retain their configured output budget.
    pub(crate) fn encode_with_credit<I, F, N, V>(
        &mut self,
        stream_id: u64,
        fields: I,
        credit: usize,
    ) -> Result<Bytes, QpackError>
    where
        I: IntoIterator<Item = F>,
        F: Into<EncodeField<N, V>>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let configured = self.config.max_encoder_stream_bytes;
        self.config.max_encoder_stream_bytes = configured.min(credit);
        let result = self.encode(stream_id, fields);
        self.config.max_encoder_stream_bytes = configured;
        result
    }

    fn output_fits(&self, additional: usize) -> bool {
        additional
            <= self
                .config
                .max_encoder_stream_bytes
                .saturating_sub(self.encoder_output.len())
    }

    fn ensure_capacity(&mut self) {
        if !self.capacity_initialized
            && self.config.target_capacity > 0
            && self.output_fits(int_encoded_len(self.config.target_capacity, 5))
        {
            self.capacity_initialized = true;
            let ok = self.table.set_capacity(self.config.target_capacity);
            debug_assert!(ok);
            encode_int(
                &mut self.encoder_output,
                self.config.target_capacity,
                5,
                0x20,
            );
        }
    }

    /// Encode ordered fields for a HEADERS/PUSH_PROMISE payload. Tuples represent ordinary fields;
    /// [`EncodeField`] or decoded [`FieldPair`] values preserve sensitivity.
    ///
    /// Input size and stream ID are validated before any connection state changes. A tracking or
    /// encoder-output budget prevents optional dynamic compression rather than failing the section.
    pub fn encode<I, F, N, V>(&mut self, stream_id: u64, fields: I) -> Result<Bytes, QpackError>
    where
        I: IntoIterator<Item = F>,
        F: Into<EncodeField<N, V>>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        if VarInt::from_u64(stream_id).is_err() {
            return Err(QpackError::ResourceLimit(
                "stream ID exceeds QUIC integer range",
            ));
        }
        // Retain the caller's original values, without allocating per-literal copies. This bounded
        // preflight makes input rejection transactional even for one-shot iterators.
        let mut input = Vec::new();
        let mut size = 0usize;
        for field in fields {
            let field = field.into();
            size = size
                .checked_add(field.name.as_ref().len())
                .and_then(|n| n.checked_add(field.value.as_ref().len()))
                .and_then(|n| n.checked_add(ENTRY_OVERHEAD as usize))
                .filter(|n| *n <= self.config.max_field_section_size)
                .ok_or(QpackError::EncodeFieldSectionLimit(
                    "field section too large",
                ))?;
            input.push(field);
        }
        self.ensure_capacity();
        let base = self.table.insert_count();
        let was_blocking = self.is_stream_blocking(stream_id);
        let may_block = was_blocking || self.blocking_streams < self.config.max_blocked_streams;
        let may_track = self.section_count < self.config.max_outstanding_sections;
        let mut refs = Vec::new();
        let mut ric = 0;
        // Two u64 prefixed integers need at most 22 bytes. Backfill the prefix into this headroom
        // after the body is encoded; slicing it away avoids moving or copying the body.
        const PREFIX_HEADROOM: usize = 22;
        let mut out = BytesMut::with_capacity(PREFIX_HEADROOM + size.min(kib(1)));
        out.resize(PREFIX_HEADROOM, 0);
        for field in input {
            let name = field.name.as_ref();
            let value = field.value.as_ref();
            let can_track =
                may_track && self.reference_count < self.config.max_outstanding_references;
            let referenceable =
                |abs: u64| can_track && (abs < self.known_received_count || may_block);
            if !field.never_index {
                if let Some(index) = static_table::find(name, value) {
                    encode_int(&mut out, index as u64, 6, 0xc0);
                    continue;
                }
                if let Some(abs) = self
                    .table
                    .find(name, value)
                    .filter(|abs| referenceable(*abs))
                {
                    self.reference(abs, &mut refs, &mut ric);
                    encode_dynamic_index(&mut out, abs, base);
                    continue;
                }
                if can_track && may_block && self.try_insert(name, value) {
                    let abs = self.table.insert_count() - 1;
                    self.reference(abs, &mut refs, &mut ric);
                    encode_dynamic_index(&mut out, abs, base);
                    continue;
                }
            }
            if let Some(index) = static_table::find_name(name) {
                encode_int(
                    &mut out,
                    index as u64,
                    4,
                    0x50 | if field.never_index { 0x20 } else { 0 },
                );
            } else if let Some(abs) = self
                .table
                .find_name(name)
                .filter(|abs| can_track && (*abs < self.known_received_count || may_block))
            {
                self.reference(abs, &mut refs, &mut ric);
                if abs < base {
                    encode_int(
                        &mut out,
                        base - abs - 1,
                        4,
                        0x40 | if field.never_index { 0x20 } else { 0 },
                    );
                } else {
                    encode_int(
                        &mut out,
                        abs - base,
                        3,
                        if field.never_index { 0x08 } else { 0 },
                    );
                }
            } else {
                StringEncoder::new(name, 3, self.config.huffman)
                    .encode(&mut out, 0x20 | if field.never_index { 0x10 } else { 0 });
            }
            StringEncoder::new(value, 7, self.config.huffman).encode(&mut out, 0);
        }
        let mut prefix = [0u8; PREFIX_HEADROOM];
        let mut cursor = &mut prefix[..];
        HeaderPrefix::new(ric, if ric == 0 { 0 } else { base })
            .encode(&mut cursor, self.table.max_entries());
        let prefix_len = PREFIX_HEADROOM - cursor.len();
        out[PREFIX_HEADROOM - prefix_len..PREFIX_HEADROOM].copy_from_slice(&prefix[..prefix_len]);
        if ric > 0 {
            let sections = self.sections.entry(stream_id).or_default();
            sections.queue.push_back(Section {
                refs,
                required_insert_count: ric,
            });
            self.section_count += 1;
            if ric > self.known_received_count {
                *self.blocking_sections.entry((ric, stream_id)).or_default() += 1;
                sections.blocking += 1;
                if !was_blocking {
                    self.blocking_streams += 1;
                }
            }
        }
        Ok(out.freeze().slice(PREFIX_HEADROOM - prefix_len..))
    }

    fn reference(&mut self, abs: u64, refs: &mut Vec<u64>, ric: &mut u64) {
        refs.push(abs);
        *ric = (*ric).max(abs + 1);
        self.table.add_ref(abs);
        self.reference_count += 1;
    }

    fn try_insert(&mut self, name: &[u8], value: &[u8]) -> bool {
        if self
            .table
            .can_insert(entry_size(name, value), Some(self.known_received_count))
            .is_err()
        {
            return false;
        }
        let static_name = static_table::find_name(name);
        let (name_literal, name_len) = if let Some(index) = static_name {
            (None, int_encoded_len(index as u64, 6))
        } else {
            let literal = StringEncoder::new(name, 5, self.config.huffman);
            let len = literal.encoded_len();
            (Some(literal), len)
        };
        let value_literal = StringEncoder::new(value, 7, self.config.huffman);
        let Some(wire_len) = name_len.checked_add(value_literal.encoded_len()) else {
            return false;
        };
        if !self.output_fits(wire_len) {
            return false;
        }
        // These copies own only table entry bytes: retaining slices of whole sections here would
        // pin unrelated payload allocations beyond the table capacity accounting.
        if self
            .table
            .insert(
                Bytes::copy_from_slice(name),
                Bytes::copy_from_slice(value),
                Some(self.known_received_count),
            )
            .is_err()
        {
            return false;
        }
        if let Some(index) = static_name {
            encode_int(&mut self.encoder_output, index as u64, 6, 0xc0);
        } else if let Some(name_literal) = name_literal {
            name_literal.encode(&mut self.encoder_output, 0x40);
        }
        value_literal.encode(&mut self.encoder_output, 0);
        true
    }

    /// Apply one decoded feedback instruction (RFC 9204 §4.4).
    pub fn on_decoder_instruction(&mut self, inst: DecoderInstruction) -> Result<(), QpackError> {
        match inst {
            DecoderInstruction::InsertCountIncrement { increment } => {
                if increment == 0 {
                    return Err(QpackError::DecoderStreamError(
                        "zero insert count increment",
                    ));
                }
                let new = self
                    .known_received_count
                    .checked_add(increment)
                    .filter(|v| *v <= self.table.insert_count())
                    .ok_or(QpackError::DecoderStreamError(
                        "insert count increment exceeds inserts",
                    ))?;
                self.advance_known_received_count(new);
            }
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                let sections =
                    self.sections
                        .get_mut(&stream_id)
                        .ok_or(QpackError::DecoderStreamError(
                            "acknowledgment for unknown section",
                        ))?;
                let section = sections
                    .queue
                    .pop_front()
                    .ok_or(QpackError::DecoderStreamError(
                        "acknowledgment for unknown section",
                    ))?;
                let required = section.required_insert_count;
                if required > self.known_received_count {
                    sections.blocking -= 1;
                    if sections.blocking == 0 {
                        self.blocking_streams -= 1;
                    }
                }
                if sections.queue.is_empty() {
                    self.sections.remove(&stream_id);
                }
                self.remove_blocking_section(stream_id, required);
                self.advance_known_received_count(required);
                self.release_section(section);
            }
            DecoderInstruction::StreamCancellation { stream_id } => {
                if VarInt::from_u64(stream_id).is_err() {
                    return Err(QpackError::DecoderStreamError(
                        "stream ID exceeds QUIC integer range",
                    ));
                }
                if let Some(sections) = self.sections.remove(&stream_id) {
                    if sections.blocking > 0 {
                        self.blocking_streams -= 1;
                    }
                    for section in sections.queue {
                        self.remove_blocking_section(stream_id, section.required_insert_count);
                        self.release_section(section);
                    }
                }
            }
        }
        Ok(())
    }

    fn release_section(&mut self, section: Section) {
        self.section_count -= 1;
        self.reference_count -= section.refs.len();
        for abs in section.refs {
            self.table.release_ref(abs);
        }
    }

    /// Process arbitrarily fragmented decoder-stream bytes, retaining at most eleven bytes of
    /// one incomplete instruction. Complete instructions before a malformed one remain applied.
    pub fn feed_decoder_stream(&mut self, mut input: &[u8]) -> Result<(), QpackError> {
        while !input.is_empty() {
            if self.decoder_partial_len > 0 {
                if self.decoder_partial_len == self.decoder_partial.len() {
                    return Err(QpackError::DecoderStreamError(
                        "decoder-stream integer overflow",
                    ));
                }
                self.decoder_partial[self.decoder_partial_len] = input[0];
                self.decoder_partial_len += 1;
                input = &input[1..];
                let mut cursor = &self.decoder_partial[..self.decoder_partial_len];
                match DecoderInstruction::decode(&mut cursor) {
                    Ok(inst) => {
                        self.decoder_partial_len = 0;
                        self.on_decoder_instruction(inst)?;
                    }
                    Err(PrefixError::UnexpectedEnd) => {}
                    Err(_) => {
                        return Err(QpackError::DecoderStreamError(
                            "malformed decoder-stream instruction",
                        ));
                    }
                }
            } else {
                let mut cursor = input;
                match DecoderInstruction::decode(&mut cursor) {
                    Ok(inst) => {
                        input = cursor;
                        self.on_decoder_instruction(inst)?;
                    }
                    Err(PrefixError::UnexpectedEnd) => {
                        if input.len() > self.decoder_partial.len() {
                            return Err(QpackError::DecoderStreamError(
                                "decoder-stream integer overflow",
                            ));
                        }
                        self.decoder_partial[..input.len()].copy_from_slice(input);
                        self.decoder_partial_len = input.len();
                        break;
                    }
                    Err(_) => {
                        return Err(QpackError::DecoderStreamError(
                            "malformed decoder-stream instruction",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Whether feedback ends on an instruction boundary. The connection driver handles critical
    /// stream closure; this reports a partial instruction for diagnostics and incremental tests.
    #[must_use]
    pub fn is_at_decoder_instruction_boundary(&self) -> bool {
        self.decoder_partial_len == 0
    }
}

fn encode_dynamic_index(out: &mut BytesMut, abs: u64, base: u64) {
    if abs < base {
        encode_int(out, base - abs - 1, 6, 0x80);
    } else {
        encode_int(out, abs - base, 4, 0x10);
    }
}

#[cfg(test)]
#[path = "encoder_tests.rs"]
mod tests;
