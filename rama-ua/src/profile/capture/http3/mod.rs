//! HTTP/3 client stream/control prefixes and QPACK instruction shapes.

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        order::{
            OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, OrderedProtocolField,
            ProtocolValue,
        },
    },
    format::canonical::{
        CanonicalDomain, CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError,
    },
};
use rama_http::proto::h3::{
    FrameType, SettingId, StreamType,
    observation::{H3ObservationSnapshot, ObservedControlFrame, ObservedEncoderInstruction},
    qpack::static_table,
};
use rama_utils::octets::kib;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
/// Resource limits for one retained HTTP/3 connection prefix.
pub struct H3SequenceCaptureLimits {
    pub events: usize,
    pub instructions: usize,
    pub settings: usize,
    pub bytes: usize,
    /// Maximum represented QPACK field length, independent of encoded metadata.
    pub observed_field_bytes: usize,
}

impl Default for H3SequenceCaptureLimits {
    fn default() -> Self {
        Self {
            events: 256,
            instructions: 256,
            settings: 256,
            bytes: kib(16),
            observed_field_bytes: kib(64),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
/// A stream creation or control frame in the observed connection order.
pub enum H3CapturedEvent {
    Stream {
        stream_id: u64,
        stream_type: u64,
    },
    Control {
        frame_type: u64,
        length: u64,
        element_id: Option<u64>,
        value: Box<[u8]>,
    },
}

/// A prefix at one immutable connection boundary. Fingerprint collection freezes
/// it once both the first request and peer SETTINGS have arrived. Recorder
/// revision gaps have no wire meaning. Stream and control events share relative
/// order; QPACK has only its own instruction order. No order between those
/// sequences is invented.
/// Inserted names/values and ignored frame payloads are absent, so this model
/// alone does not grant exact dynamic-table or unknown-frame replay capability.
#[derive(Debug, Clone, Serialize)]
pub struct H3ClientSequenceCapture {
    pub completeness: ProfileCaptureCompleteness,
    pub local_settings: OrderedProtocolCapture,
    pub events: Box<[H3CapturedEvent]>,
    pub encoder_instructions: Box<[ObservedEncoderInstruction]>,
}

impl H3ClientSequenceCapture {
    pub fn capture_at_request_head(
        source: &H3ObservationSnapshot,
        limits: H3SequenceCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        let complete = source.completeness;
        if !(complete.snapshot
            && complete.local_settings
            && complete.settings
            && source.settings_received
            && source.settings.is_some()
            && complete.streams
            && complete.control
            && complete.qpack)
            || source.connection_error.is_some()
        {
            return Err(ProfileDataError::Incomplete("H3 request-boundary sequence"));
        }
        if source.streams.len().saturating_add(source.control.len()) > limits.events
            || source.encoder_instructions.len() > limits.instructions
            || source.local_settings.len() > limits.settings
        {
            return Err(ProfileDataError::LimitExceeded("H3 sequence elements"));
        }
        if source.settings_received
            != source
                .control
                .iter()
                .any(|frame| frame.frame_type == FrameType::SETTINGS.value())
        {
            return Err(ProfileDataError::Invalid("H3 SETTINGS receipt context"));
        }
        let mut remaining = limits.bytes;
        let mut charge = |bytes: usize| -> Result<(), ProfileDataError> {
            remaining = remaining
                .checked_sub(bytes)
                .ok_or(ProfileDataError::LimitExceeded("H3 sequence bytes"))?;
            Ok(())
        };
        charge(42)?;
        for _ in &source.local_settings {
            charge(16)?;
        }
        for _ in &source.streams {
            charge(17)?;
        }
        for frame in &source.control {
            charge(26 + usize::from(frame.element_id.is_some()) * 8)?;
            charge(frame.value.len())?;
        }
        for instruction in &source.encoder_instructions {
            charge(match instruction {
                ObservedEncoderInstruction::Capacity { .. }
                | ObservedEncoderInstruction::Duplicate { .. } => 9,
                ObservedEncoderInstruction::InsertNameReference { .. }
                | ObservedEncoderInstruction::InsertLiteral { .. } => 19,
            })?;
        }
        let local_settings = OrderedProtocolCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            namespace: OrderNamespace::Http3Setting,
            fields: source
                .local_settings
                .iter()
                .map(|setting| OrderedProtocolField {
                    id: setting.id,
                    value: ProtocolValue::Literal(setting.value.to_be_bytes().into()),
                })
                .collect(),
        };
        let mut events = Vec::new();
        for stream in &source.streams {
            events.push((
                stream.sequence,
                H3CapturedEvent::Stream {
                    stream_id: stream.stream_id,
                    stream_type: stream.stream_type,
                },
            ));
        }
        for frame in &source.control {
            let ObservedControlFrame {
                sequence,
                frame_type,
                length,
                element_id,
                value,
            } = frame;
            events.push((
                *sequence,
                H3CapturedEvent::Control {
                    frame_type: *frame_type,
                    length: *length,
                    element_id: *element_id,
                    value: value.clone(),
                },
            ));
        }
        events.sort_unstable_by_key(|(sequence, _)| *sequence);
        let mut previous = 0;
        for (sequence, _) in &events {
            if *sequence <= previous || *sequence > source.revision {
                return Err(ProfileDataError::Invalid("H3 recorder sequence"));
            }
            previous = *sequence;
        }
        let mut result = Self {
            completeness: ProfileCaptureCompleteness::Complete,
            local_settings,
            events: events.into_iter().map(|(_, event)| event).collect(),
            encoder_instructions: source.encoder_instructions.clone().into(),
        };
        result.canonical(limits)?;
        // Names are not available for literal/dynamic references. Conservatively
        // omit every inserted value length, including cookie/auth/body fields.
        for instruction in &mut result.encoder_instructions {
            match instruction {
                ObservedEncoderInstruction::InsertNameReference { value_bytes, .. }
                | ObservedEncoderInstruction::InsertLiteral { value_bytes, .. } => *value_bytes = 0,
                _ => (),
            }
        }
        Ok(result)
    }

    pub fn canonical(
        &self,
        limits: H3SequenceCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        encode(self, limits, false)
    }

    pub fn structural(
        &self,
        limits: H3SequenceCaptureLimits,
    ) -> Result<CanonicalValue, ProfileDataError> {
        self.canonical(limits)?;
        encode(self, limits, true)
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        limits: H3SequenceCaptureLimits,
    ) -> Result<Self, ProfileDataError> {
        Self::decode(value, limits, false)
    }

    pub(in crate::profile) fn decode(
        value: &CanonicalValue,
        limits: H3SequenceCaptureLimits,
        structural: bool,
    ) -> Result<Self, ProfileDataError> {
        let domain = domain(structural);
        value.verify(domain, limits.bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, domain)?;
        let completeness = ProfileCaptureCompleteness::from_tag(reader.u8()?)?;
        let local_bytes = reader.bytes(limits.bytes)?;
        let local_settings = decode_settings(local_bytes, limits, structural)?;
        let mut events = Vec::new();
        for _ in 0..reader.count(limits.events)? {
            events.push(match reader.u8()? {
                0 => H3CapturedEvent::Stream {
                    stream_id: reader.u64()?,
                    stream_type: reader.u64()?,
                },
                1 => H3CapturedEvent::Control {
                    frame_type: reader.u64()?,
                    length: reader.u64()?,
                    element_id: if flag(&mut reader)? {
                        Some(reader.u64()?)
                    } else {
                        None
                    },
                    value: reader.bytes(limits.bytes)?.into(),
                },
                _ => return Err(ProfileDataError::Invalid("H3 sequence event")),
            });
        }
        let mut instructions = Vec::new();
        for _ in 0..reader.count(limits.instructions)? {
            instructions.push(match reader.u8()? {
                0 => ObservedEncoderInstruction::Capacity {
                    capacity: reader.u64()?,
                },
                1 => ObservedEncoderInstruction::InsertNameReference {
                    is_static: flag(&mut reader)?,
                    index: reader.u64()?,
                    value_bytes: reader.count(limits.observed_field_bytes)?,
                    value_huffman: flag(&mut reader)?,
                },
                2 => ObservedEncoderInstruction::InsertLiteral {
                    name_bytes: reader.count(limits.observed_field_bytes)?,
                    value_bytes: reader.count(limits.observed_field_bytes)?,
                    name_huffman: flag(&mut reader)?,
                    value_huffman: flag(&mut reader)?,
                },
                3 => ObservedEncoderInstruction::Duplicate {
                    index: reader.u64()?,
                },
                _ => return Err(ProfileDataError::Invalid("H3 encoder instruction")),
            });
        }
        reader.finish()?;
        let result = Self {
            completeness,
            local_settings,
            events: events.into(),
            encoder_instructions: instructions.into(),
        };
        if encode(&result, limits, structural)?.bytes != value.bytes {
            return Err(ProfileDataError::Invalid("noncanonical H3 sequence"));
        }
        Ok(result)
    }
}

fn order_limits(limits: H3SequenceCaptureLimits) -> OrderCaptureLimits {
    OrderCaptureLimits {
        elements: limits.settings,
        bytes: limits.bytes,
    }
}

fn domain(structural: bool) -> CanonicalDomain {
    if structural {
        CanonicalDomain::H3SequenceStructure
    } else {
        CanonicalDomain::H3Sequence
    }
}

fn flag(reader: &mut CanonicalReader<'_>) -> Result<bool, ProfileDataError> {
    match reader.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ProfileDataError::Invalid("H3 sequence flag")),
    }
}

fn varint(value: u64) -> Result<(), ProfileDataError> {
    if value >= (1 << 62) {
        Err(ProfileDataError::Invalid("H3 sequence varint"))
    } else {
        Ok(())
    }
}

// Context SETTINGS remain typed entries. Structural context sorts and masks only
// protocol-reserved candidates; the raw model keeps their actual ids and values.
fn settings_bytes(
    settings: &OrderedProtocolCapture,
    limits: H3SequenceCaptureLimits,
    structural: bool,
) -> Result<Vec<u8>, ProfileDataError> {
    if !matches!(settings.namespace, OrderNamespace::Http3Setting) {
        return Err(ProfileDataError::Invalid("H3 local SETTINGS namespace"));
    }
    settings.validate_fields(order_limits(limits))?;
    if settings.fields.len() > limits.bytes / 16 {
        return Err(ProfileDataError::LimitExceeded("H3 local SETTINGS bytes"));
    }
    let mut entries: Vec<_> = settings
        .fields
        .iter()
        .map(|field| {
            let ProtocolValue::Literal(value) = &field.value else {
                return Err(ProfileDataError::Invalid("H3 local SETTINGS binding"));
            };
            let value = u64::from_be_bytes(
                value
                    .as_ref()
                    .try_into()
                    .map_err(|_error| ProfileDataError::Invalid("H3 local SETTINGS value"))?,
            );
            let id = SettingId::new(field.id);
            Ok(if structural && id.is_reserved() {
                (SettingId::FIRST_RESERVED.value(), 0)
            } else {
                (field.id, value)
            })
        })
        .collect::<Result<_, ProfileDataError>>()?;
    if structural {
        entries.sort_unstable();
    }
    let mut output = Vec::new();
    for (id, value) in entries {
        output.extend_from_slice(&id.to_be_bytes());
        output.extend_from_slice(&value.to_be_bytes());
    }
    Ok(output)
}

fn decode_settings(
    bytes: &[u8],
    limits: H3SequenceCaptureLimits,
    structural: bool,
) -> Result<OrderedProtocolCapture, ProfileDataError> {
    if !bytes.len().is_multiple_of(16) || bytes.len() / 16 > limits.settings {
        return Err(ProfileDataError::Invalid("H3 local SETTINGS bytes"));
    }
    let mut fields = Vec::new();
    let mut candidates = 0;
    for bytes in bytes.as_chunks::<16>().0 {
        let mut id = u64::from_be_bytes(
            bytes[..8]
                .try_into()
                .map_err(|_error| ProfileDataError::Invalid("H3 setting id"))?,
        );
        if structural && id == SettingId::FIRST_RESERVED.value() {
            id += SettingId::RESERVED_INTERVAL * candidates;
            candidates += 1;
        }
        fields.push(OrderedProtocolField {
            id,
            value: ProtocolValue::Literal(bytes[8..].into()),
        });
    }
    let settings = OrderedProtocolCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        namespace: OrderNamespace::Http3Setting,
        fields: fields.into(),
    };
    settings.validate_fields(order_limits(limits))?;
    Ok(settings)
}

fn encode(
    capture: &H3ClientSequenceCapture,
    limits: H3SequenceCaptureLimits,
    structural: bool,
) -> Result<CanonicalValue, ProfileDataError> {
    capture
        .completeness
        .require_complete("H3 request-boundary sequence")?;
    if capture.events.len() > limits.events
        || capture.encoder_instructions.len() > limits.instructions
    {
        return Err(ProfileDataError::LimitExceeded("H3 sequence elements"));
    }
    let normalized;
    let capture = if structural {
        let mut events: Vec<_> = capture
            .events
            .iter()
            .filter_map(|event| match event {
                H3CapturedEvent::Stream { .. } => Some(event.clone()),
                H3CapturedEvent::Control { .. } => None,
            })
            .collect();
        // Control arrival relative to independent unidirectional streams and
        // request-owned priority/QPACK traffic do not identify a client.
        events.push(H3CapturedEvent::Control {
            frame_type: FrameType::SETTINGS.value(),
            length: 0,
            element_id: None,
            value: Box::default(),
        });
        normalized = H3ClientSequenceCapture {
            completeness: capture.completeness,
            local_settings: capture.local_settings.clone(),
            events: events.into(),
            encoder_instructions: Box::default(),
        };
        &normalized
    } else {
        capture
    };
    let local = settings_bytes(&capture.local_settings, limits, structural)?;
    let mut writer = CanonicalWriter::new(domain(structural), limits.bytes)?;
    writer.u8(capture.completeness.tag())?;
    writer.bytes(&local)?;
    writer.u64(capture.events.len() as u64)?;
    let mut stream_ids = Vec::new();
    let mut critical = 0u8;
    let mut settings = false;
    let mut control_seen = false;

    const CONTROL_STREAM_BIT: u8 = 1;
    const QPACK_ENCODER_STREAM_BIT: u8 = 2;
    const QPACK_DECODER_STREAM_BIT: u8 = 4;

    for event in &capture.events {
        match event {
            H3CapturedEvent::Stream {
                stream_id,
                stream_type,
            } => {
                varint(*stream_id)?;
                varint(*stream_type)?;
                if stream_id % 4 != 2 || stream_ids.contains(stream_id) {
                    return Err(ProfileDataError::Invalid("H3 client stream identity"));
                }

                let stream_type = StreamType::new(*stream_type);
                let bit = match stream_type {
                    StreamType::CONTROL => CONTROL_STREAM_BIT,
                    StreamType::QPACK_ENCODER => QPACK_ENCODER_STREAM_BIT,
                    StreamType::QPACK_DECODER => QPACK_DECODER_STREAM_BIT,
                    _ => 0,
                };
                if critical & bit != 0 || stream_type == StreamType::PUSH {
                    return Err(ProfileDataError::Invalid("H3 client critical stream"));
                }

                critical |= bit;
                let id = if structural {
                    2 + 4 * stream_ids.len() as u64
                } else {
                    *stream_id
                };
                stream_ids.push(*stream_id);
                writer.u8(0)?;
                writer.u64(id)?;
                writer.u64(if structural && stream_type.is_reserved() {
                    StreamType::FIRST_RESERVED.value()
                } else {
                    stream_type.value()
                })?;
            }
            H3CapturedEvent::Control {
                frame_type,
                length,
                element_id,
                value,
            } => {
                varint(*frame_type)?;
                varint(*length)?;
                if let Some(id) = element_id {
                    varint(*id)?;
                }

                let frame_type = FrameType::new(*frame_type);
                if critical & CONTROL_STREAM_BIT == 0
                    || (!control_seen && frame_type != FrameType::SETTINGS)
                    || (frame_type == FrameType::SETTINGS && settings)
                    || frame_type.is_h2_reserved()
                    || matches!(
                        frame_type,
                        FrameType::DATA | FrameType::HEADERS | FrameType::PUSH_PROMISE
                    )
                {
                    return Err(ProfileDataError::Invalid("H3 control stream order"));
                }

                control_seen = true;
                settings |= frame_type == FrameType::SETTINGS;
                let priority = frame_type.is_priority_update();
                let has_id = frame_type.carries_element_id();
                if element_id.is_some() != has_id
                    || (!priority && !value.is_empty())
                    || value.len() > limits.bytes
                    || (!structural && value.len() as u64 > *length)
                {
                    return Err(ProfileDataError::Invalid("H3 control payload shape"));
                }
                writer.u8(1)?;
                writer.u64(if structural && frame_type.is_reserved() {
                    FrameType::FIRST_RESERVED.value()
                } else {
                    frame_type.value()
                })?;
                writer.u64(if structural { 0 } else { *length })?;
                writer.u8(u8::from(element_id.is_some()))?;
                if let Some(id) = element_id {
                    writer.u64(if structural { 0 } else { *id })?;
                }
                writer.bytes(value)?;
            }
        }
    }
    if !settings {
        return Err(ProfileDataError::Incomplete("H3 SETTINGS"));
    }
    if !capture.encoder_instructions.is_empty() && critical & QPACK_ENCODER_STREAM_BIT == 0 {
        return Err(ProfileDataError::Invalid("missing H3 QPACK encoder stream"));
    }
    let maximum_capacity = match capture
        .local_settings
        .fields
        .iter()
        .find(|field| field.id == SettingId::QPACK_MAX_TABLE_CAPACITY.value())
    {
        None => 0,
        Some(field) => {
            let ProtocolValue::Literal(bytes) = &field.value else {
                return Err(ProfileDataError::Invalid("H3 QPACK capacity context"));
            };
            u64::from_be_bytes(
                bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_error| ProfileDataError::Invalid("H3 QPACK capacity context"))?,
            )
        }
    };
    writer.u64(capture.encoder_instructions.len() as u64)?;
    for instruction in &capture.encoder_instructions {
        match instruction {
            ObservedEncoderInstruction::Capacity { capacity } => {
                varint(*capacity)?;
                if *capacity > maximum_capacity {
                    return Err(ProfileDataError::Invalid("H3 QPACK advertised capacity"));
                }
                writer.u8(0)?;
                writer.u64(*capacity)?;
            }
            ObservedEncoderInstruction::InsertNameReference {
                is_static,
                index,
                value_bytes,
                value_huffman,
            } => {
                varint(*index)?;
                if *value_bytes > limits.observed_field_bytes
                    || (*is_static
                        && usize::try_from(*index)
                            .ok()
                            .and_then(static_table::get)
                            .is_none())
                {
                    return Err(ProfileDataError::Invalid("H3 QPACK name reference"));
                }
                writer.u8(1)?;
                writer.u8(u8::from(*is_static))?;
                writer.u64(if structural && !*is_static { 0 } else { *index })?;
                writer.u64(0)?;
                writer.u8(u8::from(*value_huffman))?;
            }
            ObservedEncoderInstruction::InsertLiteral {
                name_bytes,
                value_bytes,
                name_huffman,
                value_huffman,
            } => {
                if name_bytes.saturating_add(*value_bytes) > limits.observed_field_bytes {
                    return Err(ProfileDataError::LimitExceeded("H3 QPACK literal shape"));
                }
                writer.u8(2)?;
                writer.u64(if structural { 0 } else { *name_bytes as u64 })?;
                writer.u64(0)?;
                writer.u8(u8::from(*name_huffman))?;
                writer.u8(u8::from(*value_huffman))?;
            }
            ObservedEncoderInstruction::Duplicate { index } => {
                varint(*index)?;
                writer.u8(3)?;
                writer.u64(if structural { 0 } else { *index })?;
            }
        }
    }
    Ok(writer.finish())
}

#[cfg(test)]
mod tests;
