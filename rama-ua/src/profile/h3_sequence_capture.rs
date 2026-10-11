//! HTTP/3 client stream/control prefixes and QPACK instruction shapes.

use super::{
    CanonicalDomain, CanonicalValue, OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture,
    OrderedProtocolField, ProfileCaptureCompleteness, ProfileDataError, ProtocolValue,
    canonical::{CanonicalReader, CanonicalWriter},
};
use rama_http::proto::h3::{
    observation::{H3ObservationSnapshot, ObservedControlFrame, ObservedEncoderInstruction},
    qpack::static_table,
};
use rama_utils::octets::kib;
use serde::Serialize;

#[derive(Debug, Clone, Copy)]
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
/// revision gaps have no wire meaning. Stream and control events share relative order; QPACK has
/// only its own instruction order. No order between those sequences is invented.
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
        if source.settings_received != source.control.iter().any(|frame| frame.frame_type == 4) {
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

    pub(super) fn decode(
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

fn reserved(id: u64) -> bool {
    id >= 0x21 && (id - 0x21).is_multiple_of(31)
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
            Ok(if structural && reserved(field.id) {
                (0x21, 0)
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
        if structural && id == 0x21 {
            id += 31 * candidates;
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
            frame_type: 4,
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
                let bit = match stream_type {
                    0 => 1,
                    2 => 2,
                    3 => 4,
                    _ => 0,
                };
                if critical & bit != 0 || *stream_type == 1 {
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
                writer.u64(if structural && reserved(*stream_type) {
                    0x21
                } else {
                    *stream_type
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
                if critical & 1 == 0
                    || (!control_seen && *frame_type != 4)
                    || (*frame_type == 4 && settings)
                    || matches!(frame_type, 0 | 1 | 2 | 5 | 6 | 8 | 9)
                {
                    return Err(ProfileDataError::Invalid("H3 control stream order"));
                }
                control_seen = true;
                settings |= *frame_type == 4;
                let priority = matches!(*frame_type, 0xf0700 | 0xf0701);
                let has_id = matches!(*frame_type, 3 | 7 | 13 | 0xf0700 | 0xf0701);
                if element_id.is_some() != has_id
                    || (!priority && !value.is_empty())
                    || value.len() > limits.bytes
                    || (!structural && value.len() as u64 > *length)
                {
                    return Err(ProfileDataError::Invalid("H3 control payload shape"));
                }
                writer.u8(1)?;
                writer.u64(if structural && reserved(*frame_type) {
                    0x21
                } else {
                    *frame_type
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
    if !capture.encoder_instructions.is_empty() && critical & 2 == 0 {
        return Err(ProfileDataError::Invalid("missing H3 QPACK encoder stream"));
    }
    let maximum_capacity = match capture
        .local_settings
        .fields
        .iter()
        .find(|field| field.id == 1)
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
mod tests {
    use super::*;
    use crate::profile::{
        CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits, ValueId,
    };
    use rama_http::proto::h3::observation::{
        ObservationCompleteness, ObservedSetting, ObservedUniStream,
    };
    use sha2::{Digest as _, Sha256};

    #[test]
    fn compact_local_settings_accept_exact_budget_with_settings_prefix() {
        for count in [0, 1, 2, 3, 16, 256] {
            let mut source = source();
            source.streams.retain(|stream| stream.stream_type == 0);
            source.control.retain(|frame| frame.frame_type == 4);
            source.encoder_instructions.clear();
            source.local_settings = (0..count)
                .map(|index| ObservedSetting {
                    id: 0x21 + 31 * index,
                    value: index,
                    grease: true,
                })
                .collect();
            let limits = H3SequenceCaptureLimits::default();
            let capture =
                H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap();
            for value in [
                capture.canonical(limits).unwrap(),
                capture.structural(limits).unwrap(),
            ] {
                let exact = H3SequenceCaptureLimits {
                    bytes: value.bytes.len(),
                    ..limits
                };
                value.validated_domain(exact.bytes).unwrap();
                value.validated_domain(exact.bytes - 1).unwrap_err();
                // Structural encoding omits per-request details; its budget
                // does not substitute for the raw capture's input budget.
                value.validated_domain(exact.bytes).unwrap();
            }
        }
    }

    fn source() -> H3ObservationSnapshot {
        H3ObservationSnapshot {
            revision: 10,
            settings_received: true,
            settings: Some(vec![]),
            local_settings: vec![ObservedSetting {
                id: 1,
                value: 4096,
                grease: false,
            }],
            streams: vec![
                ObservedUniStream {
                    sequence: 2,
                    stream_id: 2,
                    stream_type: 0,
                    grease: false,
                },
                ObservedUniStream {
                    sequence: 5,
                    stream_id: 10,
                    stream_type: 0x21,
                    grease: true,
                },
                ObservedUniStream {
                    sequence: 3,
                    stream_id: 18,
                    stream_type: 2,
                    grease: false,
                },
            ],
            control: vec![
                ObservedControlFrame {
                    sequence: 4,
                    frame_type: 4,
                    length: 0,
                    element_id: None,
                    value: Box::default(),
                },
                ObservedControlFrame {
                    sequence: 9,
                    frame_type: 0xf0700,
                    length: 4,
                    element_id: Some(0),
                    value: b"u=1".as_slice().into(),
                },
                ObservedControlFrame {
                    sequence: 10,
                    frame_type: 0x21,
                    length: 13,
                    element_id: None,
                    value: Box::default(),
                },
            ],
            encoder_instructions: vec![
                ObservedEncoderInstruction::Capacity { capacity: 4096 },
                ObservedEncoderInstruction::InsertLiteral {
                    name_bytes: 4,
                    value_bytes: 12,
                    name_huffman: false,
                    value_huffman: true,
                },
            ],
            completeness: ObservationCompleteness {
                snapshot: true,
                settings: true,
                local_settings: true,
                streams: true,
                control: true,
                qpack: true,
                fields: true,
            },
            connection_error: None,
        }
    }

    fn capture() -> H3ClientSequenceCapture {
        H3ClientSequenceCapture::capture_at_request_head(
            &source(),
            H3SequenceCaptureLimits::default(),
        )
        .unwrap()
    }

    fn resign(bytes: Vec<u8>) -> CanonicalValue {
        CanonicalValue {
            id: ValueId(Sha256::digest(&bytes).into()),
            bytes: bytes.into(),
        }
    }

    #[test]
    fn h3_sequence_preserves_merged_relative_order_and_independent_qpack_order() {
        let limits = H3SequenceCaptureLimits::default();
        let capture = capture();
        let encoded = capture.canonical(limits).unwrap();
        let restored = H3ClientSequenceCapture::from_canonical(&encoded, limits).unwrap();
        assert_eq!(
            serde_json::to_value(&capture).unwrap(),
            serde_json::to_value(&restored).unwrap()
        );
        assert!(matches!(
            restored.events[0],
            H3CapturedEvent::Stream { stream_type: 0, .. }
        ));
        assert!(matches!(
            restored.events[2],
            H3CapturedEvent::Control { frame_type: 4, .. }
        ));
        assert!(matches!(
            restored.events[3],
            H3CapturedEvent::Stream {
                stream_type: 0x21,
                ..
            }
        ));
        let mut later = source();
        later.revision = 100;
        for stream in &mut later.streams {
            stream.sequence += 20;
        }
        for frame in &mut later.control {
            frame.sequence += 20;
        }
        assert_eq!(
            encoded.id,
            H3ClientSequenceCapture::capture_at_request_head(&later, limits)
                .unwrap()
                .canonical(limits)
                .unwrap()
                .id
        );
        later.streams[1].sequence = 21;
        assert_ne!(
            encoded.id,
            H3ClientSequenceCapture::capture_at_request_head(&later, limits)
                .unwrap()
                .canonical(limits)
                .unwrap()
                .id
        );
    }

    #[test]
    fn h3_sequence_requires_complete_component_prefixes_and_valid_revisions() {
        let limits = H3SequenceCaptureLimits::default();
        for case in 0..9 {
            let mut source = source();
            match case {
                0 => source.completeness.snapshot = false,
                1 => source.completeness.local_settings = false,
                2 => source.completeness.streams = false,
                3 => source.completeness.control = false,
                4 => source.completeness.qpack = false,
                5 => source.connection_error = Some(0x100),
                6 => source.control[0].sequence = 2,
                7 => source.revision = 9,
                _ => source.settings_received = false,
            }
            H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap_err();
        }
        let mut source = source();
        source.settings_received = false;
        source.settings = None;
        source.completeness.settings = false;
        source.streams.clear();
        source.control.clear();
        source.encoder_instructions.clear();
        H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap_err();
    }

    #[test]
    fn h3_sequence_budget_precedes_owned_capture_and_bounds_all_arrays() {
        let source = source();
        let limits = H3SequenceCaptureLimits::default();
        let size = capture().canonical(limits).unwrap().bytes.len();
        for limits in [
            H3SequenceCaptureLimits {
                events: 4,
                ..limits
            },
            H3SequenceCaptureLimits {
                instructions: 1,
                ..limits
            },
            H3SequenceCaptureLimits {
                settings: 0,
                ..limits
            },
            H3SequenceCaptureLimits {
                bytes: size - 1,
                ..limits
            },
        ] {
            H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap_err();
        }
        H3ClientSequenceCapture::capture_at_request_head(
            &source,
            H3SequenceCaptureLimits {
                bytes: size,
                ..limits
            },
        )
        .unwrap();
    }

    #[test]
    fn h3_sequence_import_enforces_stream_roles_control_order_and_instruction_shapes() {
        let limits = H3SequenceCaptureLimits::default();
        for case in 0..10 {
            let mut value = capture();
            match case {
                0 => {
                    value.events[0] = H3CapturedEvent::Stream {
                        stream_id: 3,
                        stream_type: 0,
                    }
                }
                1 => {
                    value.events[3] = H3CapturedEvent::Stream {
                        stream_id: 2,
                        stream_type: 0x21,
                    }
                }
                2 => {
                    value.events[3] = H3CapturedEvent::Stream {
                        stream_id: 10,
                        stream_type: 0,
                    }
                }
                3 => value.events.swap(0, 2),
                4 => {
                    value.events[4] = H3CapturedEvent::Control {
                        frame_type: 4,
                        length: 0,
                        element_id: None,
                        value: Box::default(),
                    }
                }
                5 => {
                    value.events[4] = H3CapturedEvent::Control {
                        frame_type: 0,
                        length: 0,
                        element_id: None,
                        value: Box::default(),
                    }
                }
                6 => {
                    value.encoder_instructions[1] =
                        ObservedEncoderInstruction::InsertNameReference {
                            is_static: true,
                            index: 99,
                            value_bytes: 0,
                            value_huffman: false,
                        }
                }
                7 => {
                    value.events[5] = H3CapturedEvent::Control {
                        frame_type: 0x21,
                        length: 1,
                        element_id: None,
                        value: Box::new([7]),
                    }
                }
                8 => {
                    value.encoder_instructions[0] =
                        ObservedEncoderInstruction::Capacity { capacity: 4097 }
                }
                _ => {
                    value.events[1] = H3CapturedEvent::Stream {
                        stream_id: 18,
                        stream_type: 0x40,
                    }
                }
            }
            value.canonical(limits).unwrap_err();
        }
    }

    #[test]
    fn h3_sequence_structures_group_reserved_draws_and_connection_references() {
        let limits = H3SequenceCaptureLimits::default();
        let mut key = None;
        for sequence in 0..10_000u64 {
            let mut value = capture();
            value.events[3] = H3CapturedEvent::Stream {
                stream_id: 22 + 4 * sequence,
                stream_type: 0x21 + 31 * sequence,
            };
            value.events[5] = H3CapturedEvent::Control {
                frame_type: 0x21 + 31 * sequence,
                length: sequence % 17,
                element_id: None,
                value: Box::default(),
            };
            value.encoder_instructions[1] = ObservedEncoderInstruction::InsertLiteral {
                name_bytes: 3,
                value_bytes: sequence as usize % 256,
                name_huffman: false,
                value_huffman: true,
            };
            let structure = value.structural(limits).unwrap();
            assert_eq!(*key.get_or_insert(structure.id), structure.id);
            structure.validated_domain(limits.bytes).unwrap();
        }
        let mut value = capture();
        value.encoder_instructions[0] = ObservedEncoderInstruction::Capacity { capacity: 1024 };
        assert_eq!(key.unwrap(), value.structural(limits).unwrap().id);
    }

    #[test]
    fn h3_sequence_import_rejects_bad_envelopes_trailers_and_noncanonical_structure() {
        let limits = H3SequenceCaptureLimits::default();
        let value = capture().canonical(limits).unwrap();
        for size in 0..value.bytes.len() {
            H3ClientSequenceCapture::from_canonical(&resign(value.bytes[..size].to_vec()), limits)
                .unwrap_err();
        }
        let mut bad = value.clone();
        bad.id.0[0] ^= 1;
        bad.validated_domain(limits.bytes).unwrap_err();
        let mut bytes = value.bytes.to_vec();
        bytes.push(0);
        resign(bytes).validated_domain(limits.bytes).unwrap_err();
        let mut bytes = value.bytes.to_vec();
        bytes[16] = 20;
        resign(bytes).validated_domain(limits.bytes).unwrap_err();
    }

    #[test]
    fn h3_sequence_is_quic_connection_owned_in_joint_captures() {
        let value = capture()
            .canonical(H3SequenceCaptureLimits::default())
            .unwrap();
        let mut joint = JointCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            level: CaptureLevel::Connection,
            slots: Box::new([CapturedSlot {
                kind: CapturedSlotKind::Http3Sequence,
                value,
            }]),
        };
        let limits = JointCaptureLimits::default();
        joint.canonical(limits).unwrap();
        joint
            .structural(limits)
            .unwrap()
            .validated_domain(limits.bytes)
            .unwrap();
        joint.level = CaptureLevel::Request;
        joint.canonical(limits).unwrap_err();
    }

    #[test]
    fn qpack_shape_lengths_have_separate_observed_and_encoded_budgets() {
        for instruction in [
            ObservedEncoderInstruction::InsertNameReference {
                is_static: true,
                index: 0,
                value_bytes: 4096,
                value_huffman: false,
            },
            ObservedEncoderInstruction::InsertLiteral {
                name_bytes: 512,
                value_bytes: 4096,
                name_huffman: false,
                value_huffman: true,
            },
        ] {
            let mut capture = capture();
            capture.encoder_instructions = Box::new([instruction]);
            let value = capture
                .canonical(H3SequenceCaptureLimits::default())
                .unwrap();
            assert!(value.bytes.len() < 512);
            let limits = H3SequenceCaptureLimits {
                bytes: value.bytes.len(),
                ..H3SequenceCaptureLimits::default()
            };
            capture.canonical(limits).unwrap();
            H3ClientSequenceCapture::from_canonical(&value, limits).unwrap();
            value.validated_domain(value.bytes.len()).unwrap();
            capture
                .canonical(H3SequenceCaptureLimits {
                    observed_field_bytes: 511,
                    ..limits
                })
                .unwrap_err();
            let decoded = H3ClientSequenceCapture::from_canonical(
                &value,
                H3SequenceCaptureLimits {
                    observed_field_bytes: 511,
                    ..limits
                },
            );
            if matches!(
                capture.encoder_instructions[0],
                ObservedEncoderInstruction::InsertLiteral { .. }
            ) {
                decoded.unwrap_err();
            } else {
                // The inserted value length is deliberately not retained.
                decoded.unwrap();
            }
            capture
                .canonical(H3SequenceCaptureLimits {
                    bytes: value.bytes.len() - 1,
                    ..limits
                })
                .unwrap_err();
        }
    }

    #[test]
    fn h3_structure_ignores_request_qpack_priority_and_control_arrival() {
        let limits = H3SequenceCaptureLimits::default();
        let original = capture();
        let structure = original.structural(limits).unwrap();
        let sample = original.canonical(limits).unwrap();
        for static_index in [5, 84] {
            // cookie and authorization
            let mut different = capture();
            different.encoder_instructions = Box::new([
                ObservedEncoderInstruction::Capacity { capacity: 1024 },
                ObservedEncoderInstruction::InsertNameReference {
                    is_static: true,
                    index: static_index,
                    value_bytes: 37,
                    value_huffman: false,
                },
                ObservedEncoderInstruction::Duplicate { index: 0 },
            ]);
            different.events[4] = H3CapturedEvent::Control {
                frame_type: 0xf0700,
                length: 9,
                element_id: Some(12),
                value: b"u=7, i".as_slice().into(),
            };
            // SETTINGS arrives before the independent encoder stream.
            different.events.swap(1, 2);
            assert_eq!(different.structural(limits).unwrap().id, structure.id);
            assert_ne!(different.canonical(limits).unwrap().id, sample.id);
            different.encoder_instructions = Box::default();
            assert_eq!(different.structural(limits).unwrap().id, structure.id);
        }
        let mut before_settings = source();
        before_settings.settings_received = false;
        before_settings.settings = None;
        before_settings.control.clear();
        H3ClientSequenceCapture::capture_at_request_head(&before_settings, limits).unwrap_err();
    }

    #[test]
    fn h3_sequence_has_independent_canonical_goldens() {
        let capture = capture();
        let limits = H3SequenceCaptureLimits::default();
        for (value, expected, digest) in [
            (
                capture.canonical(limits).unwrap(),
                "72616d612d70726f66696c65000001001301000000000000001000000000000000010000000000001000000000000000000600000000000000000200000000000000000000000000000000120000000000000002010000000000000004000000000000000000000000000000000000000000000000000a00000000000000210100000000000f070000000000000000040100000000000000000000000000000003753d31010000000000000021000000000000000d000000000000000000000000000000000200000000000000100002000000000000000400000000000000000001",
                "17dafb08287c4f1b63cef92932102914dd0d2363ef485fac1410a047b8fce619",
            ),
            (
                capture.structural(limits).unwrap(),
                "72616d612d70726f66696c6500000100140100000000000000100000000000000001000000000000100000000000000000040000000000000000020000000000000000000000000000000006000000000000000200000000000000000a000000000000002101000000000000000400000000000000000000000000000000000000000000000000",
                "7a3a2c785c879a0190c797ec5552ede85cfa5c54a28969960966ec4a13067974",
            ),
        ] {
            let bytes = value
                .bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            let hash = value
                .id
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            assert_eq!(bytes, expected);
            assert_eq!(hash, digest);
        }
    }

    #[test]
    fn h3_sequence_rejects_out_of_range_wire_integers() {
        let limits = H3SequenceCaptureLimits::default();
        for case in 0..6 {
            let mut capture = capture();
            match case {
                0 => {
                    capture.events[3] = H3CapturedEvent::Stream {
                        stream_id: (1_u64 << 62) + 2,
                        stream_type: 33,
                    }
                }
                1 => {
                    capture.events[3] = H3CapturedEvent::Stream {
                        stream_id: 10,
                        stream_type: 1_u64 << 62,
                    }
                }
                2 => {
                    capture.events[5] = H3CapturedEvent::Control {
                        frame_type: 1_u64 << 62,
                        length: 0,
                        element_id: None,
                        value: Box::default(),
                    }
                }
                3 => {
                    capture.events[5] = H3CapturedEvent::Control {
                        frame_type: 33,
                        length: 1_u64 << 62,
                        element_id: None,
                        value: Box::default(),
                    }
                }
                4 => {
                    capture.events[4] = H3CapturedEvent::Control {
                        frame_type: 0xf0700,
                        length: 12,
                        element_id: Some(1_u64 << 62),
                        value: b"u=1".as_slice().into(),
                    }
                }
                _ => {
                    capture.encoder_instructions[1] =
                        ObservedEncoderInstruction::Duplicate { index: 1_u64 << 62 }
                }
            }
            capture.canonical(limits).unwrap_err();
            capture.structural(limits).unwrap_err();
        }
        let mut capture = capture();
        capture.encoder_instructions[1] = ObservedEncoderInstruction::Duplicate {
            index: (1_u64 << 62) - 1,
        };
        capture.canonical(limits).unwrap();
    }

    #[test]
    fn qpack_samples_do_not_retain_request_value_lengths() {
        let limits = H3SequenceCaptureLimits::default();
        for reference in [false, true] {
            let mut sample_id = None;
            for length in [1, 8, 128, kib(8)] {
                let mut source = source();
                source.encoder_instructions = vec![if reference {
                    ObservedEncoderInstruction::InsertNameReference {
                        is_static: true,
                        index: 5,
                        value_bytes: length,
                        value_huffman: true,
                    }
                } else {
                    ObservedEncoderInstruction::InsertLiteral {
                        name_bytes: 6,
                        value_bytes: length,
                        name_huffman: false,
                        value_huffman: true,
                    }
                }];
                let captured =
                    H3ClientSequenceCapture::capture_at_request_head(&source, limits).unwrap();
                assert!(matches!(
                    captured.encoder_instructions[0],
                    ObservedEncoderInstruction::InsertNameReference { value_bytes: 0, .. }
                        | ObservedEncoderInstruction::InsertLiteral { value_bytes: 0, .. }
                ));
                let encoded = captured.canonical(limits).unwrap();
                assert_eq!(*sample_id.get_or_insert(encoded.id), encoded.id);
            }
        }
    }
}
