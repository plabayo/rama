//! Bounded HTTP/3 observation values, independent of the connection driver.

use super::qpack::{EncoderInstruction, FieldLine};
use crate::proto::h2::PseudoHeaderOrder;
use rama_core::extensions::Extension;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub struct ObservationLimits {
    pub bytes: usize,
    pub events: usize,
    pub fields: usize,
    pub streams: usize,
    /// Maximum live connection snapshots and pending decoded field observations,
    /// each independently capped. Request consumers release field observations on delivery.
    pub retained_snapshots: usize,
}

impl Default for ObservationLimits {
    fn default() -> Self {
        Self {
            bytes: 64 * 1024,
            events: 256,
            fields: 256,
            streams: 32,
            retained_snapshots: 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldRepresentation {
    StaticIndex,
    DynamicIndex,
    DynamicPostBaseIndex,
    LiteralStaticName,
    LiteralDynamicName,
    LiteralPostBaseName,
    LiteralName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedFieldRepresentation {
    pub representation: FieldRepresentation,
    pub index: Option<u64>,
    pub name_huffman: bool,
    pub value_huffman: bool,
    pub never_index: bool,
}

impl From<&FieldLine> for ObservedFieldRepresentation {
    fn from(line: &FieldLine) -> Self {
        let (representation, index, name_huffman, value_huffman, never_index) = match line {
            FieldLine::Indexed { is_static, index } => (
                if *is_static {
                    FieldRepresentation::StaticIndex
                } else {
                    FieldRepresentation::DynamicIndex
                },
                Some(*index),
                false,
                false,
                false,
            ),
            FieldLine::IndexedPostBase { index } => (
                FieldRepresentation::DynamicPostBaseIndex,
                Some(*index),
                false,
                false,
                false,
            ),
            FieldLine::LiteralWithNameRef {
                is_static,
                name_index,
                value_huffman,
                never_index,
                ..
            } => (
                if *is_static {
                    FieldRepresentation::LiteralStaticName
                } else {
                    FieldRepresentation::LiteralDynamicName
                },
                Some(*name_index),
                false,
                *value_huffman,
                *never_index,
            ),
            FieldLine::LiteralWithPostBaseNameRef {
                name_index,
                value_huffman,
                never_index,
                ..
            } => (
                FieldRepresentation::LiteralPostBaseName,
                Some(*name_index),
                false,
                *value_huffman,
                *never_index,
            ),
            FieldLine::LiteralWithLiteralName {
                name_huffman,
                value_huffman,
                never_index,
                ..
            } => (
                FieldRepresentation::LiteralName,
                None,
                *name_huffman,
                *value_huffman,
                *never_index,
            ),
        };
        Self {
            representation,
            index,
            name_huffman,
            value_huffman,
            never_index,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservedEncoderInstruction {
    Capacity {
        capacity: u64,
    },
    InsertNameReference {
        is_static: bool,
        index: u64,
        value_bytes: usize,
        value_huffman: bool,
    },
    InsertLiteral {
        name_bytes: usize,
        value_bytes: usize,
        name_huffman: bool,
        value_huffman: bool,
    },
    Duplicate {
        index: u64,
    },
}

impl From<&EncoderInstruction> for ObservedEncoderInstruction {
    fn from(value: &EncoderInstruction) -> Self {
        match value {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => Self::Capacity {
                capacity: *capacity,
            },
            EncoderInstruction::InsertWithNameRef {
                is_static,
                name_index,
                value,
                value_huffman,
            } => Self::InsertNameReference {
                is_static: *is_static,
                index: *name_index,
                value_bytes: value.len(),
                value_huffman: *value_huffman,
            },
            EncoderInstruction::InsertWithLiteralName {
                name,
                value,
                name_huffman,
                value_huffman,
            } => Self::InsertLiteral {
                name_bytes: name.len(),
                value_bytes: value.len(),
                name_huffman: *name_huffman,
                value_huffman: *value_huffman,
            },
            EncoderInstruction::Duplicate { index } => Self::Duplicate { index: *index },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedSetting {
    pub id: u64,
    pub value: u64,
    pub grease: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedUniStream {
    pub sequence: u64,
    pub stream_id: u64,
    pub stream_type: u64,
    pub grease: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedControlFrame {
    pub sequence: u64,
    pub frame_type: u64,
    pub length: u64,
    pub element_id: Option<u64>,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ObservationCompleteness {
    pub settings: bool,
    pub streams: bool,
    pub control: bool,
    pub qpack: bool,
    pub fields: bool,
    pub snapshot: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct H3ObservationSnapshot {
    pub revision: u64,
    pub settings: Option<Vec<ObservedSetting>>,
    pub local_settings: Vec<ObservedSetting>,
    pub streams: Vec<ObservedUniStream>,
    pub control: Vec<ObservedControlFrame>,
    pub encoder_instructions: Vec<ObservedEncoderInstruction>,
    pub completeness: ObservationCompleteness,
    pub connection_error: Option<u64>,
}

/// Immutable connection and field-representation data at request-head delivery.
#[derive(Debug, Clone)]
pub struct H3RequestObservation {
    pub connection: Arc<H3ObservationSnapshot>,
    pub fields: Vec<ObservedFieldRepresentation>,
    pub fields_complete: bool,
    pub priority: Option<Vec<u8>>,
}
impl Extension for H3RequestObservation {}

/// Additive echo/fingerprint view. Missing SETTINGS remain `null`, with an explicit status.
#[derive(Debug, Serialize)]
pub struct H3ObservationView<'a> {
    pub connection_revision: u64,
    pub request_revision: u64,
    pub settings_status: &'a str,
    pub settings: &'a Option<Vec<ObservedSetting>>,
    pub local_settings: &'a [ObservedSetting],
    pub streams: &'a [ObservedUniStream],
    pub control: &'a [ObservedControlFrame],
    pub qpack: &'a [ObservedEncoderInstruction],
    pub priorities: &'a Option<Vec<u8>>,
    pub pseudo_headers: Option<&'a PseudoHeaderOrder>,
    pub request_fields: &'a [ObservedFieldRepresentation],
    pub completeness: ObservationCompleteness,
}

impl H3RequestObservation {
    #[must_use]
    pub fn view<'a>(
        &'a self,
        connection: &'a H3ObservationSnapshot,
        settings_status: &'a str,
        pseudo_headers: Option<&'a PseudoHeaderOrder>,
    ) -> H3ObservationView<'a> {
        let mut completeness = connection.completeness;
        completeness.fields = self.fields_complete;
        H3ObservationView {
            connection_revision: connection.revision,
            request_revision: self.connection.revision,
            settings_status,
            settings: &connection.settings,
            local_settings: &connection.local_settings,
            streams: &connection.streams,
            control: &connection.control,
            qpack: &connection.encoder_instructions,
            priorities: &self.priority,
            pseudo_headers,
            request_fields: &self.fields,
            completeness,
        }
    }
}
