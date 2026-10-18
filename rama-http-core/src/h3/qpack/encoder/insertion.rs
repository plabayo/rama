//! Explicit current-field insertions, planned before mutating compression state.

use super::{EncodeField, Encoder, FieldEncoding, QpackError};
use crate::h3::qpack::dynamic_table::{InsertError, entry_size};
use rama_core::bytes::Bytes;
use rama_http_types::proto::h3::qpack::{
    encoding::{InsertionNameEncoding, InsertionPreferences},
    prefix::{StringEncoder, encode_int, int_encoded_len},
    static_table,
};

enum Name<'a> {
    Static(u64),
    Literal(StringEncoder<'a>),
}

struct Insertion<'a> {
    name: &'a [u8],
    value: &'a [u8],
    name_wire: Name<'a>,
    value_wire: StringEncoder<'a>,
}

impl<'a> Insertion<'a> {
    fn prepare(
        encoder: &Encoder,
        name: &'a [u8],
        value: &'a [u8],
        preferences: InsertionPreferences,
    ) -> Result<Self, QpackError> {
        let static_name = match preferences.name_encoding {
            InsertionNameEncoding::Automatic => {
                static_table::find_name(name).map(|index| index as u64)
            }
            InsertionNameEncoding::Literal => None,
            InsertionNameEncoding::StaticName(index) => {
                if usize::try_from(index)
                    .ok()
                    .and_then(static_table::get)
                    .map(|field| field.0)
                    != Some(name)
                {
                    return Err(QpackError::EncodeFieldSectionLimit(
                        "invalid insertion static-name preference",
                    ));
                }
                Some(index)
            }
        };
        Ok(Self {
            name,
            value,
            name_wire: match static_name {
                Some(index) => Name::Static(index),
                None => Name::Literal(encoder.literal_string(name, 5, preferences.name_huffman)),
            },
            value_wire: encoder.literal_string(value, 7, preferences.value_huffman),
        })
    }

    fn wire_len(&self) -> Result<usize, QpackError> {
        let name = match &self.name_wire {
            Name::Static(index) => int_encoded_len(*index, 6),
            Name::Literal(name) => name.encoded_len(),
        };
        name.checked_add(self.value_wire.encoded_len())
            .ok_or(QpackError::EncodeFieldSectionLimit(
                "insertion output length overflow",
            ))
    }

    fn apply(self, encoder: &mut Encoder) -> Result<(), InsertError> {
        encoder.table.insert(
            Bytes::copy_from_slice(self.name),
            Bytes::copy_from_slice(self.value),
            Some(encoder.known_received_count),
        )?;
        match self.name_wire {
            Name::Static(index) => encode_int(&mut encoder.encoder_output, index, 6, 0xc0),
            Name::Literal(name) => name.encode(&mut encoder.encoder_output, 0x40),
        }
        self.value_wire.encode(&mut encoder.encoder_output, 0);
        Ok(())
    }
}

pub(super) struct Plan<'a> {
    initialize_capacity: Option<u64>,
    insertions: Vec<Insertion<'a>>,
}

impl<'a> Plan<'a> {
    pub(super) fn prepare<'preferences, N, V>(
        encoder: &Encoder,
        input: &'a [(EncodeField<'preferences, N, V>, FieldEncoding)],
        count: usize,
    ) -> Result<Self, QpackError>
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let capacity = if encoder.capacity_initialized {
            encoder.table.capacity()
        } else {
            encoder.config.target_capacity
        };
        let initialize_capacity = (!encoder.capacity_initialized).then_some(capacity);
        let mut wire_bytes = initialize_capacity.map_or(0, |capacity| int_encoded_len(capacity, 5));
        let mut entry_bytes = 0u64;
        let mut insertions = Vec::with_capacity(count);
        for (field, _) in input {
            let Some(preferences) = field
                .preferences
                .and_then(|preferences| encoder.active_insertion(preferences))
            else {
                continue;
            };
            if field.never_index {
                return Err(QpackError::EncodeFieldSectionLimit(
                    "never-index field cannot be explicitly inserted",
                ));
            }
            let insertion = Insertion::prepare(
                encoder,
                field.name.as_ref(),
                field.value.as_ref(),
                preferences,
            )?;
            wire_bytes = wire_bytes.checked_add(insertion.wire_len()?).ok_or(
                QpackError::EncodeFieldSectionLimit("insertion output length overflow"),
            )?;
            entry_bytes = entry_bytes
                .checked_add(entry_size(insertion.name, insertion.value))
                .ok_or(QpackError::EncodeFieldSectionLimit(
                    "insertion table size overflow",
                ))?;
            insertions.push(insertion);
        }
        let count = u64::try_from(insertions.len())
            .map_err(|_error| QpackError::EncodeFieldSectionLimit("insertion count overflow"))?;
        encoder
            .table
            .can_insert_batch(capacity, count, entry_bytes, encoder.known_received_count)
            .map_err(|_error| {
                QpackError::StreamResourceLimit(
                    "explicit insertions exceed table capacity or references",
                )
            })?;
        if !encoder.output_fits(wire_bytes) {
            return Err(QpackError::OutputBlocked);
        }
        Ok(Self {
            initialize_capacity,
            insertions,
        })
    }

    pub(super) fn apply(self, encoder: &mut Encoder) -> Result<(), QpackError> {
        if let Some(capacity) = self.initialize_capacity {
            if !encoder.table.set_capacity(capacity) {
                return Err(QpackError::ResourceLimit(
                    "insertion capacity exceeds peer maximum",
                ));
            }
            encoder.capacity_initialized = true;
            encode_int(&mut encoder.encoder_output, capacity, 5, 0x20);
        }
        for insertion in self.insertions {
            // Only protocol table entries own copies. The plan borrows the current
            // fields and releases those borrows before ordinary field encoding.
            insertion.apply(encoder).map_err(|_error| {
                QpackError::ResourceLimit("insertion plan no longer fits the table")
            })?;
        }
        Ok(())
    }
}

/// Opportunistic compression uses the same literal planning and table commit as
/// explicit insertions, retaining its existing allocation-free rejection path.
pub(super) fn try_insert(encoder: &mut Encoder, name: &[u8], value: &[u8]) -> bool {
    if encoder
        .table
        .can_insert(entry_size(name, value), Some(encoder.known_received_count))
        .is_err()
    {
        return false;
    }
    let Ok(insertion) = Insertion::prepare(encoder, name, value, InsertionPreferences::default())
    else {
        return false;
    };
    let Ok(length) = insertion.wire_len() else {
        return false;
    };
    encoder.output_fits(length) && insertion.apply(encoder).is_ok()
}
