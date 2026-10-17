//! Field-section encoding preferences, independent of dynamic-table contents.

use super::static_table;
use crate::{
    HeaderMap,
    proto::h3::{
        PseudoHeader,
        observation::{FieldRepresentation, ObservedFieldRepresentation},
    },
};
use rama_core::extensions::Extension;
use std::collections::BTreeMap;

/// How to encode a field when references are legal under the current peer limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Representation {
    /// Prefer an exact static or dynamic reference, inserting when permitted.
    #[default]
    Automatic,
    /// Emit both name and value literally, without inserting the field.
    LiteralName,
    /// Emit a literal value with this stable static-table name index.
    /// An index naming a different field is rejected before encoder state changes.
    LiteralStaticName(u64),
    /// Reference a current dynamic name when possible, otherwise emit its name literally.
    /// Captured dynamic indexes are never reused.
    LiteralDynamicName,
}

/// Choices for one field; peer limits and the caller's sensitivity still apply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FieldPreferences {
    pub representation: Representation,
    /// Force Huffman (`true`) or plain (`false`) field names; `None` uses connection policy.
    pub name_huffman: Option<bool>,
    /// Force Huffman (`true`) or plain (`false`) literal values; `None` uses connection policy.
    /// Encoder-stream instructions continue to use the connection's Huffman policy.
    pub value_huffman: Option<bool>,
    /// Strengthen never-index; this cannot clear sensitivity supplied by the caller.
    pub never_index: bool,
}

impl FieldPreferences {
    /// Turn valid wire metadata into preferences for a fresh table.
    /// Static indexes are stable; dynamic indexes describe another table and are discarded.
    pub fn from_observed(field: &ObservedFieldRepresentation) -> Option<Self> {
        let index = field.index;
        let mut result = Self {
            never_index: field.never_index,
            ..Self::default()
        };
        match field.representation {
            FieldRepresentation::StaticIndex => {
                static_table::get(usize::try_from(index?).ok()?)?;
                if field.name_huffman || field.value_huffman || field.never_index {
                    return None;
                }
            }
            FieldRepresentation::DynamicIndex | FieldRepresentation::DynamicPostBaseIndex => {
                if index? >= 1 << 62
                    || field.name_huffman
                    || field.value_huffman
                    || field.never_index
                {
                    return None;
                }
            }
            FieldRepresentation::LiteralStaticName => {
                static_table::get(usize::try_from(index?).ok()?)?;
                if field.name_huffman {
                    return None;
                }
                result.representation = Representation::LiteralStaticName(index?);
                result.value_huffman = Some(field.value_huffman);
            }
            FieldRepresentation::LiteralDynamicName | FieldRepresentation::LiteralPostBaseName => {
                if index? >= 1 << 62 || field.name_huffman {
                    return None;
                }
                result.representation = Representation::LiteralDynamicName;
                result.value_huffman = Some(field.value_huffman);
            }
            FieldRepresentation::LiteralName => {
                if index.is_some() {
                    return None;
                }
                result.representation = Representation::LiteralName;
                result.name_huffman = Some(field.name_huffman);
                result.value_huffman = Some(field.value_huffman);
            }
        }
        Some(result)
    }
}

/// Optional request/response head-field preferences consumed by the HTTP/3 encoder.
///
/// Regular fields match by name and occurrence, preserving duplicate-field choices.
/// Pseudo-fields use their protocol names. Missing preferences retain native policy.
/// No header values or connection-specific table indexes are stored here.
/// Trailers retain the encoder's connection policy.
#[derive(Clone, Debug, Default, Extension)]
#[extension(tags(http))]
pub struct HeaderPreferences {
    pub headers: HeaderMap<FieldPreferences>,
    pub pseudo_headers: BTreeMap<PseudoHeader, FieldPreferences>,
}
