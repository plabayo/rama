//! A request variant decoded and validated once, so every replay of it only
//! builds headers instead of revalidating the canonical capture.
//!
//! Variants of a profile mostly reorder the same fields, so a plan lists
//! positions in the profile's field table, where each distinct field (name
//! spelling, value or request binding, wire representation) is stored once.

use ahash::HashMap;
use rama_http::{
    HeaderName, HeaderValue, Version, proto::h3::observation::ObservedFieldRepresentation,
};

use crate::profile::{
    capture::{
        headers::{
            HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource, RequestBinding,
        },
        joint::{CaptureLevel, CapturedSlotKind, JointCapture, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::{CanonicalValue, ProfileDataError},
};

/// The slots of a request variant in captured order.
#[derive(Debug)]
pub(crate) struct RequestReplayPlan {
    pub(super) slots: Box<[PlannedSlot]>,
}

#[derive(Debug)]
pub(super) enum PlannedSlot {
    Headers(PlannedHeaders),
    PseudoHeaders(PseudoHeaderCapture),
    RuntimeMetadata,
}

#[derive(Debug)]
pub(crate) struct PlannedHeaders {
    pub(crate) version: Version,
    pub(crate) fields: Box<[PlannedField]>,
}

/// One occurrence of a field table entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PlannedField {
    entry: u32,
    pub(crate) occurrence: u32,
}

/// A distinct captured field of a profile.
#[derive(Debug)]
pub(crate) struct FieldEntry {
    pub(crate) name: HeaderName,
    pub(crate) sensitive: bool,
    pub(crate) representation: Option<ObservedFieldRepresentation>,
    pub(crate) value: PlannedValue,
}

#[derive(Debug)]
pub(crate) enum PlannedValue {
    Profile(HeaderValue),
    Request(RequestBinding),
}

/// The fields of one profile's plans; immutable once built, so replay reads it lock-free.
#[derive(Debug, Default)]
pub(crate) struct FieldTable(Box<[FieldEntry]>);

impl FieldTable {
    pub(crate) fn get(&self, field: PlannedField) -> &FieldEntry {
        &self.0[field.entry as usize]
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
struct EntryKey {
    /// The spelling as captured: names compare case-insensitively, but HTTP/1 sends their case.
    name: Box<str>,
    sensitive: bool,
    representation: Option<(u8, Option<u64>, [bool; 3])>,
    value: KeyValue,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum KeyValue {
    Profile(Box<[u8]>),
    Request(u8),
}

/// Collects the distinct fields of the plans built for one profile.
#[derive(Debug, Default)]
pub(crate) struct FieldTableBuilder {
    entries: Vec<FieldEntry>,
    index: HashMap<EntryKey, u32>,
}

impl FieldTableBuilder {
    pub(crate) fn get(&self, field: PlannedField) -> &FieldEntry {
        &self.entries[field.entry as usize]
    }

    pub(crate) fn finish(self) -> FieldTable {
        FieldTable(self.entries.into_boxed_slice())
    }

    fn field(&mut self, field: HeaderOccurrence) -> Result<PlannedField, ProfileDataError> {
        let occurrence = field.occurrence;
        let key = EntryKey {
            name: field.name.as_original_str().into(),
            sensitive: field.sensitive,
            representation: field.representation.map(|observed| {
                (
                    observed.representation as u8,
                    observed.index,
                    [
                        observed.name_huffman,
                        observed.value_huffman,
                        observed.never_index,
                    ],
                )
            }),
            value: match &field.value {
                HeaderValueSource::Profile(bytes)
                | HeaderValueSource::CaptureSafeProfile(bytes) => KeyValue::Profile(bytes.clone()),
                HeaderValueSource::Request(binding) => KeyValue::Request(*binding as u8),
            },
        };
        if let Some(entry) = self.index.get(&key) {
            return Ok(PlannedField {
                entry: *entry,
                occurrence,
            });
        }
        let value = match field.value {
            HeaderValueSource::Profile(bytes) | HeaderValueSource::CaptureSafeProfile(bytes) => {
                PlannedValue::Profile(
                    HeaderValue::from_bytes(&bytes).map_err(|_error| {
                        ProfileDataError::Invalid("profile replay header value")
                    })?,
                )
            }
            HeaderValueSource::Request(binding) => PlannedValue::Request(binding),
        };
        let entry = u32::try_from(self.entries.len())
            .map_err(|_error| ProfileDataError::LimitExceeded("profile replay fields"))?;
        self.entries.push(FieldEntry {
            name: field.name,
            sensitive: field.sensitive,
            representation: field.representation,
            value,
        });
        self.index.insert(key, entry);
        Ok(PlannedField { entry, occurrence })
    }
}

impl RequestReplayPlan {
    /// Decode and validate `capture` with the same checks replay applies.
    pub(crate) fn decode(
        capture: &CanonicalValue,
        fields: &mut FieldTableBuilder,
    ) -> Result<Self, ProfileDataError> {
        let limits = JointCaptureLimits::default();
        let joint = JointCapture::from_canonical(capture, limits)?;
        if joint.level != CaptureLevel::Request {
            return Err(ProfileDataError::Invalid("request capture level"));
        }
        let slots = joint
            .slots
            .iter()
            .map(|slot| {
                Ok(match slot.kind {
                    CapturedSlotKind::Headers => {
                        let capture = HeaderCapture::from_canonical(
                            &slot.value,
                            &HeaderCapturePolicy::default(),
                        )?;
                        PlannedSlot::Headers(PlannedHeaders {
                            version: capture.version,
                            fields: capture
                                .fields
                                .into_vec()
                                .into_iter()
                                .map(|field| fields.field(field))
                                .collect::<Result<_, ProfileDataError>>()?,
                        })
                    }
                    CapturedSlotKind::PseudoHeaders => PlannedSlot::PseudoHeaders(
                        PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes)?,
                    ),
                    CapturedSlotKind::RuntimeMetadata => PlannedSlot::RuntimeMetadata,
                    _ => {
                        return Err(ProfileDataError::Invalid(
                            "connection slot in request capture",
                        ));
                    }
                })
            })
            .collect::<Result<_, ProfileDataError>>()?;
        Ok(Self { slots })
    }

    /// The captured header fields, if the variant recorded any.
    pub(crate) fn headers(&self) -> Option<&PlannedHeaders> {
        self.slots.iter().find_map(|slot| match slot {
            PlannedSlot::Headers(headers) => Some(headers),
            PlannedSlot::PseudoHeaders(_) | PlannedSlot::RuntimeMetadata => None,
        })
    }
}
