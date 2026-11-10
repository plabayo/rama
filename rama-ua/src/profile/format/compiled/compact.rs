//! Request and header captures stored as positions in the set's field table rather
//! than canonical bytes. Each distinct header capture is stored once for the set.

use std::sync::Arc;

use ahash::HashMap;
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http::{HeaderName, HeaderValue, proto::h3::observation::ObservedFieldRepresentation};
use serde::{Deserialize, Serialize};

use super::wire::WireValue;
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{
            HeaderCapturePolicy, RequestBinding, representation_from_tag, representation_tag,
            version_from_tag, version_tag,
        },
        joint::{CapturedSlot, CapturedSlotKind, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::{CanonicalValue, ProfileDataError, ValueId},
    replay::request::{
        CompactKind, FieldEntry, FieldTable, PlannedField, PlannedHeaders, PlannedValue,
    },
};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CompiledField {
    /// The name as captured, including its case.
    name: Box<str>,
    sensitive: bool,
    representation: Option<CompiledRepresentation>,
    value: CompiledFieldValue,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledRepresentation {
    kind: u8,
    index: Option<u64>,
    name_huffman: bool,
    value_huffman: bool,
    never_index: bool,
}

#[derive(Debug, Serialize, Deserialize)]
enum CompiledFieldValue {
    Profile(Bytes),
    CaptureSafe(Bytes),
    Request(u8),
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) enum CompiledCapture {
    /// A request joint capture: its headers and its other slots in canonical form.
    Request {
        headers: Option<u32>,
        other: Vec<(u16, WireValue)>,
    },
    Headers(u32),
}

/// One distinct header capture of the set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(super) struct CompiledHeaders {
    pub(super) completeness: u8,
    version: u8,
    /// Set field table entry and occurrence, in captured order.
    pub(super) fields: Box<[(u32, u32)]>,
}

impl CompiledCapture {
    /// The canonical slots of a request capture.
    pub(super) fn values_mut(&mut self) -> impl Iterator<Item = &mut WireValue> {
        let other = match self {
            Self::Request { other, .. } => other.as_mut_slice(),
            Self::Headers(_) => &mut [],
        };
        other.iter_mut().map(|(_kind, value)| value)
    }
}

/// Collects each distinct header capture of a set once.
#[derive(Default)]
pub(super) struct HeaderInterner {
    headers: Vec<CompiledHeaders>,
    index: HashMap<CompiledHeaders, u32>,
}

impl HeaderInterner {
    fn intern(&mut self, headers: &PlannedHeaders) -> Result<u32, ProfileDataError> {
        let headers = CompiledHeaders {
            completeness: headers.completeness.tag(),
            version: version_tag(headers.version),
            fields: headers
                .fields
                .iter()
                .map(|field| (field.entry, field.occurrence))
                .collect(),
        };
        if let Some(index) = self.index.get(&headers) {
            return Ok(*index);
        }
        let index = u32::try_from(self.headers.len())
            .map_err(|_error| ProfileDataError::LimitExceeded("compiled header captures"))?;
        self.headers.push(headers.clone());
        self.index.insert(headers, index);
        Ok(index)
    }

    pub(super) fn finish(self) -> Vec<CompiledHeaders> {
        self.headers
    }
}

pub(super) fn compiled_capture(
    kind: &CompactKind,
    headers: &mut HeaderInterner,
) -> Result<CompiledCapture, ProfileDataError> {
    Ok(match kind {
        CompactKind::Request { plan, other } => CompiledCapture::Request {
            headers: plan
                .headers()
                .map(|planned| headers.intern(planned))
                .transpose()?,
            other: other
                .iter()
                .map(|slot| (slot.kind.tag(), WireValue::Bytes(slot.value.bytes.clone())))
                .collect(),
        },
        CompactKind::Headers(planned) => CompiledCapture::Headers(headers.intern(planned)?),
    })
}

pub(super) fn compiled_fields(table: &FieldTable) -> Vec<CompiledField> {
    table
        .entries()
        .iter()
        .map(|entry| CompiledField {
            name: entry.name.as_original_str().into(),
            sensitive: entry.sensitive,
            representation: entry.representation.map(|observed| CompiledRepresentation {
                kind: representation_tag(observed.representation),
                index: observed.index,
                name_huffman: observed.name_huffman,
                value_huffman: observed.value_huffman,
                never_index: observed.never_index,
            }),
            value: match &entry.value {
                PlannedValue::Profile(value) if entry.capture_safe => {
                    CompiledFieldValue::CaptureSafe(Bytes::copy_from_slice(value.as_bytes()))
                }
                PlannedValue::Profile(value) => {
                    CompiledFieldValue::Profile(Bytes::copy_from_slice(value.as_bytes()))
                }
                PlannedValue::Request(binding) => CompiledFieldValue::Request(binding.tag()),
            },
        })
        .collect()
}

pub(super) fn load_fields(fields: &[CompiledField]) -> Result<Vec<FieldEntry>, ProfileDataError> {
    let limit = HeaderCapturePolicy::default().bytes;
    fields
        .iter()
        .map(|field| {
            let value_bytes = match &field.value {
                CompiledFieldValue::Profile(bytes) | CompiledFieldValue::CaptureSafe(bytes) => {
                    bytes.len()
                }
                CompiledFieldValue::Request(_) => 0,
            };
            if field.name.len().saturating_add(value_bytes) > limit {
                return Err(ProfileDataError::LimitExceeded(
                    "compact header field bytes",
                ));
            }
            let (value, capture_safe) = match &field.value {
                CompiledFieldValue::Profile(bytes) => (header_value(bytes)?, false),
                CompiledFieldValue::CaptureSafe(bytes) => (header_value(bytes)?, true),
                CompiledFieldValue::Request(tag) => (
                    PlannedValue::Request(RequestBinding::from_tag(*tag)?),
                    false,
                ),
            };
            Ok(FieldEntry {
                name: HeaderName::from_bytes(field.name.as_bytes())
                    .map_err(|_error| ProfileDataError::Invalid("compact header name"))?,
                sensitive: field.sensitive,
                representation: field
                    .representation
                    .as_ref()
                    .map(|representation| {
                        Ok::<_, ProfileDataError>(ObservedFieldRepresentation {
                            representation: representation_from_tag(representation.kind)?,
                            index: representation.index,
                            name_huffman: representation.name_huffman,
                            value_huffman: representation.value_huffman,
                            never_index: representation.never_index,
                        })
                    })
                    .transpose()?,
                value,
                capture_safe,
            })
        })
        .collect()
}

fn header_value(bytes: &Bytes) -> Result<PlannedValue, ProfileDataError> {
    HeaderValue::from_maybe_shared(bytes.clone())
        .map(PlannedValue::Profile)
        .map_err(|_error| ProfileDataError::Invalid("compact header value"))
}

/// The field table of one profile: the set entries its captures name, in first use order.
pub(super) struct ProfileFields<'a> {
    fields: &'a [FieldEntry],
    headers: &'a [CompiledHeaders],
    local: HashMap<u32, u32>,
    entries: Vec<FieldEntry>,
    pseudo: HashMap<ValueId, Arc<PseudoHeaderCapture>>,
}

impl<'a> ProfileFields<'a> {
    pub(super) fn new(fields: &'a [FieldEntry], headers: &'a [CompiledHeaders]) -> Self {
        Self {
            fields,
            headers,
            local: HashMap::default(),
            entries: Vec::new(),
            pseudo: HashMap::default(),
        }
    }

    /// Load a compact capture whose canonical slots `resolve` returns.
    pub(super) fn capture(
        &mut self,
        capture: &CompiledCapture,
        mut resolve: impl FnMut(&WireValue) -> Result<CanonicalValue, BoxError>,
    ) -> Result<CompactKind, BoxError> {
        Ok(match capture {
            CompiledCapture::Headers(index) => CompactKind::Headers(self.headers(*index)?),
            CompiledCapture::Request { other, .. }
                if other.len() >= JointCaptureLimits::default().slots =>
            {
                return Err(ProfileDataError::LimitExceeded("compact request slots").into());
            }
            CompiledCapture::Request { headers, other } => {
                let headers = headers.map(|index| self.headers(index)).transpose()?;
                let other = other
                    .iter()
                    .map(|(kind, value)| {
                        Ok(CapturedSlot {
                            kind: CapturedSlotKind::from_tag(*kind)?,
                            value: resolve(value)?,
                        })
                    })
                    .collect::<Result<_, BoxError>>()?;
                CompactKind::request(headers, other, &mut self.pseudo)?
            }
        })
    }

    /// The limits the canonical header decoder applies, so a compact capture never replays more.
    fn headers(&mut self, index: u32) -> Result<PlannedHeaders, ProfileDataError> {
        let headers = self
            .headers
            .get(index as usize)
            .ok_or(ProfileDataError::Invalid("compact header capture index"))?;
        let policy = HeaderCapturePolicy::default();
        if headers.fields.len() > policy.fields {
            return Err(ProfileDataError::LimitExceeded("compact header fields"));
        }
        let completeness = ProfileCaptureCompleteness::from_tag(headers.completeness)?;
        completeness.require_complete("compact header capture")?;
        let mut bytes = 0_usize;
        let mut fields = Vec::with_capacity(headers.fields.len());
        for (entry, occurrence) in &headers.fields {
            let field = self
                .fields
                .get(*entry as usize)
                .ok_or(ProfileDataError::Invalid("compact header field entry"))?;
            let value = match &field.value {
                PlannedValue::Profile(value) => value.len(),
                PlannedValue::Request(_) => 0,
            };
            bytes = bytes
                .saturating_add(field.name.as_str().len())
                .saturating_add(value);
            let next = u32::try_from(self.entries.len())
                .map_err(|_error| ProfileDataError::LimitExceeded("profile replay fields"))?;
            let local = *self.local.entry(*entry).or_insert_with(|| {
                self.entries.push(field.clone());
                next
            });
            fields.push(PlannedField {
                entry: local,
                occurrence: *occurrence,
            });
        }
        if bytes > policy.bytes {
            return Err(ProfileDataError::LimitExceeded("compact header bytes"));
        }
        Ok(PlannedHeaders {
            completeness,
            version: version_from_tag(headers.version)?,
            fields: fields.into(),
        })
    }

    /// The finished table every capture of the profile shares.
    pub(super) fn finish(self) -> Arc<FieldTable> {
        Arc::new(FieldTable::new(self.entries))
    }
}
