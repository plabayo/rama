//! Request and header captures stored as their profile's field table and index
//! lists rather than canonical bytes. Export rebuilds every compacted capture
//! through the load path and requires its exact canonical bytes back.

use std::sync::Arc;

use ahash::{HashMap, HashSet};
use rama_core::{bytes::Bytes, error::BoxError};
use rama_http::{HeaderName, HeaderValue, proto::h3::observation::ObservedFieldRepresentation};
use serde::{Deserialize, Serialize};

use crate::profile::{
    analysis::{capture::VariantValue, profile::AnalyzedProfile},
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{
            HeaderCapturePolicy, RequestBinding, representation_from_tag, representation_tag,
            version_from_tag, version_tag,
        },
        joint::{CapturedSlot, CapturedSlotKind, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::{CanonicalDomain, CanonicalValue, ProfileDataError, ValueId},
    replay::request::{
        CompactCapture, CompactKind, FieldEntry, FieldTable, FieldTableBuilder, PendingCompact,
        PlannedHeaders, PlannedValue,
    },
};

/// One profile of a compiled set.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct CompiledProfile {
    /// Compacted variants keep their id here; their bytes are empty.
    pub(super) analysis: AnalyzedProfile,
    fields: Vec<CompiledField>,
    pub(super) compact: Vec<CompiledCompact>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledField {
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
pub(super) struct CompiledCompact {
    pub(super) scope: u32,
    pub(super) variant: u32,
    capture: CompiledCapture,
}

#[derive(Debug, Serialize, Deserialize)]
enum CompiledCapture {
    /// A request joint capture: its headers and its other slots in canonical form.
    Request {
        headers: Option<CompiledHeaders>,
        other: Vec<(u16, CanonicalValue)>,
    },
    Headers(CompiledHeaders),
}

#[derive(Debug, Serialize, Deserialize)]
struct CompiledHeaders {
    completeness: u8,
    version: u8,
    /// Field table entry and occurrence, in captured order.
    fields: Vec<(u32, u32)>,
}

impl CompiledProfile {
    /// Every value stored with its bytes: scope structures, canonical variants and the
    /// canonical slots of compacted request captures.
    pub(super) fn values_mut(&mut self) -> Vec<&mut CanonicalValue> {
        let compacted = self.compacted();
        let mut values = Vec::new();
        for (scope_index, scope) in self.analysis.scopes.iter_mut().enumerate() {
            values.push(&mut scope.structure);
            for (variant_index, variant) in scope.observations.variants.iter_mut().enumerate() {
                if compacted.contains(&(scope_index, variant_index)) {
                    continue;
                }
                if let VariantValue::Canonical(value) = &mut variant.value {
                    values.push(value);
                }
            }
        }
        for compact in &mut self.compact {
            if let CompiledCapture::Request { other, .. } = &mut compact.capture {
                values.extend(other.iter_mut().map(|(_kind, value)| value));
            }
        }
        values
    }

    fn compacted(&self) -> HashSet<(usize, usize)> {
        self.compact
            .iter()
            .map(|compact| (compact.scope as usize, compact.variant as usize))
            .collect()
    }
}

/// Compact the request and header captures of `profile` and prove each rebuilds exactly.
pub(super) fn compile_profile(profile: &AnalyzedProfile) -> Result<CompiledProfile, BoxError> {
    let mut analysis = profile.clone();
    let mut builder = FieldTableBuilder::default();
    let mut pending = Vec::new();
    for (scope_index, scope) in analysis.scopes.iter_mut().enumerate() {
        let request = scope.flow.is_some() && scope.observations.domain == CanonicalDomain::Joint;
        let headers = scope.observations.domain == CanonicalDomain::Headers;
        if !request && !headers {
            continue;
        }
        for (variant_index, variant) in scope.observations.variants.iter_mut().enumerate() {
            let original = variant.value.canonical()?.into_owned();
            let compacted = if request {
                PendingCompact::request(&original, &mut builder)
            } else {
                PendingCompact::headers(&original, &mut builder)
            };
            // A capture that does not decode stays canonical; selection reports it.
            let Ok(compacted) = compacted else {
                variant.value = VariantValue::Canonical(original);
                continue;
            };
            variant.value = VariantValue::Canonical(CanonicalValue {
                id: original.id,
                bytes: Bytes::new(),
            });
            pending.push((scope_index, variant_index, original, compacted));
        }
    }
    let fields = compiled_fields(&builder.finish());
    // Rebuild through the load path, so export proves what loading will produce.
    let table = Arc::new(load_fields(&fields)?);
    let mut compact = Vec::with_capacity(pending.len());
    for (scope, variant, original, compacted) in pending {
        let capture = compiled_capture(compacted.kind());
        let loaded = load_capture(original.id, &capture, &table, &mut HashMap::default())?;
        if loaded.canonical()?.bytes != original.bytes {
            return Err(ProfileDataError::Invalid("compact capture round trip").into());
        }
        let position = |index: usize| {
            u32::try_from(index)
                .map_err(|_error| ProfileDataError::LimitExceeded("compact capture position"))
        };
        compact.push(CompiledCompact {
            scope: position(scope)?,
            variant: position(variant)?,
            capture,
        });
    }
    Ok(CompiledProfile {
        analysis,
        fields,
        compact,
    })
}

/// Put every compacted capture of `compiled` back into its analysis.
pub(super) fn load_profile(compiled: CompiledProfile) -> Result<AnalyzedProfile, BoxError> {
    let CompiledProfile {
        mut analysis,
        fields,
        compact,
    } = compiled;
    let table = Arc::new(load_fields(&fields)?);
    let mut pseudo = HashMap::default();
    for compact in compact {
        let variant = analysis
            .scopes
            .get_mut(compact.scope as usize)
            .and_then(|scope| {
                scope
                    .observations
                    .variants
                    .get_mut(compact.variant as usize)
            })
            .ok_or(ProfileDataError::Invalid("compact capture position"))?;
        let id = variant.value.id();
        variant.value = VariantValue::Compact(Arc::new(load_capture(
            id,
            &compact.capture,
            &table,
            &mut pseudo,
        )?));
    }
    Ok(analysis)
}

fn compiled_fields(table: &FieldTable) -> Vec<CompiledField> {
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

fn load_fields(fields: &[CompiledField]) -> Result<FieldTable, ProfileDataError> {
    let limit = HeaderCapturePolicy::default().bytes;
    let entries = fields
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
        .collect::<Result<_, ProfileDataError>>()?;
    Ok(FieldTable::new(entries))
}

fn header_value(bytes: &Bytes) -> Result<PlannedValue, ProfileDataError> {
    HeaderValue::from_maybe_shared(bytes.clone())
        .map(PlannedValue::Profile)
        .map_err(|_error| ProfileDataError::Invalid("compact header value"))
}

fn compiled_capture(kind: &CompactKind) -> CompiledCapture {
    match kind {
        CompactKind::Request { plan, other } => CompiledCapture::Request {
            headers: plan.headers().map(compiled_headers),
            other: other
                .iter()
                .map(|slot| (slot.kind.tag(), slot.value.clone()))
                .collect(),
        },
        CompactKind::Headers(headers) => CompiledCapture::Headers(compiled_headers(headers)),
    }
}

fn compiled_headers(headers: &PlannedHeaders) -> CompiledHeaders {
    CompiledHeaders {
        completeness: headers.completeness.tag(),
        version: version_tag(headers.version),
        fields: headers
            .fields
            .iter()
            .map(|field| (field.entry, field.occurrence))
            .collect(),
    }
}

fn load_capture(
    id: ValueId,
    capture: &CompiledCapture,
    table: &Arc<FieldTable>,
    pseudo: &mut HashMap<ValueId, Arc<PseudoHeaderCapture>>,
) -> Result<CompactCapture, ProfileDataError> {
    let kind = match capture {
        CompiledCapture::Headers(headers) => CompactKind::Headers(load_headers(headers, table)?),
        CompiledCapture::Request { other, .. }
            if other.len() >= JointCaptureLimits::default().slots =>
        {
            return Err(ProfileDataError::LimitExceeded("compact request slots"));
        }
        CompiledCapture::Request { headers, other } => CompactKind::request(
            headers
                .as_ref()
                .map(|headers| load_headers(headers, table))
                .transpose()?,
            other
                .iter()
                .map(|(kind, value)| {
                    Ok(CapturedSlot {
                        kind: CapturedSlotKind::from_tag(*kind)?,
                        value: value.clone(),
                    })
                })
                .collect::<Result<_, ProfileDataError>>()?,
            pseudo,
        )?,
    };
    Ok(PendingCompact::from_parts(id, kind).finish(Arc::clone(table)))
}

/// The limits the canonical header decoder applies, so a compact capture never replays more.
fn load_headers(
    headers: &CompiledHeaders,
    table: &FieldTable,
) -> Result<PlannedHeaders, ProfileDataError> {
    let policy = HeaderCapturePolicy::default();
    if headers.fields.len() > policy.fields {
        return Err(ProfileDataError::LimitExceeded("compact header fields"));
    }
    let completeness = ProfileCaptureCompleteness::from_tag(headers.completeness)?;
    completeness.require_complete("compact header capture")?;
    let fields = headers
        .fields
        .iter()
        .map(|(entry, occurrence)| table.field(*entry, *occurrence))
        .collect::<Result<Box<[_]>, ProfileDataError>>()?;
    let bytes = fields.iter().fold(0_usize, |total, field| {
        let entry = table.get(*field);
        let value = match &entry.value {
            PlannedValue::Profile(value) => value.len(),
            PlannedValue::Request(_) => 0,
        };
        total
            .saturating_add(entry.name.as_str().len())
            .saturating_add(value)
    });
    if bytes > policy.bytes {
        return Err(ProfileDataError::LimitExceeded("compact header bytes"));
    }
    Ok(PlannedHeaders {
        completeness,
        version: version_from_tag(headers.version)?,
        fields,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::format::compiled::decode_compiled_profiles;

    fn compiled_with_headers(edit: impl Fn(&mut CompiledHeaders)) -> CompiledProfile {
        let profiles = decode_compiled_profiles(include_bytes!("../embed_profiles.bin")).unwrap();
        let mut compiled = compile_profile(&profiles[0]).unwrap();
        let headers = compiled
            .compact
            .iter_mut()
            .find_map(|compact| match &mut compact.capture {
                CompiledCapture::Request {
                    headers: Some(headers),
                    ..
                } => Some(headers),
                _ => None,
            })
            .unwrap();
        edit(headers);
        compiled
    }

    #[test]
    fn compact_plans_beyond_the_header_limits_are_refused_at_load() {
        let many = compiled_with_headers(|headers| {
            let first = headers.fields[0];
            headers.fields = vec![first; 32_768];
        });
        let error = load_profile(many).unwrap_err();
        assert!(
            error.to_string().contains("compact header fields"),
            "{error}"
        );

        let incomplete = compiled_with_headers(|headers| {
            headers.completeness = ProfileCaptureCompleteness::Incomplete.tag();
        });
        load_profile(incomplete).unwrap_err();

        let intact = compiled_with_headers(|_headers| {});
        load_profile(intact).unwrap();
    }
}
