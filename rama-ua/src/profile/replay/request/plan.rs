//! A request variant decoded and validated once, so every replay of it only
//! builds headers instead of revalidating the canonical capture.
//!
//! Variants of a profile mostly reorder the same fields, so a plan lists
//! positions in the profile's field table, where each distinct field (name
//! spelling, value or request binding, wire representation) is stored once.
//! Compiled sets keep request and header captures in this compact form only;
//! [`CompactCapture::canonical`] rebuilds the exact canonical bytes on demand.

use std::sync::Arc;

use ahash::{HashMap, HashSet};
use rama_http::{
    HeaderName, HeaderValue, Version, proto::h3::observation::ObservedFieldRepresentation,
};

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        headers::{
            HeaderCapture, HeaderCapturePolicy, HeaderOccurrence, HeaderValueSource, RequestBinding,
        },
        joint::{CaptureLevel, CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        pseudo_headers::PseudoHeaderCapture,
    },
    format::canonical::{CanonicalValue, ProfileDataError, ValueId},
};

/// The slots of a request variant in captured order.
#[derive(Debug)]
pub(crate) struct RequestReplayPlan {
    pub(super) slots: Box<[PlannedSlot]>,
}

#[derive(Debug)]
pub(super) enum PlannedSlot {
    Headers(PlannedHeaders),
    PseudoHeaders(Arc<PseudoHeaderCapture>),
    RuntimeMetadata,
}

#[derive(Debug)]
pub(crate) struct PlannedHeaders {
    pub(crate) completeness: ProfileCaptureCompleteness,
    pub(crate) version: Version,
    pub(crate) fields: Box<[PlannedField]>,
}

impl PlannedHeaders {
    fn retained_bytes(&self) -> usize {
        size_of_val::<[PlannedField]>(&self.fields)
    }
}

/// One occurrence of a field table entry.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PlannedField {
    pub(crate) entry: u32,
    pub(crate) occurrence: u32,
}

/// A distinct captured field of a profile.
#[derive(Debug)]
pub(crate) struct FieldEntry {
    pub(crate) name: HeaderName,
    pub(crate) sensitive: bool,
    pub(crate) representation: Option<ObservedFieldRepresentation>,
    pub(crate) value: PlannedValue,
    /// Imported as capture-safe; replayed like any profile value.
    pub(crate) capture_safe: bool,
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
    fn retained_bytes(&self) -> usize {
        self.0
            .iter()
            .map(|entry| {
                size_of::<FieldEntry>()
                    + entry.name.as_str().len()
                    + match &entry.value {
                        PlannedValue::Profile(value) => value.len(),
                        PlannedValue::Request(_) => 0,
                    }
            })
            .sum()
    }

    pub(crate) fn new(entries: Vec<FieldEntry>) -> Self {
        Self(entries.into_boxed_slice())
    }

    pub(crate) fn get(&self, field: PlannedField) -> &FieldEntry {
        &self.0[field.entry as usize]
    }

    #[cfg(feature = "embed-profiles")]
    pub(crate) fn entries(&self) -> &[FieldEntry] {
        &self.0
    }

    /// A planned field that names an entry of this table.
    #[cfg(feature = "embed-profiles")]
    pub(crate) fn field(
        &self,
        entry: u32,
        occurrence: u32,
    ) -> Result<PlannedField, ProfileDataError> {
        if (entry as usize) < self.0.len() {
            Ok(PlannedField { entry, occurrence })
        } else {
            Err(ProfileDataError::Invalid("compact header field entry"))
        }
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
    CaptureSafe(Box<[u8]>),
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
        FieldTable::new(self.entries)
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
                HeaderValueSource::Profile(bytes) => KeyValue::Profile(bytes.clone()),
                HeaderValueSource::CaptureSafeProfile(bytes) => {
                    KeyValue::CaptureSafe(bytes.clone())
                }
                HeaderValueSource::Request(binding) => KeyValue::Request(binding.tag()),
            },
        };
        if let Some(entry) = self.index.get(&key) {
            return Ok(PlannedField {
                entry: *entry,
                occurrence,
            });
        }
        let capture_safe = matches!(field.value, HeaderValueSource::CaptureSafeProfile(_));
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
            capture_safe,
        });
        self.index.insert(key, entry);
        Ok(PlannedField { entry, occurrence })
    }

    fn headers(&mut self, capture: HeaderCapture) -> Result<PlannedHeaders, ProfileDataError> {
        Ok(PlannedHeaders {
            completeness: capture.completeness,
            version: capture.version,
            fields: capture
                .fields
                .into_vec()
                .into_iter()
                .map(|field| self.field(field))
                .collect::<Result<_, ProfileDataError>>()?,
        })
    }
}

impl RequestReplayPlan {
    /// Decode and validate `capture` with the same checks replay applies.
    pub(crate) fn decode(
        capture: &CanonicalValue,
        fields: &mut FieldTableBuilder,
    ) -> Result<Self, ProfileDataError> {
        let joint = JointCapture::from_canonical(capture, JointCaptureLimits::default())?;
        Ok(Self::from_joint(&joint, fields)?.0)
    }

    /// The plan of a decoded request joint and its slots other than headers.
    fn from_joint(
        joint: &JointCapture,
        fields: &mut FieldTableBuilder,
    ) -> Result<(Self, Vec<CapturedSlot>), ProfileDataError> {
        if joint.level != CaptureLevel::Request {
            return Err(ProfileDataError::Invalid("request capture level"));
        }
        let limits = JointCaptureLimits::default();
        let mut other = Vec::new();
        let slots = joint
            .slots
            .iter()
            .map(|slot| {
                if slot.kind != CapturedSlotKind::Headers {
                    other.push(slot.clone());
                }
                Ok(match slot.kind {
                    CapturedSlotKind::Headers => {
                        PlannedSlot::Headers(fields.headers(HeaderCapture::from_canonical(
                            &slot.value,
                            &HeaderCapturePolicy::default(),
                        )?)?)
                    }
                    CapturedSlotKind::PseudoHeaders => PlannedSlot::PseudoHeaders(Arc::new(
                        PseudoHeaderCapture::from_canonical(&slot.value, limits.value_bytes)?,
                    )),
                    CapturedSlotKind::RuntimeMetadata => PlannedSlot::RuntimeMetadata,
                    _ => {
                        return Err(ProfileDataError::Invalid(
                            "connection slot in request capture",
                        ));
                    }
                })
            })
            .collect::<Result<_, ProfileDataError>>()?;
        Ok((Self { slots }, other))
    }

    /// The captured header fields, if the variant recorded any.
    pub(crate) fn headers(&self) -> Option<&PlannedHeaders> {
        self.slots.iter().find_map(|slot| match slot {
            PlannedSlot::Headers(headers) => Some(headers),
            PlannedSlot::PseudoHeaders(_) | PlannedSlot::RuntimeMetadata => None,
        })
    }
}

/// A request or header capture held as fields of its profile's table instead of
/// canonical bytes. Compiled sets load their request captures this way.
#[derive(Debug)]
pub struct CompactCapture {
    id: ValueId,
    fields: Arc<FieldTable>,
    kind: CompactKind,
}

#[derive(Debug)]
#[cfg_attr(
    not(feature = "embed-profiles"),
    expect(
        dead_code,
        reason = "only compiled profile sets build compact captures"
    )
)]
pub(crate) enum CompactKind {
    /// A request joint capture: its replay plan and its slots other than headers.
    Request {
        plan: RequestReplayPlan,
        other: Box<[CapturedSlot]>,
    },
    Headers(PlannedHeaders),
}

/// A compact capture waiting for its profile's finished field table.
#[cfg(feature = "embed-profiles")]
#[derive(Debug)]
pub(crate) struct PendingCompact {
    id: ValueId,
    kind: CompactKind,
}

#[cfg(feature = "embed-profiles")]
impl PendingCompact {
    /// Compact a canonical request joint capture, validating it.
    pub(crate) fn request(
        value: &CanonicalValue,
        fields: &mut FieldTableBuilder,
    ) -> Result<Self, ProfileDataError> {
        let joint = JointCapture::from_canonical(value, JointCaptureLimits::default())?;
        let (plan, other) = RequestReplayPlan::from_joint(&joint, fields)?;
        Ok(Self {
            id: value.id,
            kind: CompactKind::Request {
                plan,
                other: other.into(),
            },
        })
    }

    /// Compact a canonical header capture, validating it.
    pub(crate) fn headers(
        value: &CanonicalValue,
        fields: &mut FieldTableBuilder,
    ) -> Result<Self, ProfileDataError> {
        let capture = HeaderCapture::from_canonical(value, &HeaderCapturePolicy::default())?;
        Ok(Self {
            id: value.id,
            kind: CompactKind::Headers(fields.headers(capture)?),
        })
    }

    pub(crate) fn kind(&self) -> &CompactKind {
        &self.kind
    }

    /// A compact capture from parts already validated when the set was exported.
    pub(crate) fn from_parts(id: ValueId, kind: CompactKind) -> Self {
        Self { id, kind }
    }

    pub(crate) fn finish(self, fields: Arc<FieldTable>) -> CompactCapture {
        CompactCapture {
            id: self.id,
            fields,
            kind: self.kind,
        }
    }
}

#[cfg(feature = "embed-profiles")]
impl CompactKind {
    /// A compact request capture; equal pseudo-header slots of a profile decode once.
    pub(crate) fn request(
        headers: Option<PlannedHeaders>,
        other: Vec<CapturedSlot>,
        pseudo: &mut HashMap<ValueId, Arc<PseudoHeaderCapture>>,
    ) -> Result<Self, ProfileDataError> {
        let limits = JointCaptureLimits::default();
        let mut slots: Vec<(CapturedSlotKind, PlannedSlot)> = Vec::with_capacity(other.len() + 1);
        if let Some(headers) = headers {
            slots.push((CapturedSlotKind::Headers, PlannedSlot::Headers(headers)));
        }
        for slot in &other {
            slots.push((
                slot.kind,
                match slot.kind {
                    CapturedSlotKind::PseudoHeaders => {
                        let capture = if let Some(capture) = pseudo.get(&slot.value.id) {
                            Arc::clone(capture)
                        } else {
                            let capture = Arc::new(PseudoHeaderCapture::from_canonical(
                                &slot.value,
                                limits.value_bytes,
                            )?);
                            pseudo.insert(slot.value.id, Arc::clone(&capture));
                            capture
                        };
                        PlannedSlot::PseudoHeaders(capture)
                    }
                    CapturedSlotKind::RuntimeMetadata => PlannedSlot::RuntimeMetadata,
                    _ => {
                        return Err(ProfileDataError::Invalid(
                            "connection slot in request capture",
                        ));
                    }
                },
            ));
        }
        slots.sort_by_key(|(kind, _slot)| *kind);
        Ok(Self::Request {
            plan: RequestReplayPlan {
                slots: slots.into_iter().map(|(_kind, slot)| slot).collect(),
            },
            other: other.into(),
        })
    }
}

impl CompactCapture {
    #[must_use]
    pub fn id(&self) -> ValueId {
        self.id
    }

    /// Tests: whether both captures read the same field table.
    #[cfg(all(test, feature = "embed-profiles"))]
    pub(crate) fn shares_fields_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.fields, &other.fields)
    }

    /// Approximate heap bytes this capture holds; field tables and pseudo-header
    /// captures shared with captures already in `shared` are not counted again.
    pub(crate) fn retained_bytes(&self, shared: &mut HashSet<usize>) -> usize {
        let mut bytes = size_of::<Self>();
        if shared.insert(Arc::as_ptr(&self.fields).addr()) {
            bytes += self.fields.retained_bytes();
        }
        match &self.kind {
            CompactKind::Headers(headers) => bytes + headers.retained_bytes(),
            CompactKind::Request { plan, other } => {
                bytes += other
                    .iter()
                    .map(|slot| size_of::<CapturedSlot>() + slot.value.bytes.len())
                    .sum::<usize>();
                for slot in &plan.slots {
                    bytes += size_of::<PlannedSlot>();
                    match slot {
                        PlannedSlot::Headers(headers) => bytes += headers.retained_bytes(),
                        PlannedSlot::PseudoHeaders(capture) => {
                            if shared.insert(Arc::as_ptr(capture).addr()) {
                                bytes += size_of::<PseudoHeaderCapture>()
                                    + size_of_val::<[_]>(&capture.fields);
                            }
                        }
                        PlannedSlot::RuntimeMetadata => {}
                    }
                }
                bytes
            }
        }
    }

    /// The request replay plan, for a compact request capture.
    pub(crate) fn plan(&self) -> Option<(&RequestReplayPlan, &FieldTable)> {
        match &self.kind {
            CompactKind::Request { plan, .. } => Some((plan, &self.fields)),
            CompactKind::Headers(_) => None,
        }
    }

    /// Rebuild the exact canonical capture this compact form was made from.
    pub fn canonical(&self) -> Result<CanonicalValue, ProfileDataError> {
        let policy = HeaderCapturePolicy::default();
        let value = match &self.kind {
            CompactKind::Headers(headers) => self.header_capture(headers).canonical(&policy)?,
            CompactKind::Request { plan, other } => {
                let mut slots = other.to_vec();
                if let Some(headers) = plan.headers() {
                    slots.push(CapturedSlot {
                        kind: CapturedSlotKind::Headers,
                        value: self.header_capture(headers).canonical(&policy)?,
                    });
                }
                slots.sort_by_key(|slot| slot.kind);
                JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Request,
                    slots: slots.into(),
                }
                .canonical(JointCaptureLimits::default())?
            }
        };
        if value.id != self.id {
            return Err(ProfileDataError::Invalid("compact capture identity"));
        }
        Ok(value)
    }

    fn header_capture(&self, headers: &PlannedHeaders) -> HeaderCapture {
        HeaderCapture {
            completeness: headers.completeness,
            version: headers.version,
            fields: headers
                .fields
                .iter()
                .map(|field| {
                    let entry = self.fields.get(*field);
                    HeaderOccurrence {
                        name: entry.name.clone(),
                        occurrence: field.occurrence,
                        sensitive: entry.sensitive,
                        representation: entry.representation,
                        value: match &entry.value {
                            PlannedValue::Profile(value) if entry.capture_safe => {
                                HeaderValueSource::CaptureSafeProfile(value.as_bytes().into())
                            }
                            PlannedValue::Profile(value) => {
                                HeaderValueSource::Profile(value.as_bytes().into())
                            }
                            PlannedValue::Request(binding) => HeaderValueSource::Request(*binding),
                        },
                    }
                })
                .collect(),
        }
    }
}
