//! Which reserved identifiers a profile generates per connection, read as slots.

use std::collections::{BTreeMap, BTreeSet};

use rama_quic_proto::{
    Version, transport_parameters::TransportParameterId, version::VersionInformation,
};

use crate::profile::{
    capture::{
        http3::{H3CapturedEvent, H3ClientSequenceCapture},
        order::{OrderNamespace, OrderedProtocolCapture, ProtocolValue},
        quic::QuicFlightCapture,
        reserved::{
            H3_FRAMES, ReservedFamily, ReservedLength, ReservedSlot, TRANSPORT_PARAMETERS,
            VERSION_SLOT,
        },
    },
    format::canonical::ProfileDataError,
};

/// Fewer distinct identifiers than this do not show that a client generates them.
const MINIMUM_GENERATED: usize = 16;
/// One bit per count of low ordinal bits a payload length may follow.
const COUPLINGS: u8 = 0b1_1110;
const VERSION_FREE_BITS: u32 = 0xf0f0_f0f0;
/// Fewer distinct payload lengths than this do not show that a client draws the length.
const MINIMUM_LENGTHS: u32 = 4;
/// Marks a payload too long to count among drawn lengths.
const LONG: u32 = u64::BITS - 1;

/// What the payloads of one identifier showed.
#[derive(Clone, Copy)]
struct Payloads {
    /// Couplings every payload satisfied.
    couplings: u8,
    /// One bit per payload length.
    lengths: u64,
}

impl Payloads {
    /// An identifier seen without its payload.
    const UNSEEN: Self = Self {
        couplings: COUPLINGS,
        lengths: 0,
    };

    fn of(family: ReservedFamily, id: u64, length: u64) -> Option<Self> {
        let ordinal = family.ordinal(id)?;
        Some(Self {
            couplings: (1..=4)
                .filter(|bits| length == ordinal & ((1 << bits) - 1))
                .fold(0, |couplings, bits| couplings | 1 << bits),
            lengths: 1 << length.min(u64::from(LONG)),
        })
    }

    fn merge(&mut self, other: Self) {
        self.couplings &= other.couplings;
        self.lengths |= other.lengths;
    }

    /// Whether every length up to the longest was seen.
    fn ranged(self) -> bool {
        self.lengths >> LONG == 0
            && (self.lengths + 1).is_power_of_two()
            && self.lengths.count_ones() >= MINIMUM_LENGTHS
    }
}

#[derive(Default)]
struct Identifiers {
    /// Components carrying each identifier, and what its payloads showed.
    seen: BTreeMap<u64, (u64, Payloads)>,
    components: u64,
}

impl Identifiers {
    fn component(&mut self, identifiers: impl IntoIterator<Item = (u64, Payloads)>) {
        let mut carried = BTreeMap::<u64, Payloads>::new();
        for (id, payloads) in identifiers {
            carried
                .entry(id)
                .or_insert(Payloads::UNSEEN)
                .merge(payloads);
        }
        if carried.is_empty() {
            return;
        }
        self.components += 1;
        for (id, payloads) in carried {
            let seen = self.seen.entry(id).or_insert((0, Payloads::UNSEEN));
            seen.0 += 1;
            seen.1.merge(payloads);
        }
    }

    fn generated(&self, family: ReservedFamily) -> Option<Generated> {
        let mut ids = BTreeSet::new();
        let (mut any, mut all, mut payloads) = (0_u64, u64::MAX, Payloads::UNSEEN);
        let mut unseen = false;
        for (&id, &(components, carried)) in &self.seen {
            // A constant recurs across the components; a slot is already read.
            if components * 2 > self.components || family.slot(id).is_some() {
                continue;
            }
            let Some(ordinal) = family.ordinal(id) else {
                continue;
            };
            any |= ordinal;
            all &= ordinal;
            payloads.merge(carried);
            unseen |= carried.lengths == 0;
            ids.insert(id);
        }
        if ids.len() < MINIMUM_GENERATED {
            return None;
        }
        let bits = u8::try_from(u64::BITS - any.leading_zeros()).ok()?;
        // A bit never seen set, or never seen clear, is not drawn freely.
        if all != 0 || any.count_ones() != u32::from(bits) {
            return None;
        }
        let length = match payloads.couplings.checked_ilog2() {
            _ if unseen => ReservedLength::Captured,
            Some(bits) => ReservedLength::Ordinal(bits as u8),
            None if payloads.ranged() => ReservedLength::Ranged,
            None => ReservedLength::Captured,
        };
        Some(Generated {
            ids,
            length,
            longest: payloads.lengths.checked_ilog2().unwrap_or(0) as usize,
            slot_id: family.slot_id(ReservedSlot { bits, length })?,
        })
    }
}

#[derive(Default)]
struct Versions {
    seen: BTreeMap<u32, u64>,
    components: u64,
}

impl Versions {
    fn component(&mut self, versions: impl IntoIterator<Item = Version>) {
        let carried: BTreeSet<u32> = versions
            .into_iter()
            .filter(|version| version.is_reserved())
            .map(Version::as_u32)
            .collect();
        if carried.is_empty() {
            return;
        }
        self.components += 1;
        for version in carried {
            *self.seen.entry(version).or_default() += 1;
        }
    }

    fn generated(&self) -> Option<BTreeSet<u32>> {
        let versions: BTreeSet<u32> = self
            .seen
            .iter()
            .filter(|(version, components)| {
                **components * 2 <= self.components && **version != VERSION_SLOT.as_u32()
            })
            .map(|(version, _components)| *version)
            .collect();
        let any = versions.iter().fold(0, |any, version| any | version);
        let all = versions.iter().fold(u32::MAX, |all, version| all & version);
        (versions.len() >= MINIMUM_GENERATED
            && any & VERSION_FREE_BITS == VERSION_FREE_BITS
            && all & VERSION_FREE_BITS == 0)
            .then_some(versions)
    }
}

/// A reserved frame whose whole payload was retained: its type and length.
fn reserved_frame(event: &H3CapturedEvent) -> Option<(u64, u64)> {
    let H3CapturedEvent::Control {
        frame_type,
        length,
        element_id: None,
        value,
    } = event
    else {
        return None;
    };
    H3_FRAMES.ordinal(*frame_type)?;
    (value.len() as u64 == *length).then_some((*frame_type, *length))
}

fn version_information(bytes: &[u8]) -> Result<VersionInformation, ProfileDataError> {
    VersionInformation::read(true, bytes.len(), &mut &bytes[..])
        .map_err(|_error| ProfileDataError::Invalid("QUIC version information"))
}

fn is_version_information(id: u64) -> bool {
    TransportParameterId::from(id) == TransportParameterId::VersionInformation
}

/// Reserved identifiers seen across one profile's evidence.
#[derive(Default)]
pub(super) struct ReservedSurvey {
    parameters: Identifiers,
    frames: Identifiers,
    versions: Versions,
}

impl ReservedSurvey {
    pub(super) fn order(
        &mut self,
        capture: &OrderedProtocolCapture,
    ) -> Result<(), ProfileDataError> {
        match capture.namespace {
            OrderNamespace::QuicParameter => {
                self.parameters
                    .component(capture.fields.iter().filter_map(|field| {
                        let ProtocolValue::Literal(value) = &field.value else {
                            return None;
                        };
                        let payloads =
                            Payloads::of(TRANSPORT_PARAMETERS, field.id, value.len() as u64)?;
                        Some((field.id, payloads))
                    }));
                for field in &capture.fields {
                    if is_version_information(field.id)
                        && let ProtocolValue::Literal(bytes) = &field.value
                    {
                        let information = version_information(bytes)?;
                        let chosen = information.chosen();
                        self.versions.component(
                            information
                                .available()
                                .iter()
                                .copied()
                                .filter(|version| *version != chosen),
                        );
                    }
                }
            }
            OrderNamespace::QuicVersion => self.versions.component(
                capture
                    .fields
                    .iter()
                    .filter_map(|field| u32::try_from(field.id).ok())
                    .map(Version::from_u32),
            ),
            OrderNamespace::Http3Setting => {}
        }
        Ok(())
    }

    pub(super) fn flight(&mut self, capture: &QuicFlightCapture) {
        let flight = &capture.flight;
        self.parameters.component(
            flight
                .parameters
                .iter()
                .map(|id| u64::from(*id))
                .filter(|id| TRANSPORT_PARAMETERS.ordinal(*id).is_some())
                .map(|id| (id, Payloads::UNSEEN)),
        );
        self.versions.component(
            flight
                .available_versions
                .iter()
                .copied()
                .filter(|version| Some(*version) != flight.chosen_version),
        );
    }

    pub(super) fn sequence(&mut self, capture: &H3ClientSequenceCapture) {
        self.frames
            .component(capture.events.iter().filter_map(reserved_frame).filter_map(
                |(frame_type, length)| {
                    Some((frame_type, Payloads::of(H3_FRAMES, frame_type, length)?))
                },
            ));
    }

    pub(super) fn slots(&self) -> ReservedSlots {
        ReservedSlots {
            parameters: self.parameters.generated(TRANSPORT_PARAMETERS),
            frames: self.frames.generated(H3_FRAMES),
            versions: self.versions.generated(),
        }
    }
}

struct Generated {
    ids: BTreeSet<u64>,
    length: ReservedLength,
    /// The longest payload among `ids`.
    longest: usize,
    slot_id: u64,
}

impl Generated {
    /// The payload a slot holds in place of one of `captured` bytes.
    fn payload(&self, captured: usize) -> Box<[u8]> {
        let length = match self.length {
            ReservedLength::Captured => captured,
            // The drawn identifier gives the length, so none is kept here.
            ReservedLength::Ordinal(_) => 0,
            ReservedLength::Ranged => self.longest,
        };
        vec![0; length].into()
    }
}

/// The identifiers of one profile that read as slots.
pub(super) struct ReservedSlots {
    parameters: Option<Generated>,
    frames: Option<Generated>,
    versions: Option<BTreeSet<u32>>,
}

impl ReservedSlots {
    pub(super) fn is_empty(&self) -> bool {
        self.parameters.is_none() && self.frames.is_none() && self.versions.is_none()
    }

    fn version(&self, version: Version) -> Option<Version> {
        self.versions
            .as_ref()
            .is_some_and(|versions| versions.contains(&version.as_u32()))
            .then_some(VERSION_SLOT)
    }

    /// The parameter slot, when exactly one of `ids` is generated: identifiers stay unique.
    fn parameter(&self, ids: impl Iterator<Item = u64>) -> Option<&Generated> {
        let generated = self.parameters.as_ref()?;
        (ids.filter(|id| generated.ids.contains(id)).count() == 1).then_some(generated)
    }

    pub(super) fn order(
        &self,
        capture: &mut OrderedProtocolCapture,
    ) -> Result<bool, ProfileDataError> {
        let mut changed = false;
        match capture.namespace {
            OrderNamespace::QuicParameter => {
                let parameter = self.parameter(capture.fields.iter().map(|field| field.id));
                for field in &mut capture.fields {
                    let ProtocolValue::Literal(bytes) = &mut field.value else {
                        continue;
                    };
                    if let Some(generated) = parameter
                        && generated.ids.contains(&field.id)
                    {
                        field.id = generated.slot_id;
                        *bytes = generated.payload(bytes.len());
                        changed = true;
                    } else if self.versions.is_some() && is_version_information(field.id) {
                        let information = version_information(bytes)?;
                        let chosen = information.chosen();
                        let mut slotted = false;
                        let available = information
                            .available()
                            .iter()
                            .map(|version| {
                                self.version(*version)
                                    .filter(|_slot| *version != chosen)
                                    .inspect(|_slot| slotted = true)
                                    .unwrap_or(*version)
                            })
                            .collect();
                        if slotted {
                            let mut read = Vec::with_capacity(bytes.len());
                            VersionInformation::new(chosen, available).write(&mut read);
                            *bytes = read.into();
                            changed = true;
                        }
                    }
                }
            }
            OrderNamespace::QuicVersion => {
                for field in &mut capture.fields {
                    if let Ok(version) = u32::try_from(field.id)
                        && let Some(slot) = self.version(Version::from_u32(version))
                    {
                        field.id = u64::from(slot.as_u32());
                        changed = true;
                    }
                }
            }
            OrderNamespace::Http3Setting => {}
        }
        Ok(changed)
    }

    pub(super) fn flight(&self, capture: &mut QuicFlightCapture) -> bool {
        let mut changed = false;
        let flight = &mut capture.flight;
        if let Some(generated) = self.parameter(flight.parameters.iter().map(|id| u64::from(*id))) {
            for id in &mut flight.parameters {
                if generated.ids.contains(&u64::from(*id)) {
                    *id = TransportParameterId::from(generated.slot_id);
                    changed = true;
                }
            }
        }
        for version in &mut flight.available_versions {
            if Some(*version) != flight.chosen_version
                && let Some(slot) = self.version(*version)
            {
                *version = slot;
                changed = true;
            }
        }
        changed
    }

    pub(super) fn sequence(&self, capture: &mut H3ClientSequenceCapture) -> bool {
        let Some(generated) = &self.frames else {
            return false;
        };
        let mut changed = false;
        for event in &mut capture.events {
            if !reserved_frame(event).is_some_and(|(id, _length)| generated.ids.contains(&id)) {
                continue;
            }
            let H3CapturedEvent::Control {
                frame_type,
                length,
                value,
                ..
            } = event
            else {
                continue;
            };
            *frame_type = generated.slot_id;
            *value = generated.payload(value.len());
            *length = value.len() as u64;
            changed = true;
        }
        changed
    }
}
