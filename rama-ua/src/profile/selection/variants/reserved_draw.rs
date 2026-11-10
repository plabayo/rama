//! Draw fresh reserved identifiers per connection where the profile holds a slot.

use std::num::NonZeroU64;

use rama_quic_proto::{
    Version, transport_parameters::TransportParameterId, version::VersionInformation,
};

use crate::profile::{
    capture::{
        http3::{H3CapturedEvent, H3ClientSequenceCapture, H3SequenceCaptureLimits},
        joint::{CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProtocolValue},
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
        reserved::{
            H3_FRAMES, ReservedFamily, ReservedLength, ReservedSlot, TRANSPORT_PARAMETERS,
            VERSION_SLOT, reserved_version,
        },
    },
    format::canonical::{CanonicalValue, ProfileDataError},
    selection::{ProfileDraw, ProfileDrawContext, ProfileSeed},
};

const PARAMETER: u64 = 1;
const VERSION: u64 = 2;
const FRAME: u64 = 3;

/// One independent draw per slot, so every component of a connection that
/// names the same slot receives the same identifier.
#[derive(Clone, Copy)]
pub(super) struct ReservedDraws {
    pub(super) seed: ProfileSeed,
    /// Its `slot` is replaced per draw.
    pub(super) context: ProfileDrawContext,
}

/// A fresh payload for a drawn identifier, in place of the `held` bytes of its slot.
fn payload(draw: &mut ProfileDraw, slot: ReservedSlot, ordinal: u64, held: usize) -> Box<[u8]> {
    let length = match slot.length {
        ReservedLength::Captured => held,
        ReservedLength::Ordinal(bits) => (ordinal & ((1 << bits) - 1)) as usize,
        ReservedLength::Ranged => {
            NonZeroU64::new(held as u64 + 1).map_or(held, |lengths| draw.index(lengths) as usize)
        }
    };
    (0..length).map(|_index| draw.next_u64() as u8).collect()
}

impl ReservedDraws {
    fn draw(self, kind: u64, occurrence: u64) -> ProfileDraw {
        ProfileDraw::new(
            self.seed,
            ProfileDrawContext {
                slot: kind << 32 | occurrence,
                ..self.context
            },
        )
    }

    fn identifier(
        self,
        kind: u64,
        occurrence: u64,
        family: ReservedFamily,
        slot: ReservedSlot,
    ) -> (ProfileDraw, u64, u64) {
        let mut draw = self.draw(kind, occurrence);
        loop {
            // The largest range reaches past the family's last identifier.
            if let Some((id, ordinal)) = family.draw(slot, draw.next_u64()) {
                return (draw, id, ordinal);
            }
        }
    }

    fn version(self, occurrence: &mut u64) -> Version {
        let version = reserved_version(self.draw(VERSION, *occurrence).next_u64() as u16);
        *occurrence += 1;
        version
    }

    fn order(self, capture: &mut OrderedProtocolCapture) -> Result<bool, ProfileDataError> {
        let mut changed = false;
        let (mut parameters, mut versions) = (0, 0);
        match capture.namespace {
            OrderNamespace::QuicParameter => {
                for field in &mut capture.fields {
                    let ProtocolValue::Literal(value) = &mut field.value else {
                        continue;
                    };
                    if let Some(slot) = TRANSPORT_PARAMETERS.slot(field.id) {
                        let (mut draw, id, ordinal) =
                            self.identifier(PARAMETER, parameters, TRANSPORT_PARAMETERS, slot);
                        parameters += 1;
                        field.id = id;
                        *value = payload(&mut draw, slot, ordinal, value.len());
                        changed = true;
                    } else if TransportParameterId::from(field.id)
                        == TransportParameterId::VersionInformation
                    {
                        let information =
                            VersionInformation::read(true, value.len(), &mut &value[..]).map_err(
                                |_error| ProfileDataError::Invalid("QUIC version information"),
                            )?;
                        let chosen = information.chosen();
                        if !information.available().contains(&VERSION_SLOT) {
                            continue;
                        }
                        let available = information
                            .available()
                            .iter()
                            .map(|version| {
                                if *version == VERSION_SLOT && *version != chosen {
                                    self.version(&mut versions)
                                } else {
                                    *version
                                }
                            })
                            .collect();
                        let mut drawn = Vec::with_capacity(value.len());
                        VersionInformation::new(chosen, available).write(&mut drawn);
                        *value = drawn.into();
                        changed = true;
                    }
                }
            }
            OrderNamespace::QuicVersion => {
                for field in &mut capture.fields {
                    if field.id == u64::from(VERSION_SLOT.as_u32()) {
                        field.id = u64::from(self.version(&mut versions).as_u32());
                        changed = true;
                    }
                }
            }
            OrderNamespace::Http3Setting => {}
        }
        Ok(changed)
    }

    fn flight(self, capture: &mut QuicFlightCapture) -> bool {
        let mut changed = false;
        let (mut parameters, mut versions) = (0, 0);
        let flight = &mut capture.flight;
        for id in &mut flight.parameters {
            if let Some(slot) = TRANSPORT_PARAMETERS.slot(u64::from(*id)) {
                let (_draw, drawn, _ordinal) =
                    self.identifier(PARAMETER, parameters, TRANSPORT_PARAMETERS, slot);
                parameters += 1;
                *id = TransportParameterId::from(drawn);
                changed = true;
            }
        }
        for version in &mut flight.available_versions {
            if *version == VERSION_SLOT && Some(*version) != flight.chosen_version {
                *version = self.version(&mut versions);
                changed = true;
            }
        }
        changed
    }

    fn sequence(self, capture: &mut H3ClientSequenceCapture) -> bool {
        let mut frames = 0;
        for event in &mut capture.events {
            let H3CapturedEvent::Control {
                frame_type,
                length,
                element_id: None,
                value,
            } = event
            else {
                continue;
            };
            let Some(slot) = H3_FRAMES.slot(*frame_type) else {
                continue;
            };
            if value.len() as u64 != *length {
                continue;
            }
            let (mut draw, id, ordinal) = self.identifier(FRAME, frames, H3_FRAMES, slot);
            frames += 1;
            *frame_type = id;
            *value = payload(&mut draw, slot, ordinal, value.len());
            *length = value.len() as u64;
        }
        frames != 0
    }
}

/// The selected capture with every reserved slot replaced by a drawn identifier.
pub(super) fn draw_reserved(
    capture: CanonicalValue,
    draws: ReservedDraws,
) -> Result<CanonicalValue, ProfileDataError> {
    let limits = JointCaptureLimits::default();
    let mut joint = JointCapture::from_canonical(&capture, limits)?;
    let mut changed = false;
    for slot in &mut joint.slots {
        let drawn = match slot.kind {
            CapturedSlotKind::QuicParameters | CapturedSlotKind::QuicVersions => {
                let limits = OrderCaptureLimits::default();
                let mut order = OrderedProtocolCapture::from_canonical(&slot.value, limits)?;
                draws.order(&mut order)?.then(|| order.canonical(limits))
            }
            CapturedSlotKind::QuicFirstFlight => {
                let limits = QuicFlightCaptureLimits::default();
                let mut flight = QuicFlightCapture::from_canonical(&slot.value, limits)?;
                draws.flight(&mut flight).then(|| flight.canonical(limits))
            }
            CapturedSlotKind::Http3Sequence => {
                let limits = H3SequenceCaptureLimits::default();
                let mut sequence = H3ClientSequenceCapture::from_canonical(&slot.value, limits)?;
                draws
                    .sequence(&mut sequence)
                    .then(|| sequence.canonical(limits))
            }
            _ => None,
        };
        if let Some(drawn) = drawn {
            slot.value = drawn?;
            changed = true;
        }
    }
    if changed {
        joint.canonical(limits)
    } else {
        Ok(capture)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use rama_quic_proto::{
        capture::{FirstFlight, ObservedFrame},
        profile::PaddingPlacement,
    };
    use rama_utils::octets::kib;

    use super::*;
    use crate::profile::{
        analysis::profile::{
            AnalyzedProfile, AnalyzedProfileScope, ProfileAnalysisLimits, analyze_profile_evidence,
            normalize_profile_evidence,
        },
        capture::{
            CAPTURE_REVISION,
            completeness::ProfileCaptureCompleteness,
            joint::{CaptureLevel, CapturedSlot},
            observation::ProfileCapture,
            order::OrderedProtocolField,
        },
        evidence::{
            ProfileEvidence, ProfileScopeEvidence,
            ingestion::ObservationId,
            window::{ProfileWindowLimits, RetainedBucketWindow},
        },
        format::canonical::{CanonicalDomain, ValueId},
        model::identity::{ConnectionContext, ProfileKey},
        selection::{DrawDomain, DrawKey},
    };

    const INITIAL_MAX_DATA: u64 = 4;
    const VERSION_INFORMATION: u64 = 0x11;
    const SETTINGS: u64 = 4;

    /// What one connection generated: a transport parameter, a version and a frame.
    #[derive(Clone, Copy)]
    struct Generated {
        parameter: u64,
        parameter_length: usize,
        version: Version,
        frame: u64,
    }

    fn mix(index: u64) -> u64 {
        let mut value = index.wrapping_add(1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    /// A client drawing parameters over 57 bits with any length up to 15, and
    /// frames over 32 bits with the length in their low bits.
    fn generated(connection: u64) -> Generated {
        Generated {
            parameter: TRANSPORT_PARAMETERS.id(mix(connection) >> 7).unwrap(),
            parameter_length: (connection % 16) as usize,
            version: reserved_version(mix(connection + 2000) as u16),
            frame: H3_FRAMES.id(mix(connection + 3000) >> 32).unwrap(),
        }
    }

    fn literal(id: u64, value: Vec<u8>) -> OrderedProtocolField {
        OrderedProtocolField {
            id,
            value: ProtocolValue::Literal(value.into()),
        }
    }

    fn order(
        kind: CapturedSlotKind,
        namespace: OrderNamespace,
        fields: Vec<OrderedProtocolField>,
    ) -> CapturedSlot {
        CapturedSlot {
            kind,
            value: OrderedProtocolCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                namespace,
                fields: fields.into(),
            }
            .canonical(OrderCaptureLimits::default())
            .unwrap(),
        }
    }

    fn connection(generated: Generated) -> Vec<CapturedSlot> {
        let available = vec![generated.version, Version::V1];
        let mut information = Vec::new();
        VersionInformation::new(Version::V1, available.clone()).write(&mut information);
        let frame_length = H3_FRAMES.ordinal(generated.frame).unwrap() % 4;
        vec![
            order(
                CapturedSlotKind::QuicParameters,
                OrderNamespace::QuicParameter,
                vec![
                    literal(INITIAL_MAX_DATA, vec![1]),
                    literal(VERSION_INFORMATION, information),
                    literal(generated.parameter, vec![0xab; generated.parameter_length]),
                ],
            ),
            order(
                CapturedSlotKind::QuicVersions,
                OrderNamespace::QuicVersion,
                available
                    .iter()
                    .map(|version| literal(u64::from(version.as_u32()), Vec::new()))
                    .collect(),
            ),
            CapturedSlot {
                kind: CapturedSlotKind::QuicFirstFlight,
                value: QuicFlightCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    flight: FirstFlight {
                        datagram_sizes: vec![1200],
                        trailing_bytes: vec![0],
                        version: Version::V1,
                        dcid_len: 8,
                        scid_len: 0,
                        token_len: 0,
                        first_packet_number: 1,
                        packet_number_len: 2,
                        packet_number_lengths: vec![2],
                        frames: vec![vec![
                            ObservedFrame::Crypto {
                                offset: 0,
                                len: 100,
                            },
                            ObservedFrame::Padding { len: 1000 },
                        ]],
                        padding: PaddingPlacement::Frames,
                        coalesced: false,
                        parameters: [INITIAL_MAX_DATA, VERSION_INFORMATION, generated.parameter]
                            .map(TransportParameterId::from)
                            .to_vec(),
                        chosen_version: Some(Version::V1),
                        available_versions: available,
                        packet_numbers: vec![1],
                        complete: true,
                    },
                }
                .canonical(QuicFlightCaptureLimits::default())
                .unwrap(),
            },
            CapturedSlot {
                kind: CapturedSlotKind::Http3Sequence,
                value: H3ClientSequenceCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    local_settings: OrderedProtocolCapture {
                        completeness: ProfileCaptureCompleteness::Complete,
                        namespace: OrderNamespace::Http3Setting,
                        fields: Box::default(),
                    },
                    events: vec![
                        H3CapturedEvent::Stream {
                            stream_id: 2,
                            stream_type: 0,
                        },
                        H3CapturedEvent::Control {
                            frame_type: SETTINGS,
                            length: 0,
                            element_id: None,
                            value: Box::default(),
                        },
                        H3CapturedEvent::Control {
                            frame_type: generated.frame,
                            length: frame_length,
                            element_id: None,
                            value: vec![0xcd; frame_length as usize].into(),
                        },
                    ]
                    .into(),
                    encoder_instructions: Box::default(),
                }
                .canonical(H3SequenceCaptureLimits::default())
                .unwrap(),
            },
        ]
    }

    fn evidence(connections: impl IntoIterator<Item = Generated>) -> ProfileEvidence {
        let key = ProfileKey::new("generating-browser");
        let mut profile = None;
        let mut windows = BTreeMap::<ValueId, (ProfileScopeEvidence, RetainedBucketWindow)>::new();
        for (sequence, generated) in connections.into_iter().enumerate() {
            let prepared = ProfileCapture {
                revision: CAPTURE_REVISION,
                profile: key.clone(),
                flow: None,
                connection: ConnectionContext::default(),
                joint: JointCapture {
                    completeness: ProfileCaptureCompleteness::Complete,
                    level: CaptureLevel::Connection,
                    slots: connection(generated).into(),
                },
            }
            .prepare(false, JointCaptureLimits::default())
            .unwrap();
            profile = Some(prepared.profile);
            for input in prepared.buckets.into_vec() {
                let (_, window) = windows.entry(input.scope.id).or_insert_with(|| {
                    let window = RetainedBucketWindow::new(
                        input.value.validated_domain(kib(64)).unwrap(),
                        input.scope.id,
                        [3; 32],
                        ProfileWindowLimits::default(),
                    )
                    .unwrap();
                    let evidence = ProfileScopeEvidence {
                        scope: input.scope.clone(),
                        flow: None,
                        structure: input.structure.clone(),
                        window: window.snapshot(),
                    };
                    (evidence, window)
                });
                window
                    .observe(
                        100,
                        100,
                        ObservationId {
                            run: [1; 16],
                            sequence: sequence as u64 + 1,
                        },
                        &input.value,
                    )
                    .unwrap();
            }
        }
        ProfileEvidence {
            format_version: 1,
            profile: profile.unwrap(),
            scopes: windows
                .into_values()
                .map(|(mut evidence, window)| {
                    evidence.window = window.snapshot();
                    evidence
                })
                .collect(),
        }
    }

    fn analyzed(evidence: &ProfileEvidence) -> AnalyzedProfile {
        analyze_profile_evidence(
            evidence,
            false,
            [3; 32],
            100,
            14,
            ProfileAnalysisLimits::default(),
        )
        .unwrap()
    }

    fn connection_scope(profile: &AnalyzedProfile) -> &AnalyzedProfileScope {
        profile
            .scopes
            .iter()
            .find(|scope| {
                scope.context.flow.is_none() && scope.observations.domain == CanonicalDomain::Joint
            })
            .unwrap()
    }

    /// The identifiers and payloads one connection capture carries.
    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Carried {
        parameter: u64,
        parameter_value: Box<[u8]>,
        flight_parameter: u64,
        information_version: u32,
        order_version: u32,
        flight_version: u32,
        frame: u64,
        frame_length: u64,
        frame_value: Box<[u8]>,
    }

    fn carried(capture: &CanonicalValue) -> Carried {
        let joint = JointCapture::from_canonical(capture, JointCaptureLimits::default()).unwrap();
        let slot = |kind| {
            &joint
                .slots
                .iter()
                .find(|slot| slot.kind == kind)
                .unwrap()
                .value
        };
        let orders = |kind| {
            OrderedProtocolCapture::from_canonical(slot(kind), OrderCaptureLimits::default())
                .unwrap()
        };
        let parameters = orders(CapturedSlotKind::QuicParameters);
        let ProtocolValue::Literal(information) = &parameters.fields[1].value else {
            panic!("version information is a literal");
        };
        let information =
            VersionInformation::read(true, information.len(), &mut &information[..]).unwrap();
        let ProtocolValue::Literal(parameter_value) = &parameters.fields[2].value else {
            panic!("a reserved parameter is a literal");
        };
        let flight = QuicFlightCapture::from_canonical(
            slot(CapturedSlotKind::QuicFirstFlight),
            QuicFlightCaptureLimits::default(),
        )
        .unwrap()
        .flight;
        let sequence = H3ClientSequenceCapture::from_canonical(
            slot(CapturedSlotKind::Http3Sequence),
            H3SequenceCaptureLimits::default(),
        )
        .unwrap();
        let H3CapturedEvent::Control {
            frame_type,
            length,
            value,
            ..
        } = &sequence.events[2]
        else {
            panic!("the last event is the reserved frame");
        };
        Carried {
            parameter: parameters.fields[2].id,
            parameter_value: parameter_value.clone(),
            flight_parameter: u64::from(flight.parameters[2]),
            information_version: information.available()[0].as_u32(),
            order_version: orders(CapturedSlotKind::QuicVersions).fields[0].id as u32,
            flight_version: flight.available_versions[0].as_u32(),
            frame: *frame_type,
            frame_length: *length,
            frame_value: value.clone(),
        }
    }

    fn drawn(scope: &AnalyzedProfileScope, key: u8) -> Carried {
        let capture = scope.observations.variants[0]
            .value
            .canonical()
            .unwrap()
            .into_owned();
        let draws = ReservedDraws {
            seed: ProfileSeed([5; 32]),
            context: ProfileDrawContext {
                profile: ValueId([2; 32]),
                analysis_revision: 4,
                scope: scope.id,
                key: DrawKey([key; 32]),
                domain: DrawDomain::ReservedIdentifiers,
                slot: 0,
            },
        };
        carried(&draw_reserved(capture, draws).unwrap())
    }

    #[test]
    fn connections_differing_only_in_generated_identifiers_are_one_variant_drawn_afresh() {
        let profile = analyzed(&evidence((0..64).map(generated)));
        let scope = connection_scope(&profile);
        assert_eq!(scope.observations.variants.len(), 1);

        let mut seen = BTreeSet::new();
        for key in 0..64 {
            let connection = drawn(scope, key);
            assert_eq!(connection, drawn(scope, key));
            // Every component of a connection names the same generated identifiers.
            assert_eq!(connection.parameter, connection.flight_parameter);
            assert_eq!(connection.information_version, connection.order_version);
            assert_eq!(connection.information_version, connection.flight_version);
            assert!(Version::from_u32(connection.order_version).is_reserved());
            assert!(TRANSPORT_PARAMETERS.slot(connection.parameter).is_none());
            assert!(TRANSPORT_PARAMETERS.ordinal(connection.parameter).unwrap() < 1 << 57);
            let frame = H3_FRAMES.ordinal(connection.frame).unwrap();
            assert!(frame < 1 << 32, "{frame}");
            assert_eq!(connection.frame_length, frame % 4);
            assert_eq!(connection.frame_value.len() as u64, connection.frame_length);
            seen.insert(connection);
        }
        assert_eq!(seen.len(), 64);
        let lengths: BTreeSet<_> = seen
            .iter()
            .map(|connection| connection.frame_length)
            .collect();
        assert_eq!(lengths.len(), 4);
        let lengths: BTreeSet<_> = seen
            .iter()
            .map(|connection| connection.parameter_value.len())
            .collect();
        assert!(
            lengths.len() > 8 && *lengths.last().unwrap() <= 15,
            "{lengths:?}"
        );
        assert!(
            seen.iter()
                .any(|connection| { connection.parameter_value.iter().any(|byte| *byte != 0) })
        );
    }

    #[test]
    fn identifiers_a_client_keeps_constant_stay_as_captured() {
        let constant = generated(7);
        let profile = analyzed(&evidence((0..64).map(|connection| Generated {
            parameter: constant.parameter,
            parameter_length: 4,
            ..generated(connection)
        })));
        let scope = connection_scope(&profile);
        assert_eq!(scope.observations.variants.len(), 1);
        for key in 0..8 {
            let connection = drawn(scope, key);
            assert_eq!(connection.parameter, constant.parameter);
            assert_eq!(*connection.parameter_value, [0xab; 4]);
            assert_eq!(connection.flight_parameter, constant.parameter);
        }
    }

    #[test]
    fn too_few_connections_do_not_show_a_generated_identifier() {
        let connections: Vec<_> = (0..8).map(generated).collect();
        let profile = analyzed(&evidence(connections.iter().copied()));
        let scope = connection_scope(&profile);
        assert_eq!(scope.observations.variants.len(), 8);
        let captured: BTreeSet<_> = connections
            .iter()
            .map(|generated| generated.parameter)
            .collect();
        assert!(captured.contains(&drawn(scope, 1).parameter));
    }

    #[test]
    fn reading_a_read_profile_changes_nothing() {
        let read = |evidence: &ProfileEvidence| {
            normalize_profile_evidence(evidence, false, [3; 32], ProfileAnalysisLimits::default())
                .unwrap()
                .evidence
        };
        let values = |evidence: &ProfileEvidence| -> BTreeSet<ValueId> {
            evidence
                .scopes
                .iter()
                .flat_map(|scope| &scope.window.buckets)
                .flat_map(|day| &day.bucket.values)
                .map(|value| value.id)
                .collect()
        };
        let once = read(&evidence((0..64).map(generated)));
        assert_eq!(values(&once), values(&read(&once)));
    }
}
