//! Non-ECH offers derived from matched pairs without reusing their inner on the wire.

use std::{
    array::from_fn,
    mem,
    sync::{Arc, OnceLock},
};

use ahash::HashMap;
use rama_core::telemetry::tracing;
use rama_quic_proto::{
    VarInt,
    coding::Codec as _,
    profile::{ConnectionIdProfile, TransportLimits},
    transport_parameters::TransportParameterId,
};
use rama_tls::ExtensionId;

use super::{extension_order, shapes::OfferShape};
use crate::profile::{
    analysis::{
        capture::CaptureOrderPath,
        order::{DerivedOrderRule, PinnedOrderElement},
        profile::AnalyzedProfile,
    },
    capture::{
        joint::{CapturedSlot, CapturedSlotKind, JointCapture, JointCaptureLimits},
        order::{OrderCaptureLimits, OrderedProtocolCapture, OrderedProtocolField, ProtocolValue},
        quic::{QuicFlightCapture, QuicFlightCaptureLimits},
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport, TlsCapturedExtensionValue},
    },
    format::canonical::{CanonicalDomain, ProfileDataError, ValueId},
};

#[derive(Debug, Default, Clone)]
pub(crate) struct DatabaseEvidence {
    sources: Vec<Arc<AnalyzedProfile>>,
    families: OnceLock<HashMap<Box<str>, FamilyIndex>>,
}

#[derive(Debug, Default, Clone)]
struct FamilyIndex {
    sources: Vec<Arc<AnalyzedProfile>>,
    decoded: OnceLock<Box<[VersionEvidence]>>,
}

#[derive(Debug, Clone)]
struct VersionEvidence {
    id: ValueId,
    version: Option<Box<str>>,
    ordinary: OrdinaryEvidence,
}

pub(crate) struct FamilyEvidence<'a> {
    version: Option<&'a str>,
    profiles: &'a [VersionEvidence],
}

impl<'a> FamilyEvidence<'a> {
    fn find(
        &self,
        transport: TlsCaptureTransport,
        matches: impl Fn(&OrdinaryOffer) -> bool,
    ) -> Option<&'a OrdinaryOffer> {
        self.profiles
            .iter()
            .filter_map(|profile| {
                profile
                    .ordinary
                    .offers
                    .iter()
                    .find(|offer| offer.transport == transport && matches(offer))
                    .map(|offer| (profile, offer))
            })
            .min_by_key(|(profile, _)| {
                (
                    version_distance(self.version, profile.version.as_deref()),
                    profile.id,
                )
            })
            .map(|(_, offer)| offer)
    }
}

impl DatabaseEvidence {
    pub(crate) fn insert(&mut self, analysis: Arc<AnalyzedProfile>) {
        self.sources.push(analysis);
        self.families.take();
    }

    pub(crate) fn family_evidence(&self, profile: ValueId) -> FamilyEvidence<'_> {
        let Some(source) = self.sources.iter().find(|source| source.id == profile) else {
            return FamilyEvidence {
                version: None,
                profiles: &[],
            };
        };
        let families = self.families.get_or_init(|| {
            let mut families = HashMap::<Box<str>, FamilyIndex>::default();
            for source in &self.sources {
                families
                    .entry(source.key.client.clone())
                    .or_default()
                    .sources
                    .push(source.clone());
            }
            families
        });
        let profiles = families
            .get(&source.key.client)
            .map(|family| {
                family
                    .decoded
                    .get_or_init(|| {
                        family
                            .sources
                            .iter()
                            .map(|source| VersionEvidence {
                                id: source.id,
                                version: source.key.version.clone(),
                                ordinary: OrdinaryEvidence::of(source),
                            })
                            .collect()
                    })
                    .as_ref()
            })
            .unwrap_or(&[]);
        FamilyEvidence {
            version: source.key.version.as_deref(),
            profiles,
        }
    }
}

fn version_distance(left: Option<&str>, right: Option<&str>) -> (bool, [u64; 16]) {
    let parse = |version: Option<&str>| {
        let mut parts = [0; 16];
        for (index, part) in version?.split('.').enumerate() {
            *parts.get_mut(index)? = part.parse::<u64>().ok()?;
        }
        Some(parts)
    };
    match (parse(left), parse(right)) {
        (Some(left), Some(right)) => (false, from_fn(|i| left[i].abs_diff(right[i]))),
        _ => (left != right, [u64::MAX; 16]),
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct OrdinaryEvidence {
    offers: Vec<OrdinaryOffer>,
}

#[derive(Debug, Clone)]
struct OrdinaryOffer {
    transport: TlsCaptureTransport,
    ech: Option<TlsCapturedExtensionValue>,
    extension_order: Box<[u16]>,
    shape: OfferShape,
    pinned: Option<Box<[PinnedOrderElement]>>,
    parameters_len: Option<TlsCapturedExtensionValue>,
    transport_slots: Box<[CapturedSlot]>,
    flight_version: Option<(u32, bool)>,
}

impl OrdinaryEvidence {
    pub(crate) fn of(analysis: &AnalyzedProfile) -> Self {
        let mut evidence = Self::default();
        for scope in analysis.scopes.iter().filter(|scope| {
            scope.context.flow.is_none() && scope.observations.domain == CanonicalDomain::Joint
        }) {
            for variant in scope.observations.variants.iter() {
                let decode = || -> Result<_, ProfileDataError> {
                    let value = variant.value.canonical()?;
                    let joint =
                        JointCapture::from_canonical(&value, JointCaptureLimits::default())?;
                    let tls = joint
                        .effective_tls_slot()
                        .map(|slot| TlsCapture::from_canonical(&slot.value, tls_limits()))
                        .transpose()?;
                    Ok((joint, tls))
                };
                let Ok((joint, Some(tls))) = decode() else {
                    continue;
                };
                if joint.ech_outer_slot().is_some()
                    || tls.extensions.iter().any(|extension| {
                        matches!(extension.value, TlsCapturedExtensionValue::EchInner)
                    })
                {
                    continue;
                }
                let Ok(tls) = tls.with_grease_placeholders() else {
                    continue;
                };
                evidence.offers.push(OrdinaryOffer {
                    transport: tls.transport,
                    ech: tls.extensions.iter().find_map(|extension| {
                        matches!(extension.value, TlsCapturedExtensionValue::EchOuter { .. })
                            .then(|| extension.value.clone())
                    }),
                    extension_order: tls
                        .extensions
                        .iter()
                        .map(|extension| extension.id)
                        .collect(),
                    shape: OfferShape::of(&tls),
                    pinned: scope
                        .observations
                        .orders
                        .iter()
                        .find(|order| order.path == CaptureOrderPath::TlsExtensions)
                        .and_then(|order| match &order.evidence.derived {
                            Some(DerivedOrderRule::Shuffled { pinned, .. }) => Some(pinned.clone()),
                            _ => None,
                        }),
                    parameters_len: parameter_shape(&tls).cloned(),
                    flight_version: joint
                        .slots
                        .iter()
                        .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight)
                        .and_then(|slot| {
                            QuicFlightCapture::from_canonical(
                                &slot.value,
                                QuicFlightCaptureLimits::default(),
                            )
                            .ok()
                        })
                        .map(|capture| {
                            (
                                capture.flight.version.as_u32(),
                                capture.flight.chosen_version.is_some(),
                            )
                        }),
                    transport_slots: joint
                        .slots
                        .into_iter()
                        .filter(|slot| transport_slot(slot.kind))
                        .collect(),
                });
            }
        }
        evidence
    }
}

fn tls_limits() -> TlsCaptureLimits {
    TlsCaptureLimits::uniform(JointCaptureLimits::default().value_bytes)
}

fn transport_slot(kind: CapturedSlotKind) -> bool {
    matches!(
        kind,
        CapturedSlotKind::QuicParameters
            | CapturedSlotKind::QuicOuterParameters
            | CapturedSlotKind::QuicVersions
            | CapturedSlotKind::QuicFirstFlight
    )
}

fn parameter_shape(tls: &TlsCapture) -> Option<&TlsCapturedExtensionValue> {
    tls.extensions
        .iter()
        .find(|extension| extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS))
        .map(|extension| &extension.value)
}

fn complete_outer_parameters(
    joint: &mut JointCapture,
    outer: &mut TlsCapture,
) -> Result<bool, ProfileDataError> {
    let Some(slot) = joint
        .slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::QuicOuterParameters)
        .or_else(|| {
            joint
                .slots
                .iter()
                .find(|slot| slot.kind == CapturedSlotKind::QuicParameters)
        })
    else {
        return Ok(false);
    };
    let original = slot.value.clone();
    let mut parameters =
        OrderedProtocolCapture::from_canonical(&slot.value, OrderCaptureLimits::default())?;
    let mut fields = parameters.fields.into_vec();
    let limits = TransportLimits::standard();
    let mut changed = false;
    for (id, value) in [
        (
            TransportParameterId::InitialMaxData,
            limits.initial_max_data,
        ),
        (
            TransportParameterId::InitialMaxStreamDataBidiLocal,
            limits.initial_max_stream_data_bidi_local,
        ),
        (
            TransportParameterId::InitialMaxStreamDataBidiRemote,
            limits.initial_max_stream_data_bidi_remote,
        ),
        (
            TransportParameterId::InitialMaxStreamDataUni,
            limits.initial_max_stream_data_uni,
        ),
        (
            TransportParameterId::InitialMaxStreamsBidi,
            limits.initial_max_streams_bidi,
        ),
        (
            TransportParameterId::InitialMaxStreamsUni,
            limits.initial_max_streams_uni,
        ),
    ] {
        if fields.iter().any(|field| field.id == u64::from(id)) {
            continue;
        }
        let mut bytes = Vec::new();
        VarInt::from_u64(value)
            .map_err(|_error| ProfileDataError::Invalid("native QUIC limit"))?
            .encode(&mut bytes);
        fields.push(OrderedProtocolField {
            id: id.into(),
            value: ProtocolValue::Literal(bytes.into()),
        });
        changed = true;
    }
    if !fields
        .iter()
        .any(|field| field.id == u64::from(TransportParameterId::InitialSourceConnectionId))
    {
        fields.push(OrderedProtocolField {
            id: TransportParameterId::InitialSourceConnectionId.into(),
            value: ProtocolValue::ConnectionLength(
                joint
                    .slots
                    .iter()
                    .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight)
                    .map(|slot| {
                        QuicFlightCapture::from_canonical(
                            &slot.value,
                            QuicFlightCaptureLimits::default(),
                        )
                    })
                    .transpose()?
                    .map_or(
                        usize::from(ConnectionIdProfile::standard().local_len()),
                        |capture| capture.flight.scid_len,
                    ),
            ),
        });
        changed = true;
    }
    let mut length = 0;
    for field in &fields {
        let size = match &field.value {
            ProtocolValue::Literal(bytes) => bytes.len(),
            ProtocolValue::ConnectionLength(length) => *length,
        };
        let id = VarInt::from_u64(field.id)
            .map_err(|_error| ProfileDataError::Invalid("QUIC parameter id"))?;
        let encoded = VarInt::from_u64(size as u64)
            .map_err(|_error| ProfileDataError::Invalid("QUIC parameter length"))?;
        length += id.size() + encoded.size() + size;
    }
    let length = u16::try_from(length)
        .map_err(|_error| ProfileDataError::LimitExceeded("QUIC parameters"))?;
    let same_parameters = joint
        .slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::QuicParameters)
        .is_some_and(|slot| slot.value.bytes == original.bytes);
    if !changed
        && same_parameters
        && parameter_shape(outer) == Some(&TlsCapturedExtensionValue::ConnectionLength(length))
    {
        return Ok(false);
    }
    for extension in &mut outer.extensions {
        if extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS) {
            extension.value = TlsCapturedExtensionValue::ConnectionLength(length);
        }
    }
    parameters.fields = fields.into();
    let value = parameters.canonical(OrderCaptureLimits::default())?;
    let mut slots: Vec<_> = mem::take(&mut joint.slots)
        .into_vec()
        .into_iter()
        .filter(|slot| slot.kind != CapturedSlotKind::QuicParameters)
        .collect();
    if !slots
        .iter()
        .any(|slot| slot.kind == CapturedSlotKind::QuicOuterParameters)
    {
        slots.push(CapturedSlot {
            kind: CapturedSlotKind::QuicOuterParameters,
            value: original,
        });
    }
    slots.push(CapturedSlot {
        kind: CapturedSlotKind::QuicParameters,
        value,
    });
    joint.slots = slots.into();
    Ok(true)
}

pub(super) enum DerivedExtensionOrder {
    Captured,
    Shuffled(Box<[PinnedOrderElement]>),
}

pub(super) fn derive<'a>(
    joint: &mut JointCapture,
    own: &OrdinaryEvidence,
    family: impl Fn() -> FamilyEvidence<'a>,
) -> Result<Option<DerivedExtensionOrder>, ProfileDataError> {
    let Some(outer) = joint.ech_outer_slot() else {
        return Ok(None);
    };
    let mut outer = TlsCapture::from_canonical(&outer.value, tls_limits())?;
    let inner = joint
        .effective_tls_slot()
        .ok_or(ProfileDataError::Invalid("ECH pair without inner"))?;
    let inner = TlsCapture::from_canonical(&inner.value, tls_limits())?;
    let transport = outer.transport;
    let own_offers = || {
        own.offers
            .iter()
            .filter(|offer| offer.transport == transport)
    };
    let family_evidence = OnceLock::new();
    let family = || family_evidence.get_or_init(&family);
    let (ordinary, level) = if let Some(offer) = own_offers().next() {
        (Some(offer), "profile")
    } else if let Some(offer) = family().find(outer.transport, |_| true) {
        (Some(offer), "family")
    } else {
        (None, "outer")
    };
    let ech = ordinary.map(|offer| &offer.ech);
    let desired_parameters = parameter_shape(&inner);
    let flight_version = joint
        .slots
        .iter()
        .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight)
        .map(|slot| {
            QuicFlightCapture::from_canonical(&slot.value, QuicFlightCaptureLimits::default())
        })
        .transpose()?
        .map(|capture| {
            (
                capture.flight.version,
                capture.flight.chosen_version.is_some(),
            )
        });
    let has_parameters = |offer: &OrdinaryOffer| {
        let version_fits = flight_version.is_none_or(|(version, information)| {
            offer.flight_version == Some((version.as_u32(), information))
        });
        version_fits
            && offer.parameters_len.as_ref() == desired_parameters
            && offer
                .transport_slots
                .iter()
                .any(|slot| slot.kind == CapturedSlotKind::QuicParameters)
    };
    let (parameters, mut parameters_level) = if outer.transport == TlsCaptureTransport::Quic {
        if let Some(offer) = own_offers().find(|offer| has_parameters(offer)) {
            (Some(offer), "profile")
        } else if let Some(offer) = family().find(outer.transport, has_parameters) {
            (Some(offer), "family")
        } else {
            (None, "outer")
        }
    } else {
        (None, "none")
    };
    for extension in &mut outer.extensions {
        if extension.id == u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO) {
            if let Some(Some(ech)) = ech {
                extension.value = ech.clone();
            }
        } else if extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS) {
            // The wire tuple owns the length when no ordinary parameter contents survived.
            if parameters.is_some()
                && let Some(shape) = desired_parameters
            {
                extension.value = shape.clone();
            }
        }
    }
    if ech == Some(&None) {
        outer.extensions = mem::take(&mut outer.extensions)
            .into_vec()
            .into_iter()
            .filter(|extension| extension.id != u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO))
            .collect();
    }
    outer = outer.with_grease_placeholders()?;
    let shape = OfferShape::of(&outer);
    let matches_order = |offer: &OrdinaryOffer| offer.shape.same_contents(&shape);
    let order = own_offers()
        .find(|offer| matches_order(offer))
        .or_else(|| family().find(outer.transport, matches_order));
    if let Some(ordinary) = order {
        outer.extensions.sort_by_key(|extension| {
            ordinary
                .extension_order
                .iter()
                .position(|id| *id == extension.id)
                .unwrap_or(usize::MAX)
        });
        if let Some(pinned) = &ordinary.pinned {
            outer.extensions =
                extension_order::place_pinned(mem::take(&mut outer.extensions), pinned);
        }
    }
    if let Some(parameters) = parameters {
        let mut slots: Vec<_> = mem::take(&mut joint.slots)
            .into_vec()
            .into_iter()
            .filter(|slot| !transport_slot(slot.kind))
            .collect();
        slots.extend(parameters.transport_slots.iter().cloned());
        joint.slots = slots.into();
    }
    if parameters.is_none()
        && outer.transport == TlsCaptureTransport::Quic
        && (parameter_shape(&outer) != desired_parameters
            || joint
                .slots
                .iter()
                .any(|slot| slot.kind == CapturedSlotKind::QuicOuterParameters))
        && complete_outer_parameters(joint, &mut outer)?
    {
        parameters_level = "outer-with-native-limits";
    }
    let value = outer.canonical(tls_limits())?;
    if ech == Some(&None) {
        let kind = match outer.transport {
            TlsCaptureTransport::Tcp => CapturedSlotKind::TcpTls,
            TlsCaptureTransport::Quic => CapturedSlotKind::QuicTls,
        };
        for slot in &mut joint.slots {
            if slot.kind == kind {
                slot.value = value.clone();
            }
        }
        joint.slots = mem::take(&mut joint.slots)
            .into_vec()
            .into_iter()
            .filter(|slot| slot.kind != CapturedSlotKind::TlsOuter)
            .collect();
    } else if let Some(slot) = joint
        .slots
        .iter_mut()
        .find(|slot| slot.kind == CapturedSlotKind::TlsOuter)
    {
        slot.value = value;
    }
    tracing::debug!(
        ech_evidence = level,
        quic_evidence = parameters_level,
        "derived non-ECH connection offer"
    );
    Ok(order.map(|ordinary| match &ordinary.pinned {
        Some(pinned) => DerivedExtensionOrder::Shuffled(pinned.clone()),
        None => DerivedExtensionOrder::Captured,
    }))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "embed-profiles")]
    use std::ptr;

    use rama_quic_proto::{
        Version,
        capture::{FirstFlight, ObservedFrame},
        profile::PaddingPlacement,
    };

    use super::*;
    use crate::profile::capture::{
        completeness::ProfileCaptureCompleteness, joint::CaptureLevel, order::OrderNamespace,
        tls::TlsCapturedExtension,
    };
    #[cfg(feature = "embed-profiles")]
    use crate::profile::format::compiled::decode_compiled_profiles;

    #[test]
    fn reduced_outer_parameters_keep_captured_values_and_gain_native_flow_credit() {
        let hello = |inner| {
            TlsCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                transport: TlsCaptureTransport::Quic,
                protocol_version: 771,
                ciphers: Box::new([4865]),
                compression: Box::new([0]),
                extensions: Box::new([
                    TlsCapturedExtension {
                        id: u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS),
                        value: TlsCapturedExtensionValue::ConnectionLength(if inner {
                            128
                        } else {
                            16
                        }),
                    },
                    TlsCapturedExtension {
                        id: u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO),
                        value: if inner {
                            TlsCapturedExtensionValue::EchInner
                        } else {
                            TlsCapturedExtensionValue::EchOuter {
                                kdf: 1,
                                aead: 1,
                                enc: 32,
                                payload: 144,
                            }
                        },
                    },
                ]),
            }
            .canonical(tls_limits())
            .unwrap()
        };
        let captured = OrderedProtocolField {
            id: TransportParameterId::MaxAckDelay.into(),
            value: ProtocolValue::Literal(Box::new([23])),
        };
        let parameters = OrderedProtocolCapture {
            completeness: ProfileCaptureCompleteness::Complete,
            namespace: OrderNamespace::QuicParameter,
            fields: Box::new([captured.clone()]),
        }
        .canonical(OrderCaptureLimits::default())
        .unwrap();
        let flight = || CapturedSlot {
            kind: CapturedSlotKind::QuicFirstFlight,
            value: QuicFlightCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                flight: FirstFlight {
                    datagram_sizes: vec![1200],
                    trailing_bytes: vec![0],
                    version: Version::V2,
                    dcid_len: 8,
                    scid_len: 0,
                    token_len: 0,
                    first_packet_number: 0,
                    packet_number_len: 1,
                    packet_number_lengths: vec![1],
                    frames: vec![vec![ObservedFrame::Crypto {
                        offset: 0,
                        len: 100,
                    }]],
                    padding: PaddingPlacement::Frames,
                    coalesced: false,
                    parameters: vec![TransportParameterId::MaxAckDelay],
                    chosen_version: None,
                    available_versions: vec![],
                    packet_numbers: vec![0],
                    complete: true,
                },
            }
            .canonical(QuicFlightCaptureLimits::default())
            .unwrap(),
        };
        // A reduced capture without a first flight, and one carrying a QUIC v2 flight.
        for with_flight in [false, true] {
            let mut slots = vec![
                CapturedSlot {
                    kind: CapturedSlotKind::QuicTls,
                    value: hello(true),
                },
                CapturedSlot {
                    kind: CapturedSlotKind::TlsOuter,
                    value: hello(false),
                },
            ];
            if with_flight {
                slots.extend([
                    CapturedSlot {
                        kind: CapturedSlotKind::QuicParameters,
                        value: OrderedProtocolCapture {
                            completeness: ProfileCaptureCompleteness::Complete,
                            namespace: OrderNamespace::QuicParameter,
                            fields: Box::new([OrderedProtocolField {
                                id: TransportParameterId::MaxIdleTimeout.into(),
                                value: ProtocolValue::Literal(Box::new([37])),
                            }]),
                        }
                        .canonical(OrderCaptureLimits::default())
                        .unwrap(),
                    },
                    CapturedSlot {
                        kind: CapturedSlotKind::QuicOuterParameters,
                        value: parameters.clone(),
                    },
                    flight(),
                ]);
            } else {
                slots.push(CapturedSlot {
                    kind: CapturedSlotKind::QuicParameters,
                    value: parameters.clone(),
                });
            }
            let mut joint = JointCapture {
                completeness: ProfileCaptureCompleteness::Complete,
                level: CaptureLevel::Connection,
                slots: slots.into(),
            };
            let empty = OrdinaryEvidence::default();
            derive(&mut joint, &empty, || FamilyEvidence {
                version: None,
                profiles: &[],
            })
            .unwrap();
            let parameters = OrderedProtocolCapture::from_canonical(
                &joint
                    .slots
                    .iter()
                    .find(|slot| slot.kind == CapturedSlotKind::QuicParameters)
                    .unwrap()
                    .value,
                OrderCaptureLimits::default(),
            )
            .unwrap();
            assert!(parameters.fields.iter().all(|field| field.id
                != u64::from(TransportParameterId::MaxIdleTimeout)
                && field.id != u64::from(TransportParameterId::VersionInformation)));
            let flight = joint
                .slots
                .iter()
                .find(|slot| slot.kind == CapturedSlotKind::QuicFirstFlight);
            assert_eq!(flight.is_some(), with_flight);
            if let Some(flight) = flight {
                assert_eq!(
                    QuicFlightCapture::from_canonical(
                        &flight.value,
                        QuicFlightCaptureLimits::default()
                    )
                    .unwrap()
                    .flight
                    .version,
                    Version::V2
                );
            }
            assert_eq!(parameters.fields[0], captured);
            for id in [
                TransportParameterId::InitialMaxData,
                TransportParameterId::InitialMaxStreamsUni,
                TransportParameterId::InitialMaxStreamDataUni,
            ] {
                let field = parameters
                    .fields
                    .iter()
                    .find(|field| field.id == u64::from(id))
                    .unwrap();
                let ProtocolValue::Literal(value) = &field.value else {
                    panic!("flow credit must be literal")
                };
                assert!(VarInt::decode(&mut value.as_ref()).unwrap().into_inner() > 0);
            }
            let length: usize = parameters
                .fields
                .iter()
                .map(|field| {
                    let size = match &field.value {
                        ProtocolValue::Literal(value) => value.len(),
                        ProtocolValue::ConnectionLength(length) => *length,
                    };
                    VarInt::from_u64(field.id).unwrap().size()
                        + VarInt::from_u64(size as u64).unwrap().size()
                        + size
                })
                .sum();
            let outer =
                TlsCapture::from_canonical(&joint.ech_outer_slot().unwrap().value, tls_limits())
                    .unwrap();
            assert_eq!(
                parameter_shape(&outer),
                Some(&TlsCapturedExtensionValue::ConnectionLength(
                    u16::try_from(length).unwrap()
                ))
            );
            let mut reduced_shape = outer.clone();
            for extension in &mut reduced_shape.extensions {
                if extension.id == u16::from(ExtensionId::QUIC_TRANSPORT_PARAMETERS) {
                    extension.value = TlsCapturedExtensionValue::ConnectionLength(0);
                }
            }
            assert!(complete_outer_parameters(&mut joint, &mut reduced_shape).unwrap());
            assert_eq!(parameter_shape(&reduced_shape), parameter_shape(&outer));
            assert!(
                outer.extensions.iter().all(|extension| !matches!(
                    extension.value,
                    TlsCapturedExtensionValue::EchInner
                ))
            );
        }
    }

    #[cfg(feature = "embed-profiles")]
    #[test]
    fn family_evidence_decodes_each_offer_once_and_only_for_the_requested_family() {
        let profiles =
            decode_compiled_profiles(include_bytes!("../../../format/embed_profiles.bin")).unwrap();
        let source = &profiles[0];
        let mut database = DatabaseEvidence::default();
        for index in 0..16 {
            let mut profile = source.clone();
            profile.key.client = "family".into();
            profile.key.version = Some(index.to_string().into_boxed_str());
            profile.id = ValueId([index; 32]);
            database.insert(Arc::new(profile));
        }
        let mut unrelated = source.clone();
        unrelated.key.client = "unrelated".into();
        unrelated.id = ValueId([99; 32]);
        database.insert(Arc::new(unrelated));
        assert!(database.families.get().is_none());
        let first = database.family_evidence(ValueId([0; 32]));
        let next = database.family_evidence(ValueId([15; 32]));
        assert!(ptr::eq(first.profiles, next.profiles));
        let families = database.families.get().unwrap();
        assert!(families.get("unrelated").unwrap().decoded.get().is_none());
        assert_eq!(first.profiles.len(), 16);
        let per_profile = OrdinaryEvidence::of(source).offers.len();
        assert!(per_profile > 0);
        assert_eq!(
            first
                .profiles
                .iter()
                .map(|profile| profile.ordinary.offers.len())
                .sum::<usize>(),
            16 * per_profile
        );
    }
}
