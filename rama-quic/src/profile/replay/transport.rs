//! Compile a retained parameter tuple using the engine's typed profile builders.

use super::parameters::ParameterExpectation;
use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_quic_proto::{
    capture::version_information,
    profile::{
        ConnectionIdProfile, InitialFlightLayout, PacketizationProfile, ParameterOrder,
        QuicProfile, TransportLimits, TransportParameterProfile, initial::RecordedInitialFlight,
    },
    transport_parameters::{RawParameter, TransportParameterId},
    version::{
        ClientVersionPolicy, ReservedQuicVersion, ReservedVersionGrease, VersionInformation,
    },
};
use rama_ua::profile::capture::{
    order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture, ProtocolValue},
    quic::QuicFlightCapture,
};

pub(super) fn prepare(
    parameters: OrderedProtocolCapture,
    versions: Option<&OrderedProtocolCapture>,
    flight: Option<&QuicFlightCapture>,
) -> Result<(QuicProfile, ParameterExpectation), BoxError> {
    let expectation = ParameterExpectation::try_from(parameters)?;
    let parameters = expectation.capture();
    let mut literals = Vec::with_capacity(parameters.fields.len());
    let mut order = Vec::with_capacity(parameters.fields.len());
    let mut local_cid_len = None;
    for field in &parameters.fields {
        let id = TransportParameterId::from(field.id);
        order.push(id);
        match &field.value {
            ProtocolValue::Literal(value) => literals.push(RawParameter {
                id,
                value: value.to_vec(),
            }),
            ProtocolValue::ConnectionLength(length)
                if id == TransportParameterId::InitialSourceConnectionId =>
            {
                local_cid_len = Some(u8::try_from(*length).map_err(|_error| {
                    BoxError::from_static_str("captured QUIC source CID is too long")
                })?);
            }
            ProtocolValue::ConnectionLength(_) => {
                return Err(BoxError::from_static_str(
                    "captured QUIC parameter binding is not implemented",
                ));
            }
        }
    }
    // Never invent connection identifiers to pass through the raw-value adapter.
    // Its parser reads literals; the engine regenerates the omitted bindings.
    let information = version_information(&literals).ok_or_else(|| {
        BoxError::from_static_str("captured QUIC replay currently requires version_information")
    })?;
    let version_policy = version_policy(&information)?;
    let local_cid_len = local_cid_len.ok_or_else(|| {
        BoxError::from_static_str("captured QUIC parameters omit the source CID binding")
    })?;
    let mut ids = ConnectionIdProfile::standard().try_with_local_len(local_cid_len)?;
    if let Some(flight) = flight {
        if flight.flight.version != information.chosen()
            || flight.flight.chosen_version != Some(information.chosen())
            || flight.flight.available_versions != information.available()
            || flight.flight.parameters != order
            || flight.flight.scid_len != usize::from(local_cid_len)
        {
            return Err(BoxError::from_static_str(
                "captured QUIC flight and parameter tuple disagree",
            ));
        }
        ids =
            ids.try_with_initial_destination_len(u8::try_from(flight.flight.dcid_len).map_err(
                |_error| BoxError::from_static_str("captured QUIC destination CID is too long"),
            )?)?;
    }
    if let Some(versions) = versions {
        versions.canonical(OrderCaptureLimits::default())?;
        if !matches!(versions.namespace, OrderNamespace::QuicVersion)
            || !versions.fields.iter().map(|field| field.id).eq(information
                .available()
                .iter()
                .map(|version| u64::from(version.as_u32())))
        {
            return Err(BoxError::from_static_str(
                "captured QUIC version list and parameter tuple disagree",
            ));
        }
    }
    let layout = TransportParameterProfile::try_from_sent(&literals)?
        .try_with_order(ParameterOrder::fixed_with_explicit_defaults(order))?;
    let limits = TransportLimits::try_from_sent(&literals)?;
    let mut profile = QuicProfile::standard()
        .with_versions(version_policy)
        .with_transport_parameters(layout)
        .with_connection_ids(ids)
        .with_grease_quic_bit(
            literals
                .iter()
                .any(|parameter| parameter.id == TransportParameterId::GreaseQuicBit),
        )
        .try_with_limits(limits)?;
    if let Some(flight) = flight {
        let layout = RecordedInitialFlight::try_from(&flight.flight)?;
        profile = profile.with_packetization(
            PacketizationProfile::standard().with_layout(InitialFlightLayout::Recorded(layout)),
        );
    }
    Ok((profile, expectation))
}

fn version_policy(information: &VersionInformation) -> Result<ClientVersionPolicy, BoxError> {
    let mut real = Vec::with_capacity(information.available().len());
    let mut reserved = None;
    for (index, &version) in information.available().iter().enumerate() {
        if version.is_reserved() {
            if reserved.is_some() {
                return Err(BoxError::from_static_str(
                    "multiple captured reserved QUIC versions are not implemented",
                ));
            }
            let literal = ReservedQuicVersion::try_from(version)?;
            reserved = Some(if index == 0 {
                ReservedVersionGrease::FixedFirst(literal)
            } else if index + 1 == information.available().len() {
                ReservedVersionGrease::FixedLast(literal)
            } else {
                return Err(BoxError::from_static_str(
                    "interior captured reserved QUIC versions are not implemented",
                ));
            });
        } else {
            real.push(version);
        }
    }
    // The capture describes the compatible offer, not a restart policy. Keep
    // the observed first version pinned when a peer sends Version Negotiation.
    Ok(ClientVersionPolicy::new(information.chosen())?
        .try_with_compatible(real)?
        .with_reserved_version_grease(reserved.unwrap_or(ReservedVersionGrease::None)))
}
