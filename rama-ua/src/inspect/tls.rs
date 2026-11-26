use rama_quic_proto::capture::{
    CaptureError, CaptureLimits, QuicObservation, transport_parameters_iter_from_hello,
};
use rama_tls::{client::ClientHello, server::ServerClientHellos};

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CapturedSlot, CapturedSlotKind},
        order::{OrderCaptureLimits, OrderNamespace, OrderedProtocolCapture},
        tls::{TlsCapture, TlsCaptureLimits, TlsCaptureTransport},
    },
    format::canonical::ProfileDataError,
};

/// Capture slots of one TLS connection: the effective hello, preceded by the
/// wire outer when ECH was accepted. `wire_complete` tells whether the wire
/// hello was captured whole (QUIC reassembly can exceed its budget).
///
/// Accepted ECH without its outer hello is an incomplete connection, reported
/// as [`ProfileDataError::Incomplete`] like every incomplete hello.
pub fn tls_connection_slots(
    hellos: &ServerClientHellos<'_>,
    transport: TlsCaptureTransport,
    wire_complete: bool,
    limits: TlsCaptureLimits,
) -> Result<Vec<CapturedSlot>, ProfileDataError> {
    let Some(effective) = hellos.effective() else {
        return Ok(Vec::new());
    };
    let mut slots = Vec::with_capacity(2);
    if hellos.ech_accepted() == Some(true) {
        let outer = hellos
            .wire()
            .ok_or(ProfileDataError::Incomplete("ECH outer ClientHello"))?;
        slots.push(slot(
            CapturedSlotKind::TlsOuter,
            outer,
            transport,
            wire_complete,
            limits,
        )?);
    }
    let kind = match transport {
        TlsCaptureTransport::Tcp => CapturedSlotKind::TcpTls,
        TlsCaptureTransport::Quic => CapturedSlotKind::QuicTls,
    };
    // A server reporting ECH status supplies the whole effective hello at
    // handshake completion, independent of the wire capture budget.
    let effective_complete = wire_complete || hellos.ech_accepted().is_some();
    slots.push(slot(
        kind,
        effective,
        transport,
        effective_complete,
        limits,
    )?);
    Ok(slots)
}

/// Append the effective QUIC parameter tuple and its distinct wire outer from one hello view.
pub fn append_quic_parameter_slots(
    slots: &mut Vec<CapturedSlot>,
    observed: &QuicObservation,
    hellos: &ServerClientHellos<'_>,
    limits: OrderCaptureLimits,
) -> Result<(), ProfileDataError> {
    let parameters = if let Some(inner) = hellos.ech_inner() {
        let reader = transport_parameters_iter_from_hello(inner, &CaptureLimits::default())
            .map_err(|error| inner_parameter_error(&error))?;
        OrderedProtocolCapture::try_capture(
            ProfileCaptureCompleteness::Complete,
            OrderNamespace::QuicParameter,
            reader.map(|parameter| {
                parameter
                    .map(|(id, body)| (u64::from(id), body))
                    .map_err(|error| inner_parameter_error(&error))
            }),
            limits,
        )?
    } else {
        wire_quic_parameters(observed, limits)?
    }
    .canonical(limits)?;
    if hellos.ech_inner().is_some() {
        let outer = wire_quic_parameters(observed, limits)?.canonical(limits)?;
        if outer.bytes != parameters.bytes {
            slots.push(CapturedSlot {
                kind: CapturedSlotKind::QuicOuterParameters,
                value: outer,
            });
        }
    }
    slots.push(CapturedSlot {
        kind: CapturedSlotKind::QuicParameters,
        value: parameters,
    });
    Ok(())
}

fn inner_parameter_error(error: &CaptureError) -> ProfileDataError {
    match error {
        CaptureError::LimitExceeded(_) => {
            ProfileDataError::Incomplete("inner QUIC parameter budget")
        }
        _ => ProfileDataError::Invalid("inner QUIC parameters"),
    }
}

fn wire_quic_parameters(
    observed: &QuicObservation,
    limits: OrderCaptureLimits,
) -> Result<OrderedProtocolCapture, ProfileDataError> {
    OrderedProtocolCapture::capture(
        ProfileCaptureCompleteness::from_complete(observed.completeness.transport_parameters),
        OrderNamespace::QuicParameter,
        observed
            .transport_parameters
            .iter()
            .map(|parameter| (u64::from(parameter.id), parameter.value.as_slice())),
        limits,
    )
}

fn slot(
    kind: CapturedSlotKind,
    hello: &ClientHello,
    transport: TlsCaptureTransport,
    complete: bool,
    limits: TlsCaptureLimits,
) -> Result<CapturedSlot, ProfileDataError> {
    let capture = TlsCapture::capture(
        ProfileCaptureCompleteness::from_complete(complete),
        transport,
        hello,
        limits,
    )?;
    Ok(CapturedSlot {
        kind,
        value: capture.canonical(limits)?,
    })
}

#[cfg(test)]
mod tests {
    use rama_quic_proto::{VarInt, coding::Codec as _};
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ExtensionId, ProtocolVersion,
        client::ClientHelloExtension,
        server::{EchServerObservation, ServerEchAccepted},
    };

    use super::*;

    fn hello(suite: u16) -> ClientHello {
        ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::from(suite)],
            vec![CompressionAlgorithm::from(0)],
            vec![],
        )
    }

    fn captured_suite(slot: &CapturedSlot, limits: TlsCaptureLimits) -> u16 {
        TlsCapture::from_canonical(&slot.value, limits)
            .unwrap()
            .ciphers[0]
    }

    #[test]
    fn accepted_inner_over_capture_budget_is_incomplete_evidence() {
        let mut bytes = Vec::new();
        for id in 65536..=65792u64 {
            VarInt::from_u64(id).unwrap().encode(&mut bytes);
            bytes.push(0);
        }
        let inner = ClientHello::new(
            ProtocolVersion::TLSv1_2,
            vec![CipherSuite::from(4865)],
            vec![CompressionAlgorithm::from(0)],
            vec![ClientHelloExtension::Opaque {
                id: ExtensionId::QUIC_TRANSPORT_PARAMETERS,
                data: bytes,
            }],
        );
        let outer = EchServerObservation::new(hello(4865));
        let hellos = ServerClientHellos::new(
            Some(&inner),
            Some(ServerEchAccepted::new(true)),
            Some(&outer),
        );
        let error = append_quic_parameter_slots(
            &mut Vec::new(),
            &QuicObservation {
                connection_id: Vec::new(),
                attempt_id: Vec::new(),
                retry_parent: None,
                first_flight: None,
                transport_parameters: Vec::new(),
                client_hello_message: Vec::new(),
                completeness: Default::default(),
            },
            &hellos,
            OrderCaptureLimits::default(),
        )
        .unwrap_err();
        assert!(
            matches!(error, ProfileDataError::Incomplete(_)),
            "{error:?}"
        );
    }

    #[test]
    fn accepted_ech_yields_the_outer_and_effective_slots() {
        let limits = TlsCaptureLimits::default();
        let inner = hello(1);
        let outer = EchServerObservation::new(hello(2));
        let hellos = ServerClientHellos::new(
            Some(&inner),
            Some(ServerEchAccepted::new(true)),
            Some(&outer),
        );
        let slots = tls_connection_slots(&hellos, TlsCaptureTransport::Tcp, true, limits).unwrap();
        let kinds: Vec<_> = slots.iter().map(|slot| slot.kind).collect();
        assert_eq!(
            kinds,
            [CapturedSlotKind::TlsOuter, CapturedSlotKind::TcpTls]
        );
        assert_eq!(captured_suite(&slots[0], limits), 2);
        assert_eq!(captured_suite(&slots[1], limits), 1);
    }

    #[test]
    fn accepted_ech_without_outer_is_incomplete() {
        let inner = hello(1);
        let hellos =
            ServerClientHellos::new(Some(&inner), Some(ServerEchAccepted::new(true)), None);
        let error = tls_connection_slots(
            &hellos,
            TlsCaptureTransport::Quic,
            true,
            TlsCaptureLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, ProfileDataError::Incomplete(_)));
    }

    #[test]
    fn incomplete_wire_hello_is_rejected_unless_the_server_reported_the_effective_hello() {
        let limits = TlsCaptureLimits::default();
        let wire = hello(1);
        let unreported = ServerClientHellos::new(Some(&wire), None, None);
        let error = tls_connection_slots(&unreported, TlsCaptureTransport::Quic, false, limits)
            .unwrap_err();
        assert!(matches!(error, ProfileDataError::Incomplete(_)));

        let reported =
            ServerClientHellos::new(Some(&wire), Some(ServerEchAccepted::new(false)), None);
        let slots =
            tls_connection_slots(&reported, TlsCaptureTransport::Quic, false, limits).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].kind, CapturedSlotKind::QuicTls);

        let inner = hello(2);
        let outer = EchServerObservation::new(hello(3));
        let accepted = ServerClientHellos::new(
            Some(&inner),
            Some(ServerEchAccepted::new(true)),
            Some(&outer),
        );
        let error =
            tls_connection_slots(&accepted, TlsCaptureTransport::Quic, false, limits).unwrap_err();
        assert!(matches!(error, ProfileDataError::Incomplete(_)));
    }

    #[test]
    fn missing_effective_hello_yields_no_slots() {
        let outer = EchServerObservation::new(hello(2));
        let hellos =
            ServerClientHellos::new(None, Some(ServerEchAccepted::new(true)), Some(&outer));
        let slots = tls_connection_slots(
            &hellos,
            TlsCaptureTransport::Tcp,
            true,
            TlsCaptureLimits::default(),
        )
        .unwrap();
        assert!(slots.is_empty());
    }
}
