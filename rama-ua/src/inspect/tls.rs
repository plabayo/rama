use rama_tls::{client::ClientHello, server::ServerClientHellos};

use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CapturedSlot, CapturedSlotKind},
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
    use rama_tls::{
        CipherSuite, CompressionAlgorithm, ProtocolVersion,
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
