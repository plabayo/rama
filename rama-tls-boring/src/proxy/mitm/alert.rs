//! Plaintext TLS Alert primitives, scoped to the MITM relay.
//!
//! BoringSSL's `SSL_send_fatal_alert` requires a connected `SSL*` —
//! an object that has a BIO attached and has already begun its
//! handshake state machine. In the MITM relay we hit a window where
//! the *egress* handshake has already failed but the *ingress* SSL
//! object does not yet exist (we deliberately wait for the upstream
//! to negotiate so we can mirror its version / ALPN / cert hints
//! into the ingress acceptor before starting it). At that point our
//! wire to the client is plain TCP with the client's ClientHello
//! buffered.
//!
//! The TLS record format for an Alert in this position is RFC-stable
//! (RFC 5246 §6.2.1 / RFC 8446 §6.2 + §5.1) and 7 bytes. Emitting it
//! by hand is the simplest correct thing — building a placeholder
//! `SslAcceptor`, attaching a throwaway cert, starting the
//! state machine just to call `SSL_send_fatal_alert`, then throwing
//! it all away would be strictly more code AND would commit us to a
//! TLS version / cipher before learning what the upstream
//! negotiated. Neither rustls nor openssl-Rust expose a "write an
//! alert into a raw stream" helper — it's a genuine ecosystem gap.
//!
//! Kept **private to `super` (the MITM module)** on purpose. The
//! primitives are useful enough that a future SNI-router or
//! TLS-aware load balancer would want them, but until that second
//! caller materialises the right move is to keep the surface
//! small. Lifting this into `rama-net::tls::alert` later is a
//! straight rename — no breaking-change risk because nothing
//! outside `super` can depend on the current location.

use tokio::io::AsyncWriteExt;

/// AlertLevel from the TLS 1.2/1.3 wire format. Only the two values
/// the spec defines.
///
/// TLS 1.3 effectively treats every alert as fatal (RFC 8446 §6.1)
/// regardless of the level byte, but the byte is still part of the
/// record and must be present. We always emit `Fatal` in practice;
/// `Warning` is here for completeness and to make `Fatal` an
/// intentional choice at the call site rather than the default
/// you'd get from `Default::default()`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlertLevel {
    #[allow(dead_code)] // kept for completeness; today's callers always send Fatal
    Warning = 1,
    Fatal = 2,
}

/// Subset of TLS AlertDescription values relevant to a MITM relay's
/// pre-handshake failure paths. Full IANA registry has ~30 values
/// (RFC 8446 §6); we only enumerate the ones we'd plausibly send
/// from this code path. Add more as call sites grow — the byte
/// value is the wire byte and the names match the RFC.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AlertDescription {
    /// Notify the peer that the sender is shutting down the
    /// connection cleanly. Sent by both sides as part of a normal
    /// close.
    #[allow(dead_code)] // kept for symmetry; not used by today's callers
    CloseNotify = 0,
    /// Generic "we could not agree on handshake parameters". The
    /// right choice for "upstream rejected our ClientHello" — the
    /// client interprets it as a TLS failure rather than a transport
    /// error.
    HandshakeFailure = 40,
    /// "The protocol version offered is not supported". Useful when
    /// the upstream returned a `protocol_version` alert at us and we
    /// want to surface the same shape downstream.
    #[allow(dead_code)]
    ProtocolVersion = 70,
    /// Server-side problem, can't tell you what specifically. Use
    /// when our MITM machinery failed (cert mirror, acceptor build,
    /// …) for reasons that aren't the upstream's fault.
    #[allow(dead_code)]
    InternalError = 80,
}

/// Build the 7-byte plaintext TLS Alert record. Pure function so
/// the byte layout is auditable in one place and the writer below
/// reduces to "shove these bytes at the socket".
///
/// Wire format:
///   * `[0]`   = `0x15`        — record type Alert
///   * `[1..3]` = `0x0303`      — legacy record version (TLS 1.2);
///                                accepted by all 1.2/1.3 clients
///                                in this pre-handshake position
///   * `[3..5]` = `0x0002`      — record length 2
///   * `[5]`    = `level as u8` — AlertLevel
///   * `[6]`    = `desc  as u8` — AlertDescription
pub(super) fn encode_plain_alert(level: AlertLevel, description: AlertDescription) -> [u8; 7] {
    [
        0x15,
        0x03,
        0x03,
        0x00,
        0x02,
        level as u8,
        description as u8,
    ]
}

/// Best-effort write of a plaintext TLS Alert record to `w`,
/// followed by a flush. Errors are intentionally swallowed — the
/// only sane reaction to a failed write here is to drop the stream,
/// which the caller is about to do anyway. The signature is
/// fire-and-forget for the same reason.
///
/// SAFETY (TLS state-machine, not memory-safety): valid only BEFORE
/// any TLS handshake bytes have been sent on `w`. After a
/// ServerHello the record-layer keys advance and a plaintext alert
/// would either be parsed as garbage or rejected with
/// `bad_record_mac`. The caller is responsible for the discipline.
pub(super) async fn write_plain_alert<W>(
    w: &mut W,
    level: AlertLevel,
    description: AlertDescription,
) where
    W: AsyncWriteExt + Unpin,
{
    let bytes = encode_plain_alert(level, description);
    let _ = w.write_all(&bytes).await;
    let _ = w.flush().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the exact wire bytes for the production combination we
    /// actually send from the MITM relay: `Fatal +
    /// HandshakeFailure`. Browsers parse the *byte values*, not the
    /// enum names — a refactor that flips a constant would change
    /// observable browser behavior without the type system noticing.
    /// This test catches that.
    #[test]
    fn fatal_handshake_failure_wire_bytes() {
        assert_eq!(
            encode_plain_alert(AlertLevel::Fatal, AlertDescription::HandshakeFailure),
            [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28],
        );
    }

    /// Every enum variant maps to the IANA-assigned wire byte. A
    /// regression here would silently mislabel the alert (e.g. send
    /// `40` while claiming `internal_error`) and confuse log
    /// readers + downstream policy.
    #[test]
    fn enum_variants_match_iana_wire_bytes() {
        assert_eq!(AlertLevel::Warning as u8, 1);
        assert_eq!(AlertLevel::Fatal as u8, 2);
        assert_eq!(AlertDescription::CloseNotify as u8, 0);
        assert_eq!(AlertDescription::HandshakeFailure as u8, 40);
        assert_eq!(AlertDescription::ProtocolVersion as u8, 70);
        assert_eq!(AlertDescription::InternalError as u8, 80);
    }

    /// `write_plain_alert` writes exactly the 7 bytes
    /// `encode_plain_alert` produces, nothing more. Pin the
    /// "writes exactly N bytes and flushes" contract so a future
    /// refactor (batching, framing, padding, …) trips here first.
    #[tokio::test]
    async fn writer_emits_exactly_the_encoded_bytes() {
        let mut buf: Vec<u8> = Vec::new();
        write_plain_alert(
            &mut buf,
            AlertLevel::Fatal,
            AlertDescription::HandshakeFailure,
        )
        .await;
        assert_eq!(
            buf,
            encode_plain_alert(AlertLevel::Fatal, AlertDescription::HandshakeFailure).to_vec(),
        );
    }

    /// Other level/description combinations land on their expected
    /// bytes. Doesn't lock in the *production* choice (that's the
    /// `fatal_handshake_failure_wire_bytes` test above) but does
    /// pin the encoding formula across every value.
    #[test]
    fn other_combinations_round_trip_through_encode() {
        for (level, desc, expected_last_two) in [
            (AlertLevel::Warning, AlertDescription::CloseNotify, [0x01, 0x00]),
            (AlertLevel::Fatal, AlertDescription::ProtocolVersion, [0x02, 0x46]),
            (AlertLevel::Fatal, AlertDescription::InternalError, [0x02, 0x50]),
        ] {
            let got = encode_plain_alert(level, desc);
            assert_eq!(
                &got[..5],
                &[0x15, 0x03, 0x03, 0x00, 0x02],
                "record header must not vary by alert kind",
            );
            assert_eq!(&got[5..], &expected_last_two);
        }
    }
}
