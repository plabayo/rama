use std::fmt;

use rama_core::bytes::BufMut;
use rama_quic_proto::{VarInt, coding::Codec};

/// Largest UDP payload a context-0 datagram may carry ([RFC 9298 §5]).
///
/// [RFC 9298 §5]: https://datatracker.ietf.org/doc/html/rfc9298#section-5
pub const MAX_UDP_PAYLOAD: usize = 65527;

/// A CONNECT-UDP Context ID ([RFC 9298 §4]).
///
/// Context ID 0 carries UDP payloads. Non-zero IDs are allocated by extensions
/// (even by the client, odd by the proxy); this crate defines none, so it drops
/// datagrams carrying them.
///
/// [RFC 9298 §4]: https://datatracker.ietf.org/doc/html/rfc9298#section-4
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContextId(VarInt);

impl ContextId {
    /// Context ID 0: UDP payloads.
    pub const UDP: Self = Self(VarInt::from_u32(0));

    /// A Context ID from its value, if it fits a variable-length integer.
    #[must_use]
    pub fn new(value: u64) -> Option<Self> {
        VarInt::from_u64(value).ok().map(Self)
    }

    /// The raw value.
    #[must_use]
    pub fn value(self) -> u64 {
        self.0.into_inner()
    }

    /// Whether the client allocates this ID (non-zero and even).
    #[must_use]
    pub fn is_client_allocated(self) -> bool {
        self.value() != 0 && self.value().is_multiple_of(2)
    }

    /// Whether the proxy allocates this ID (odd).
    #[must_use]
    pub fn is_proxy_allocated(self) -> bool {
        !self.value().is_multiple_of(2)
    }
}

impl fmt::Display for ContextId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value().fmt(f)
    }
}

/// Why an HTTP Datagram payload is not a valid CONNECT-UDP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextPayloadError {
    /// The payload ends inside its Context ID.
    Truncated,
    /// A context-0 payload exceeds [`MAX_UDP_PAYLOAD`]: the stream must be aborted.
    UdpPayloadTooLarge,
}

impl fmt::Display for ContextPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "http datagram ends inside its context id",
            Self::UdpPayloadTooLarge => "context-0 http datagram exceeds 65527 bytes",
        })
    }
}

impl std::error::Error for ContextPayloadError {}

/// Split an HTTP Datagram payload into its Context ID and the rest ([RFC 9298 §5]).
///
/// Non-minimal Context ID encodings are accepted. A context-0 payload longer
/// than [`MAX_UDP_PAYLOAD`] is an error the caller must answer by aborting the
/// stream; payloads of other contexts are returned as they are.
///
/// [RFC 9298 §5]: https://datatracker.ietf.org/doc/html/rfc9298#section-5
pub fn decode_context_payload(datagram: &[u8]) -> Result<(ContextId, &[u8]), ContextPayloadError> {
    let mut rest = datagram;
    let context = VarInt::decode(&mut rest).map_err(|_error| ContextPayloadError::Truncated)?;
    let context = ContextId(context);
    if context == ContextId::UDP && rest.len() > MAX_UDP_PAYLOAD {
        return Err(ContextPayloadError::UdpPayloadTooLarge);
    }
    Ok((context, rest))
}

/// Append a context-0 HTTP Datagram payload carrying `payload`.
///
/// Payloads above [`MAX_UDP_PAYLOAD`] are refused and nothing is written.
/// How many bytes `datagram`'s Context ID takes, or `None` when it ends inside it.
pub(crate) fn context_id_len(datagram: &[u8]) -> Option<usize> {
    let mut rest = datagram;
    VarInt::decode(&mut rest).ok()?;
    Some(datagram.len() - rest.len())
}

pub fn encode_udp_payload<B: BufMut>(
    out: &mut B,
    payload: &[u8],
) -> Result<(), ContextPayloadError> {
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(ContextPayloadError::UdpPayloadTooLarge);
    }
    ContextId::UDP.0.encode(out);
    out.put_slice(payload);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_every_encoding_of_context_zero() {
        for prefix in [
            &[0x00][..],
            &[0x40, 0x00][..],
            &[0x80, 0x00, 0x00, 0x00][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 0][..],
        ] {
            let mut datagram = prefix.to_vec();
            datagram.extend_from_slice(b"udp");
            let (context, payload) = decode_context_payload(&datagram).unwrap();
            assert_eq!(context, ContextId::UDP, "{prefix:?}");
            assert_eq!(payload, b"udp");
        }
    }

    #[test]
    fn empty_udp_payloads_are_valid() {
        let (context, payload) = decode_context_payload(&[0x00]).unwrap();
        assert_eq!(context, ContextId::UDP);
        assert!(payload.is_empty());
    }

    #[test]
    fn truncated_context_ids_are_errors() {
        for datagram in [&[][..], &[0x40][..], &[0xc0, 0, 0][..]] {
            assert_eq!(
                decode_context_payload(datagram).unwrap_err(),
                ContextPayloadError::Truncated,
                "{datagram:?}"
            );
        }
    }

    #[test]
    fn context_zero_payload_limit() {
        let mut at_limit = vec![0u8; 1 + MAX_UDP_PAYLOAD];
        assert_eq!(
            decode_context_payload(&at_limit).unwrap().1.len(),
            MAX_UDP_PAYLOAD
        );
        at_limit.push(0);
        assert_eq!(
            decode_context_payload(&at_limit).unwrap_err(),
            ContextPayloadError::UdpPayloadTooLarge
        );
        // Other contexts are not bound by the UDP limit.
        let mut other = vec![0x01];
        other.extend(std::iter::repeat_n(0u8, MAX_UDP_PAYLOAD + 1));
        let (context, _) = decode_context_payload(&other).unwrap();
        assert!(context.is_proxy_allocated());
    }

    #[test]
    fn encodes_context_zero_minimally() {
        let mut out = Vec::new();
        encode_udp_payload(&mut out, b"abc").unwrap();
        assert_eq!(out, b"\x00abc");

        let mut out = Vec::new();
        let too_large = vec![0u8; MAX_UDP_PAYLOAD + 1];
        assert_eq!(
            encode_udp_payload(&mut out, &too_large).unwrap_err(),
            ContextPayloadError::UdpPayloadTooLarge
        );
        assert!(out.is_empty());
    }

    #[test]
    fn allocation_parity() {
        assert!(!ContextId::UDP.is_client_allocated());
        assert!(!ContextId::UDP.is_proxy_allocated());
        assert!(ContextId::new(2).unwrap().is_client_allocated());
        assert!(ContextId::new(3).unwrap().is_proxy_allocated());
        assert!(ContextId::new(1 << 62).is_none());
    }
}
