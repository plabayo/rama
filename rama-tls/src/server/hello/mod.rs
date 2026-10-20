//! What a server answered a ClientHello with, read from its handshake messages.

use rama_core::error::{BoxError, BoxErrorExt as _};
use rama_net::tls::ApplicationProtocol;

use crate::{CipherSuite, ExtensionId, ProtocolVersion};

/// The TLS handshake message type of a ServerHello (and a HelloRetryRequest).
const SERVER_HELLO: u8 = 2;
/// The TLS 1.3 handshake message type of EncryptedExtensions.
const ENCRYPTED_EXTENSIONS: u8 = 8;

/// A server's ServerHello: what it selected, and its extensions in the order it sent them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    quic: bool,
    legacy_version: ProtocolVersion,
    selected_version: Option<ProtocolVersion>,
    cipher_suite: CipherSuite,
    alpn: Option<ApplicationProtocol>,
    extensions: Vec<ExtensionId>,
}

impl ServerHello {
    /// Read a ServerHello handshake message, its 4-byte header included, as sent over TCP.
    pub fn parse_handshake(handshake: &[u8]) -> Result<Self, BoxError> {
        Self::parse(handshake, false)
            .ok_or_else(|| BoxError::from_static_str("invalid ServerHello"))
    }

    /// Like [`Self::parse_handshake`], for a ServerHello sent over QUIC.
    pub fn parse_quic_handshake(handshake: &[u8]) -> Result<Self, BoxError> {
        Self::parse(handshake, true).ok_or_else(|| BoxError::from_static_str("invalid ServerHello"))
    }

    fn parse(handshake: &[u8], quic: bool) -> Option<Self> {
        let mut body = Reader(message_body(handshake, SERVER_HELLO)?);
        let legacy_version = ProtocolVersion::from(body.u16()?);
        body.take(32)?; // random
        body.u8_prefixed()?; // session id
        let cipher_suite = CipherSuite::from(body.u16()?);
        body.u8()?; // compression method
        let mut hello = Self {
            quic,
            legacy_version,
            selected_version: None,
            cipher_suite,
            alpn: None,
            extensions: Vec::new(),
        };
        if body.0.is_empty() {
            return Some(hello);
        }
        let mut extensions = Reader(body.u16_prefixed()?);
        if !body.0.is_empty() {
            return None;
        }
        while !extensions.0.is_empty() {
            let id = ExtensionId::from(extensions.u16()?);
            let mut data = Reader(extensions.u16_prefixed()?);
            match id {
                ExtensionId::SUPPORTED_VERSIONS => {
                    hello.selected_version = Some(ProtocolVersion::from(data.u16()?));
                }
                ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION => {
                    let mut list = Reader(data.u16_prefixed()?);
                    hello.alpn = Some(ApplicationProtocol::from(list.u8_prefixed()?));
                }
                _ => {}
            }
            hello.extensions.push(id);
        }
        Some(hello)
    }

    /// Whether the ServerHello was sent over QUIC.
    #[must_use]
    pub fn is_quic(&self) -> bool {
        self.quic
    }

    /// The legacy version field, which TLS 1.3 fixes at TLS 1.2.
    #[must_use]
    pub fn legacy_version(&self) -> ProtocolVersion {
        self.legacy_version
    }

    /// The version the server selected: from supported_versions (TLS 1.3), else the
    /// legacy version field.
    #[must_use]
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.selected_version.unwrap_or(self.legacy_version)
    }

    /// The cipher suite the server selected.
    #[must_use]
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// The protocol the server selected in its ServerHello (TLS 1.2 and earlier; TLS 1.3
    /// carries it in EncryptedExtensions).
    #[must_use]
    pub fn alpn(&self) -> Option<&ApplicationProtocol> {
        self.alpn.as_ref()
    }

    /// The extensions, in the order the server sent them.
    #[must_use]
    pub fn extensions(&self) -> &[ExtensionId] {
        &self.extensions
    }
}

/// The extensions of a TLS 1.3 EncryptedExtensions handshake message, its 4-byte header
/// included, in the order the server sent them.
pub fn parse_encrypted_extensions(handshake: &[u8]) -> Result<Vec<ExtensionId>, BoxError> {
    let parse = || {
        let mut body = Reader(message_body(handshake, ENCRYPTED_EXTENSIONS)?);
        let mut extensions = Reader(body.u16_prefixed()?);
        if !body.0.is_empty() {
            return None;
        }
        let mut ids = Vec::new();
        while !extensions.0.is_empty() {
            ids.push(ExtensionId::from(extensions.u16()?));
            extensions.u16_prefixed()?;
        }
        Some(ids)
    };
    parse().ok_or_else(|| BoxError::from_static_str("invalid EncryptedExtensions"))
}

/// The body of a handshake message of type `kind`, which must fill `handshake` exactly.
fn message_body(handshake: &[u8], kind: u8) -> Option<&[u8]> {
    let mut input = Reader(handshake);
    if input.u8()? != kind {
        return None;
    }
    let body = input.u24_prefixed()?;
    input.0.is_empty().then_some(body)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(len)?;
        self.0 = tail;
        Some(head)
    }

    fn u8(&mut self) -> Option<u8> {
        let (&byte, tail) = self.0.split_first()?;
        self.0 = tail;
        Some(byte)
    }

    fn u16(&mut self) -> Option<u16> {
        let (bytes, tail) = self.0.split_first_chunk::<2>()?;
        self.0 = tail;
        Some(u16::from_be_bytes(*bytes))
    }

    fn u8_prefixed(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    fn u16_prefixed(&mut self) -> Option<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    fn u24_prefixed(&mut self) -> Option<&'a [u8]> {
        let (bytes, tail) = self.0.split_first_chunk::<3>()?;
        self.0 = tail;
        let len = usize::from(bytes[0]) << 16 | usize::from(bytes[1]) << 8 | usize::from(bytes[2]);
        self.take(len)
    }
}

#[cfg(test)]
mod tests;
