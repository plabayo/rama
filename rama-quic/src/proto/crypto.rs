//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer as well as a single implementation of these traits that uses
//! *ring* and rustls to implement the TLS protocol support.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::{str, sync::Arc};

use rama_core::bytes::BytesMut;
use rama_crypto::pki_types::CertificateDer;
use rama_net::{address::Domain, tls::ApplicationProtocol};

use crate::proto::{
    ConnectError, Side, TransportError, shared::ConnectionId,
    transport_parameters::TransportParameters,
};

/// Cryptography interface based on *ring*
#[cfg(any(feature = "aws-lc", feature = "ring"))]
pub(crate) mod ring_like;
/// TLS interface based on rustls
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
pub(crate) mod rustls;

/// Negotiated ALPN and received server name reported by the TLS backend.
///
/// Available once the session has the data, which is before the handshake is confirmed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandshakeSummary {
    /// The application protocol both sides agreed on (RFC 7301), when ALPN was used.
    pub protocol: Option<ApplicationProtocol>,
    /// The name the client sent in its SNI extension, when it sent one. It is what the peer
    /// said, not an identity a certificate was verified against, and the backend may have
    /// canonicalised its case. `None` on a client, and on a server whose peer sent no SNI,
    /// which includes a client connecting to an IP address (RFC 6066 §3).
    pub server_name: Option<Domain>,
}

/// A cryptographic session (commonly TLS)
pub(crate) trait Session: Send + Sync + 'static {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys;

    /// What the handshake has settled, when the session has it. `None` until the connection
    /// emits `HandshakeDataReady`.
    fn handshake_summary(&self) -> Option<HandshakeSummary> {
        None
    }

    /// The certificate chain the peer presented, if it presented one.
    fn peer_certificates(&self) -> Option<Vec<CertificateDer<'static>>> {
        None
    }

    /// The negotiated key exchange group as an IANA `NamedGroup` code (test observation point)
    #[cfg(test)]
    fn negotiated_key_exchange_group(&self) -> Option<u16> {
        None
    }

    /// Get the 0-RTT keys if available (clients only)
    ///
    /// On the client side, this method can be used to see if 0-RTT key material is available
    /// to start sending data before the protocol handshake has completed.
    ///
    /// Returns `None` if the key material is not available. This might happen if you have
    /// not connected to this server before.
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)>;

    /// If the 0-RTT-encrypted data has been accepted by the peer
    fn early_data_accepted(&self) -> Option<bool>;

    /// Returns `true` until the connection is fully established.
    fn is_handshaking(&self) -> bool;

    /// Read bytes of handshake data
    ///
    /// This should be called with the contents of `CRYPTO` frames. If it returns `Ok`, the
    /// caller should call `write_handshake()` to check if the crypto protocol has anything
    /// to send to the peer. This method will only return `true` the first time that
    /// handshake data is available. Future calls will always return false.
    ///
    /// On success, returns `true` iff `self.handshake_data()` has been populated.
    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError>;

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Writes handshake bytes into the given buffer and optionally returns the negotiated keys
    ///
    /// When the handshake proceeds to the next phase, this method will return a new set of
    /// keys to encrypt data with.
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>>;

    /// Verify the integrity of a retry packet
    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool;

    /// Fill `output` with `output.len()` bytes of keying material derived
    /// from the [Session]'s secrets, using `label` and `context` for domain
    /// separation.
    ///
    /// This function will fail, returning [ExportKeyingMaterialError],
    /// if the requested output length is too large.
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError>;
}

/// A pair of keys for bidirectional communication
pub(crate) struct KeyPair<T> {
    /// Key for encrypting data
    pub(crate) local: T,
    /// Key for decrypting data
    pub(crate) remote: T,
}

/// A complete set of keys for a certain packet space
pub(crate) struct Keys {
    /// Header protection keys
    pub(crate) header: KeyPair<Box<dyn HeaderKey>>,
    /// Packet protection keys
    pub(crate) packet: KeyPair<Box<dyn PacketKey>>,
}

/// Client-side configuration for the crypto protocol
pub(crate) trait ClientConfig: Send + Sync {
    /// Start a client session with this configuration
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub(crate) trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion>;

    /// Generate the integrity tag for a retry packet
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16];

    /// Start a server session with this configuration
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, TransportError>;
}

/// Keys used to protect packet payloads
pub(crate) trait PacketKey: Send + Sync {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize);
    /// Decrypt the packet payload with the given packet number
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError>;
    /// The length of the AEAD tag appended to packets on encryption
    fn tag_len(&self) -> usize;
    /// Maximum number of packets that may be sent using a single key
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned
    fn integrity_limit(&self) -> u64;
}

/// Keys used to protect packet headers
pub(crate) trait HeaderKey: Send + Sync {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
}

/// A key for signing with HMAC-based algorithms
pub(crate) trait HmacKey: Send + Sync {
    /// Method for signing a message
    fn sign(&self, data: &[u8], signature_out: &mut [u8]);
    /// Length of `sign`'s output
    fn signature_len(&self) -> usize;
    /// Method for verifying a message
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

/// Error returned by [Session::export_keying_material].
///
/// This error occurs if the requested output length is too large.
#[derive(Debug, PartialEq, Eq)]
pub struct ExportKeyingMaterialError;

/// A pseudo random key for HKDF
pub(crate) trait HandshakeTokenKey: Send + Sync {
    /// Derive AEAD using hkdf
    ///
    /// Fails when the provider cannot expand or load the derived key.
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Result<Box<dyn AeadKey>, CryptoError>;
}

/// A key for sealing data with AEAD-based algorithms
pub(crate) trait AeadKey {
    /// Method for sealing message `data`
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError>;
    /// Method for opening a sealed message `data`
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError>;
}

/// Generic crypto errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CryptoError;

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("cryptographic operation failed")
    }
}

impl std::error::Error for CryptoError {}

/// Error indicating that the specified QUIC version is not supported
#[derive(Debug)]
pub(crate) struct UnsupportedVersion;

impl From<UnsupportedVersion> for ConnectError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}
