//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer, with built-in adapters for Rustls and BoringSSL.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::{str, sync::Arc};

use rama_core::bytes::BytesMut;
use rama_crypto::pki_types::CertificateDer;
pub use rama_tls::client::NegotiatedTlsParameters;

use crate::proto::{
    ConnectError, Side, TransportError, packet::SpaceId, shared::ConnectionId,
    transport_parameters::TransportParameters,
};

pub(crate) mod config;

#[cfg(feature = "boring")]
pub(crate) mod boring;

/// Cryptography interface based on *ring*
#[cfg(any(feature = "aws-lc", feature = "ring"))]
pub(crate) mod ring_like;
/// TLS interface based on rustls
#[cfg(all(feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
pub(crate) mod rustls;

/// A cryptographic session (commonly TLS)
pub trait Session: Send + Sync + 'static {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Result<Keys, TransportError>;

    /// What the handshake has settled, when the session has it. `None` until the connection
    /// emits `HandshakeDataReady`.
    fn handshake_summary(&self) -> Option<NegotiatedTlsParameters> {
        None
    }

    /// Borrow negotiated ALPN bytes for diagnostics without allocating a handshake summary.
    fn negotiated_alpn(&self) -> Option<&[u8]> {
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
    /// caller should call `poll_handshake()` to check if the crypto protocol has anything
    /// to send to the peer. This method will only return `true` the first time that
    /// handshake data is available. Future calls will always return false.
    ///
    /// On success, returns `true` when `handshake_summary()` first becomes available.
    fn read_handshake(&mut self, level: SpaceId, buf: &[u8]) -> Result<bool, TransportError>;

    /// The peer's QUIC transport parameters
    ///
    /// These are only available after the first flight from the peer has been received.
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError>;

    /// Drain ordered handshake output and directional key changes.
    fn poll_handshake(&mut self) -> Result<Option<HandshakeEvent>, TransportError>;

    /// Compute keys for the next key update
    fn next_1rtt_keys(&mut self) -> Result<Option<KeyPair<Box<dyn PacketKey>>>, TransportError>;

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
pub struct KeyPair<T> {
    /// Key for encrypting data
    pub local: T,
    /// Key for decrypting data
    pub remote: T,
}

/// Packet and header protection for one direction.
pub struct DirectionalKeys {
    pub header: Box<dyn HeaderKey>,
    pub packet: Box<dyn PacketKey>,
}

/// Write keys become available before read keys on a TLS server.
pub struct Keys {
    pub local: DirectionalKeys,
    pub remote: Option<DirectionalKeys>,
}

/// Ordered TLS output and packet-key installation events.
pub enum HandshakeEvent {
    /// Handshake bytes to send at this encryption level before subsequent events.
    Data(SpaceId, Vec<u8>),
    /// Install write keys and any already available read keys for this level.
    Keys(SpaceId, Keys),
    /// Install read keys that became available after the write keys.
    ReadKeys(SpaceId, DirectionalKeys),
}

/// Client-side configuration for the crypto protocol
pub trait ClientConfig: Send + Sync {
    /// Start a client session with this configuration
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(&self, version: u32, dst_cid: &ConnectionId) -> Result<Keys, InitialKeysError>;

    /// Generate the integrity tag for a retry packet
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn retry_tag(
        &self,
        version: u32,
        orig_dst_cid: &ConnectionId,
        packet: &[u8],
    ) -> Result<[u8; 16], CryptoError>;

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
pub trait PacketKey: Send + Sync {
    /// Encrypt the packet payload with the given packet number
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) -> Result<(), CryptoError>;
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
pub trait HeaderKey: Send + Sync {
    /// Decrypt the given packet's header
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// Encrypt the given packet's header
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]);
    /// The sample size used for this key's algorithm
    fn sample_size(&self) -> usize;
}

impl<T: PacketKey + ?Sized> PacketKey for Arc<T> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) -> Result<(), CryptoError> {
        (**self).encrypt(packet, buf, header_len)
    }
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        (**self).decrypt(packet, header, payload)
    }
    fn tag_len(&self) -> usize {
        (**self).tag_len()
    }
    fn confidentiality_limit(&self) -> u64 {
        (**self).confidentiality_limit()
    }
    fn integrity_limit(&self) -> u64 {
        (**self).integrity_limit()
    }
}

impl<T: HeaderKey + ?Sized> HeaderKey for Arc<T> {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        (**self).decrypt(pn_offset, packet);
    }
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        (**self).encrypt(pn_offset, packet);
    }
    fn sample_size(&self) -> usize {
        (**self).sample_size()
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "failed to export keying material"]
    ///
    /// The requested output length exceeds the exporter's limit.
    pub struct ExportKeyingMaterialError;
}

/// A pseudo random key for HKDF
pub trait HandshakeTokenKey: Send + Sync {
    /// Derive AEAD using hkdf
    ///
    /// Fails when the provider cannot expand or load the derived key.
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Result<Box<dyn AeadKey>, CryptoError>;
}

/// A key for sealing data with AEAD-based algorithms
pub trait AeadKey {
    /// Method for sealing message `data`
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), CryptoError>;
    /// Method for opening a sealed message `data`
    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], CryptoError>;
}

rama_utils::macros::error::static_str_error! {
    #[doc = "cryptographic operation failed"]
    ///
    /// Generic crypto errors.
    #[derive(Copy)]
    pub struct CryptoError;
}

/// Error indicating that the specified QUIC version is not supported
#[derive(Debug)]
pub struct UnsupportedVersion;

#[derive(Debug)]
pub enum InitialKeysError {
    UnsupportedVersion,
    Crypto(rama_core::error::BoxError),
}

impl From<UnsupportedVersion> for InitialKeysError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}

impl From<UnsupportedVersion> for ConnectError {
    fn from(_: UnsupportedVersion) -> Self {
        Self::UnsupportedVersion
    }
}
