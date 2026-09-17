//! Traits and implementations for the QUIC cryptography protocol
//!
//! The protocol logic is contained in types that abstract over the actual
//! cryptographic protocol used. This module contains the traits used for this
//! abstraction layer, with built-in adapters for Rustls and BoringSSL.
//!
//! Note that usage of any protocol (version) other than TLS 1.3 does not conform to any
//! published versions of the specification, and will not be supported in QUIC v1.

use std::{str, sync::Arc};

use rama_crypto::pki_types::CertificateDer;
pub use rama_quic_proto::crypto::{CryptoError, HeaderKey, PacketKey};
pub use rama_tls::client::NegotiatedTlsParameters;

use crate::proto::{
    ConnectError, Side, TransportError, Version, packet::SpaceId, shared::ConnectionId,
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
    /// Create the initial set of keys for `version` given the client's initial destination
    /// ConnectionId.
    ///
    /// `version` is the version of the connection, or the version compatible version
    /// negotiation (RFC 9368) is moving it to; the salt and labels follow it (RFC 9369 §3.3).
    fn initial_keys(
        &self,
        version: Version,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, TransportError>;

    /// Whether [`Self::switch_version`] can succeed on this session.
    ///
    /// A provider that derives its own packet keys from TLS secrets can re-label them for a
    /// compatible version; one that receives finished keys cannot. Defaults to `false`.
    fn supports_version_switch(&self) -> bool {
        false
    }

    /// Move the session to a compatible `version` before any Handshake or 1-RTT key is
    /// derived (RFC 9368 §2.3, RFC 9369 §4.1).
    ///
    /// Called at most once, before the handshake keys are drained. Providers that cannot
    /// switch return [`UnsupportedVersion`]; the transport then never asks them to.
    fn switch_version(&mut self, version: Version) -> Result<(), UnsupportedVersion> {
        let _ = version;
        Err(UnsupportedVersion)
    }

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
        version: Version,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError>;

    /// Whether sessions from this configuration can switch to a compatible version during
    /// the handshake. Decides at configuration time whether a version policy that needs a
    /// switch is usable; defaults to `false`.
    fn supports_version_switch(&self) -> bool {
        false
    }

    /// The version of the newest session ticket held for `server_name`, if the provider can
    /// tell without consuming it.
    ///
    /// A ticket resumes only a connection in the version that issued it (RFC 9369 §5), so a
    /// client that wants to resume starts in that version. Defaults to `None`.
    fn resumable_version(&self, server_name: &str) -> Option<Version> {
        let _ = server_name;
        None
    }
}

/// Server-side configuration for the crypto protocol
pub trait ServerConfig: Send + Sync {
    /// Create the initial set of keys given the client's initial destination ConnectionId
    fn initial_keys(
        &self,
        version: Version,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, InitialKeysError>;

    /// Generate the integrity tag for a retry packet
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn retry_tag(
        &self,
        version: Version,
        orig_dst_cid: &ConnectionId,
        packet: &[u8],
    ) -> Result<[u8; 16], CryptoError>;

    /// Start a server session with this configuration
    ///
    /// Never called if `initial_keys` rejected `version`.
    fn start_session(
        self: Arc<Self>,
        version: Version,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, TransportError>;

    /// Whether [`Self::start_negotiated_session`] is implemented.
    fn supports_compatible_negotiation(&self) -> bool {
        false
    }

    /// Start a server session for a connection the server moves from the client's `original`
    /// version to the compatible `negotiated` version (RFC 9368 §2.3).
    ///
    /// Handshake and 1-RTT keys follow `negotiated`; 0-RTT keys, if the session accepts early
    /// data at all, follow `original`, which is the only version the client sends 0-RTT in
    /// (RFC 9369 §4.1). Never called with equal versions, nor when
    /// [`Self::supports_compatible_negotiation`] is `false`.
    fn start_negotiated_session(
        self: Arc<Self>,
        original: Version,
        negotiated: Version,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, TransportError> {
        let _ = (original, negotiated, params);
        Err(TransportError::INTERNAL_ERROR(
            "TLS provider cannot move a connection to another version",
        ))
    }

    /// Whether sessions from this configuration can switch to a compatible version during
    /// the handshake; see [`ClientConfig::supports_version_switch`].
    fn supports_version_switch(&self) -> bool {
        false
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
