//! Packet-protection key interfaces (RFC 9001 §5).
//!
//! These are the abstract keys the packet codec uses to remove or apply protection. The actual
//! key derivation and AEAD live in the engine's TLS backends, which implement these traits.

use alloc::sync::Arc;

use rama_core::bytes::BytesMut;

rama_utils::macros::error::static_str_error! {
    #[doc = "cryptographic operation failed"]
    ///
    /// Generic crypto errors.
    #[derive(Copy)]
    pub struct CryptoError;
}

/// Keys used to protect packet payloads.
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
    /// Maximum number of packets that may be sent using a single key (RFC 9001 §6.6)
    ///
    /// Counted per key: a key update starts the new phase at zero. The last packet of the
    /// budget carries the close, and nothing is protected past it. Routine updates begin
    /// 10,000 packets short of this value.
    fn confidentiality_limit(&self) -> u64;
    /// Maximum number of incoming packets that may fail decryption before the connection must be
    /// abandoned (RFC 9001 §6.6)
    ///
    /// Counted for the whole connection, across every key it has used. Once exceeded, the
    /// connection ends and processes no further packets.
    fn integrity_limit(&self) -> u64;
}

/// Keys used to protect packet headers.
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
