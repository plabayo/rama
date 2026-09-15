use rama_core::{
    bytes::BytesMut,
    error::{BoxError, BoxErrorExt as _},
};
use rama_crypto::dep::boring::{aead, aes::AesEncryptKey, chacha, hash::MessageDigest, hkdf};
use zeroize::Zeroizing;

use crate::proto::{
    Side,
    crypto::{self, CryptoError, DirectionalKeys, Keys},
    shared::ConnectionId,
};

#[derive(Clone, Copy)]
pub(super) enum Suite {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Suite {
    pub(super) fn from_id(id: u16) -> Result<Self, BoxError> {
        match id {
            0x1301 => Ok(Self::Aes128Gcm),
            0x1302 => Ok(Self::Aes256Gcm),
            0x1303 => Ok(Self::ChaCha20Poly1305),
            _ => Err(BoxError::from_static_str("unsupported QUIC cipher suite")),
        }
    }

    fn digest(self) -> MessageDigest {
        match self {
            Self::Aes256Gcm => MessageDigest::sha384(),
            _ => MessageDigest::sha256(),
        }
    }

    fn aead(self) -> aead::Algorithm {
        match self {
            Self::Aes128Gcm => aead::Algorithm::Aes128Gcm,
            Self::Aes256Gcm => aead::Algorithm::Aes256Gcm,
            Self::ChaCha20Poly1305 => aead::Algorithm::ChaCha20Poly1305,
        }
    }
}

pub(super) struct Secret {
    suite: Suite,
    bytes: Zeroizing<Vec<u8>>,
}

impl Secret {
    pub(super) fn new(suite: Suite, bytes: &[u8]) -> Result<Self, BoxError> {
        if bytes.len() != suite.digest().size() {
            return Err(BoxError::from_static_str(
                "invalid QUIC traffic secret length",
            ));
        }
        Ok(Self {
            suite,
            bytes: Zeroizing::new(bytes.to_vec()),
        })
    }

    fn expand(&self, label: &[u8], output: &mut [u8]) -> Result<(), BoxError> {
        let info = rama_tls::key_schedule::encode_hkdf_label(label, &[], output.len())?;
        hkdf::expand(self.suite.digest(), &self.bytes, &info, output)?;
        Ok(())
    }

    pub(super) fn updated(&self) -> Result<Self, BoxError> {
        let mut bytes = Zeroizing::new(vec![0; self.bytes.len()]);
        self.expand(b"quic ku", &mut bytes)?;
        Ok(Self {
            suite: self.suite,
            bytes,
        })
    }

    pub(super) fn packet_key(&self) -> Result<PacketKey, BoxError> {
        let mut key = Zeroizing::new(vec![0; self.suite.aead().key_len()]);
        let mut iv = Zeroizing::new([0; 12]);
        self.expand(b"quic key", &mut key)?;
        self.expand(b"quic iv", &mut *iv)?;
        Ok(PacketKey {
            suite: self.suite,
            key: aead::AeadKey::new(self.suite.aead(), &key)?,
            iv,
        })
    }

    pub(super) fn directional_keys(&self) -> Result<DirectionalKeys, BoxError> {
        let mut key = Zeroizing::new([0; 32]);
        let len = self.suite.aead().key_len();
        self.expand(b"quic hp", &mut key[..len])?;
        let header = match self.suite {
            Suite::ChaCha20Poly1305 => HeaderKey::ChaCha(key),
            _ => HeaderKey::Aes(AesEncryptKey::new(&key[..len]).map_err(|_error| {
                BoxError::from_static_str("invalid QUIC header protection key")
            })?),
        };
        Ok(DirectionalKeys {
            header: Box::new(header),
            packet: Box::new(self.packet_key()?),
        })
    }
}

pub(super) fn initial_keys(cid: &ConnectionId, side: Side) -> Result<Keys, BoxError> {
    const SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let mut extracted = Zeroizing::new([0; 32]);
    hkdf::extract(MessageDigest::sha256(), &SALT, cid, &mut *extracted)?;
    let secret = Secret::new(Suite::Aes128Gcm, &*extracted)?;
    let mut client = Zeroizing::new([0; 32]);
    let mut server = Zeroizing::new([0; 32]);
    secret.expand(b"client in", &mut *client)?;
    secret.expand(b"server in", &mut *server)?;
    let client = Secret::new(Suite::Aes128Gcm, &*client)?.directional_keys()?;
    let server = Secret::new(Suite::Aes128Gcm, &*server)?.directional_keys()?;
    let (local, remote) = if side.is_client() {
        (client, server)
    } else {
        (server, client)
    };
    Ok(Keys {
        local,
        remote: Some(remote),
    })
}

pub(super) fn retry_tag(cid: &ConnectionId, packet: &[u8]) -> Result<[u8; 16], BoxError> {
    const KEY: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const NONCE: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];
    let mut aad = Vec::with_capacity(1 + cid.len() + packet.len());
    aad.push(cid.len() as u8);
    aad.extend_from_slice(cid);
    aad.extend_from_slice(packet);
    let mut tag = [0; 16];
    aead::AeadKey::new(aead::Algorithm::Aes128Gcm, &KEY)?.seal_in_place(&NONCE, &aad, &mut tag)?;
    Ok(tag)
}

pub(super) struct PacketKey {
    suite: Suite,
    key: aead::AeadKey,
    iv: Zeroizing<[u8; 12]>,
}

impl PacketKey {
    fn nonce(&self, packet: u64) -> [u8; 12] {
        let mut nonce = *self.iv;
        for (byte, number) in nonce[4..].iter_mut().zip(packet.to_be_bytes()) {
            *byte ^= number;
        }
        nonce
    }
}

impl crypto::PacketKey for PacketKey {
    fn encrypt(
        &self,
        packet: u64,
        buffer: &mut [u8],
        header_len: usize,
    ) -> Result<(), CryptoError> {
        let (header, payload) = buffer.split_at_mut(header_len);
        self.key
            .seal_in_place(&self.nonce(packet), header, payload)
            .map_err(|_error| CryptoError)
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let len = self
            .key
            .open_in_place(&self.nonce(packet), header, payload)
            .map_err(|_error| CryptoError)?
            .len();
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }
    fn confidentiality_limit(&self) -> u64 {
        match self.suite {
            Suite::ChaCha20Poly1305 => 1 << 62,
            _ => 1 << 23,
        }
    }
    fn integrity_limit(&self) -> u64 {
        match self.suite {
            Suite::ChaCha20Poly1305 => 1 << 36,
            _ => 1 << 52,
        }
    }
}

#[expect(
    clippy::large_enum_variant,
    reason = "the complete key is already boxed as a HeaderKey trait object"
)]
enum HeaderKey {
    Aes(AesEncryptKey),
    ChaCha(Zeroizing<[u8; 32]>),
}

impl HeaderKey {
    fn mask(&self, sample: &[u8]) -> [u8; 5] {
        let mut mask = [0; 5];
        match self {
            Self::Aes(key) => {
                let mut block = [0; 16];
                block.copy_from_slice(sample);
                mask.copy_from_slice(&key.encrypt_block(&block)[..5]);
            }
            Self::ChaCha(key) => {
                let counter = u32::from_le_bytes([sample[0], sample[1], sample[2], sample[3]]);
                let mut nonce = [0; 12];
                nonce.copy_from_slice(&sample[4..]);
                chacha::apply(key, &nonce, counter, &mut mask);
            }
        }
        mask
    }

    fn apply(&self, pn_offset: usize, packet: &mut [u8], decrypt: bool) {
        // The packet decoder/builder guarantees a full sample after four PN bytes.
        let mask = self.mask(&packet[pn_offset + 4..pn_offset + 20]);
        let first = packet[0];
        let masked = first ^ (mask[0] & if first & 0x80 == 0 { 0x1f } else { 0x0f });
        let pn_len = usize::from((if decrypt { masked } else { first } & 3) + 1);
        packet[0] = masked;
        for (byte, mask) in packet[pn_offset..pn_offset + pn_len]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= mask;
        }
    }
}

impl crypto::HeaderKey for HeaderKey {
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, false);
    }
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        self.apply(pn_offset, packet, true);
    }
    fn sample_size(&self) -> usize {
        16
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::crypto::PacketKey as _;

    fn hex(input: &str) -> Vec<u8> {
        input
            .split_whitespace()
            .collect::<String>()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9001_server_initial() {
        let cid = ConnectionId::new(&hex("8394c8f03e515708"));
        let keys = initial_keys(&cid, Side::Server).unwrap();
        let header = hex("c1000000010008f067a5502a4262b50040750001");
        let payload = hex(
            "02000000000600405a020000560303ee fce7f7b37ba1d1632e96677825ddf739
            88cfc79825df566dc5430b9a045a1200 130100002e00330024001d00209d3c94
            0d89690b84d08a60993c144eca684d10 81287c834d5311bcf32bb9da1a002b00 020304",
        );
        let mut packet = header.clone();
        packet.extend_from_slice(&payload);
        packet.resize(packet.len() + 16, 0);
        keys.local
            .packet
            .encrypt(1, &mut packet, header.len())
            .unwrap();
        keys.local.header.encrypt(header.len() - 2, &mut packet);
        assert_eq!(
            packet,
            hex(
                "cf000000010008f067a5502a4262b500 4075c0d95a482cd0991cd25b0aac406a
            5816b6394100f37a1c69797554780bb3 8cc5a99f5ede4cf73c3ec2493a1839b3
            dbcba3f6ea46c5b7684df3548e7ddeb9 c3bf9c73cc3f3bded74b562bfb19fb84
            022f8ef4cdd93795d77d06edbb7aaf2f 58891850abbdca3d20398c276456cbc4 2158407dd074ee"
            )
        );
        let read = initial_keys(&cid, Side::Client).unwrap().remote.unwrap();
        read.header.decrypt(header.len() - 2, &mut packet);
        assert_eq!(&packet[..header.len()], header);
        let mut decrypted = BytesMut::from(&packet[header.len()..]);
        read.packet.decrypt(1, &header, &mut decrypted).unwrap();
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn rfc9001_retry() {
        let cid = ConnectionId::new(&hex("8394c8f03e515708"));
        let packet = hex("ff000000010008f067a5502a4262b5746f6b656e");
        assert_eq!(
            retry_tag(&cid, &packet).unwrap().as_slice(),
            hex("04a265ba2eff4d829058fb3f0f2496ba")
        );
    }

    #[test]
    fn rfc9001_chacha_short_header_and_key_update() {
        let secret = Secret::new(
            Suite::ChaCha20Poly1305,
            &hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b"),
        )
        .unwrap();
        assert_eq!(
            *secret.updated().unwrap().bytes,
            hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        );
        let keys = secret.directional_keys().unwrap();
        let mut packet = hex("4200bff401");
        packet.resize(21, 0);
        keys.packet.encrypt(654360564, &mut packet, 4).unwrap();
        keys.header.encrypt(1, &mut packet);
        assert_eq!(packet, hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"));
        keys.header.decrypt(1, &mut packet);
        assert_eq!(&packet[..4], hex("4200bff4"));
        let mut payload = BytesMut::from(&packet[4..]);
        keys.packet
            .decrypt(654360564, &packet[..4], &mut payload)
            .unwrap();
        assert_eq!(&payload[..], &[1]);
    }

    /// RFC 9001 §6.6 and Appendix B: the AES-GCM suites stop at 2^23 packets per key and
    /// 2^52 forgeries per connection; ChaCha20-Poly1305 at 2^36 forgeries, with a
    /// confidentiality limit beyond the 2^62 packets a connection can number. The Initial keys
    /// are AES-128-GCM keys and answer as such.
    #[test]
    fn packet_keys_report_the_rfc_9001_aead_limits() {
        for (suite, confidentiality, integrity) in [
            (Suite::Aes128Gcm, 1 << 23, 1 << 52),
            (Suite::Aes256Gcm, 1 << 23, 1 << 52),
            (Suite::ChaCha20Poly1305, 1 << 62, 1 << 36),
        ] {
            let secret = Secret::new(suite, &vec![7; suite.digest().size()]).unwrap();
            for key in [
                secret.packet_key().unwrap(),
                secret.updated().unwrap().packet_key().unwrap(),
            ] {
                assert_eq!(key.confidentiality_limit(), confidentiality);
                assert_eq!(key.integrity_limit(), integrity);
            }
        }
        let keys =
            initial_keys(&ConnectionId::new(&[1, 2, 3, 4, 5, 6, 7, 8]), Side::Client).unwrap();
        for key in [&keys.local.packet, &keys.remote.unwrap().packet] {
            assert_eq!(key.confidentiality_limit(), 1 << 23);
            assert_eq!(key.integrity_limit(), 1 << 52);
        }
    }

    #[test]
    fn all_suites_authenticate_header_number_and_payload() {
        for suite in [Suite::Aes128Gcm, Suite::Aes256Gcm, Suite::ChaCha20Poly1305] {
            let secret = Secret::new(suite, &vec![7; suite.digest().size()]).unwrap();
            let key = secret.packet_key().unwrap();
            let mut packet = vec![0; 24];
            packet[..8].copy_from_slice(b"headbody");
            key.encrypt(0x123456789, &mut packet, 4).unwrap();
            let mut wrong_number = BytesMut::from(&packet[4..]);
            assert!(
                key.decrypt(0x123456788, b"head", &mut wrong_number)
                    .is_err()
            );
            let mut wrong_header = BytesMut::from(&packet[4..]);
            assert!(
                key.decrypt(0x123456789, b"HEAD", &mut wrong_header)
                    .is_err()
            );
            let mut corrupt = BytesMut::from(&packet[4..]);
            corrupt[0] ^= 1;
            assert!(key.decrypt(0x123456789, b"head", &mut corrupt).is_err());
            let mut payload = BytesMut::from(&packet[4..]);
            key.decrypt(0x123456789, b"head", &mut payload).unwrap();
            assert_eq!(&payload[..], b"body");
            let mut old = BytesMut::from(&packet[4..]);
            assert!(
                secret
                    .updated()
                    .unwrap()
                    .packet_key()
                    .unwrap()
                    .decrypt(0x123456789, b"head", &mut old)
                    .is_err()
            );
        }
    }
}
