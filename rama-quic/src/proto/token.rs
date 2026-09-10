use std::{
    fmt,
    mem::size_of,
    net::{IpAddr, SocketAddr},
};

use rama_core::bytes::{Buf, BufMut, Bytes};
use rand::{Rng, RngExt};

use crate::proto::{
    Duration, RESET_TOKEN_SIZE, ServerConfig, SystemTime, UNIX_EPOCH,
    coding::{BufExt, BufMutExt},
    crypto::{CryptoError, HandshakeTokenKey, HmacKey},
    packet::InitialHeader,
    shared::ConnectionId,
};

/// Responsible for limiting clients' ability to reuse validation tokens
///
/// [_RFC 9000 § 8.1.4:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4)
///
/// > Attackers could replay tokens to use servers as amplifiers in DDoS attacks. To protect
/// > against such attacks, servers MUST ensure that replay of tokens is prevented or limited.
/// > Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time,
/// > as they are returned immediately by clients. Tokens that are provided in NEW_TOKEN frames
/// > (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.
/// > Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include
/// > additional information about clients to further narrow applicability or reuse.
///
/// `TokenLog` pertains only to tokens provided in NEW_TOKEN frames.
pub trait TokenLog: Send + Sync {
    /// Record that the token was used and, ideally, return a token reuse error if the token may
    /// have been already used previously
    ///
    /// False negatives and false positives are both permissible. Called when a client uses an
    /// address validation token.
    ///
    /// Parameters:
    /// - `nonce`: A server-generated random unique value for the token.
    /// - `issued`: The time the server issued the token.
    /// - `lifetime`: The expiration time of address validation tokens sent via NEW_TOKEN frames,
    ///   as configured by [`ValidationTokenConfig::set_lifetime`][1].
    ///
    /// [1]: crate::proto::ValidationTokenConfig::set_lifetime
    ///
    /// ## Security & Performance
    ///
    /// To the extent that it is possible to repeatedly trigger false negatives (returning `Ok` for
    /// a token which has been reused), an attacker could use the server to perform [amplification
    /// attacks][2]. The QUIC specification requires that this be limited, if not prevented fully.
    ///
    /// A false positive (returning `Err` for a token which has never been used) is not a security
    /// vulnerability; it is permissible for a `TokenLog` to always return `Err`. A false positive
    /// causes the token to be ignored, which may cause the transmission of some 0.5-RTT data to be
    /// delayed until the handshake completes, if a sufficient amount of 0.5-RTT data it sent.
    ///
    /// [2]: https://en.wikipedia.org/wiki/Denial-of-service_attack#Amplification
    fn check_and_insert(
        &self,
        nonce: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// Error for when a validation token may have been reused
pub struct TokenReuseError;

/// Null implementation of [`TokenLog`], which never accepts tokens
pub struct NoneTokenLog;

impl TokenLog for NoneTokenLog {
    fn check_and_insert(&self, _: u128, _: SystemTime, _: Duration) -> Result<(), TokenReuseError> {
        Err(TokenReuseError)
    }
}

/// Responsible for storing validation tokens received from servers and retrieving them for use in
/// subsequent connections
pub trait TokenStore: Send + Sync {
    /// Potentially store a token for later one-time use
    ///
    /// Called when a NEW_TOKEN frame is received from the server.
    fn insert(&self, server_name: &str, token: Bytes);

    /// Try to find and take a token that was stored with the given server name
    ///
    /// The same token must never be returned from `take` twice, as doing so can be used to
    /// de-anonymize a client's traffic.
    ///
    /// Called when trying to connect to a server. It is always ok for this to return `None`.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}

/// Null implementation of [`TokenStore`], which does not store any tokens
pub struct NoneTokenStore;

impl TokenStore for NoneTokenStore {
    fn insert(&self, _: &str, _: Bytes) {}
    fn take(&self, _: &str) -> Option<Bytes> {
        None
    }
}

/// State in an `Incoming` determined by a token or lack thereof
#[derive(Debug)]
pub(crate) struct IncomingToken {
    pub(crate) retry_src_cid: Option<ConnectionId>,
    pub(crate) orig_dst_cid: ConnectionId,
    pub(crate) validated: bool,
}

impl IncomingToken {
    /// Construct for an `Incoming` given the first packet header, or error if the connection
    /// cannot be established
    pub(crate) fn from_header(
        header: &InitialHeader,
        server_config: &ServerConfig,
        remote_address: SocketAddr,
    ) -> Result<Self, InvalidRetryTokenError> {
        let unvalidated = Self {
            retry_src_cid: None,
            orig_dst_cid: header.dst_cid,
            validated: false,
        };

        // Decode token or short-circuit
        if header.token.is_empty() {
            return Ok(unvalidated);
        }

        // In cases where a token cannot be decrypted/decoded, we must allow for the possibility
        // that this is caused not by client malfeasance, but by the token having been generated by
        // an incompatible endpoint, e.g. a different version or a neighbor behind the same load
        // balancer. In such cases we proceed as if there was no token.
        //
        // [_RFC 9000 § 8.1.3:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3-10)
        //
        // > If the token is invalid, then the server SHOULD proceed as if the client did not have
        // > a validated address, including potentially sending a Retry packet.
        let Some(retry) = Token::decode(&*server_config.token_key, &header.token) else {
            return Ok(unvalidated);
        };

        // Validate token, then convert into Self
        match retry.payload {
            TokenPayload::Retry {
                address,
                orig_dst_cid,
                issued,
            } => {
                if address != remote_address {
                    return Err(InvalidRetryTokenError);
                }
                // An expiry the clock cannot represent cannot validate the token.
                if issued
                    .checked_add(server_config.retry_token_lifetime)
                    .is_none_or(|expiry| expiry < server_config.time_source.now())
                {
                    return Err(InvalidRetryTokenError);
                }

                Ok(Self {
                    retry_src_cid: Some(header.dst_cid),
                    orig_dst_cid,
                    validated: true,
                })
            }
            TokenPayload::Validation { ip, issued } => {
                if ip != remote_address.ip() {
                    return Ok(unvalidated);
                }
                if issued
                    .checked_add(server_config.validation_token.lifetime)
                    .is_none_or(|expiry| expiry < server_config.time_source.now())
                {
                    return Ok(unvalidated);
                }
                if server_config
                    .validation_token
                    .log
                    .check_and_insert(retry.nonce, issued, server_config.validation_token.lifetime)
                    .is_err()
                {
                    return Ok(unvalidated);
                }

                Ok(Self {
                    retry_src_cid: None,
                    orig_dst_cid: header.dst_cid,
                    validated: true,
                })
            }
        }
    }
}

/// Error for a token being unambiguously from a Retry packet, and not valid
///
/// The connection cannot be established.
pub(crate) struct InvalidRetryTokenError;

/// Retry or validation token
pub(crate) struct Token {
    /// Content that is encrypted from the client
    pub(crate) payload: TokenPayload,
    /// Randomly generated value, which must be unique, and is visible to the client
    nonce: u128,
}

impl Token {
    /// Construct with newly sampled randomness
    pub(crate) fn new(payload: TokenPayload, rng: &mut impl Rng) -> Self {
        Self {
            nonce: rng.random(),
            payload,
        }
    }

    /// Encode and encrypt
    ///
    /// Fails when the token key's provider cannot derive or seal with the per-token key.
    pub(crate) fn encode(&self, key: &dyn HandshakeTokenKey) -> Result<Vec<u8>, CryptoError> {
        let mut buf = Vec::new();

        // Encode payload
        match self.payload {
            TokenPayload::Retry {
                address,
                orig_dst_cid,
                issued,
            } => {
                buf.put_u8(TokenType::Retry as u8);
                encode_addr(&mut buf, address);
                orig_dst_cid.encode_long(&mut buf);
                encode_unix_secs(&mut buf, issued);
            }
            TokenPayload::Validation { ip, issued } => {
                buf.put_u8(TokenType::Validation as u8);
                encode_ip(&mut buf, ip);
                encode_unix_secs(&mut buf, issued);
            }
        }

        // Encrypt
        let aead_key = key.aead_from_hkdf(&self.nonce.to_le_bytes())?;
        aead_key.seal(&mut buf, &[])?;
        buf.extend(&self.nonce.to_le_bytes());

        Ok(buf)
    }

    /// Decode and decrypt
    fn decode(key: &dyn HandshakeTokenKey, raw_token_bytes: &[u8]) -> Option<Self> {
        // Decrypt: the nonce is the 16-byte tail; anything shorter is not a token.
        let (sealed_token, nonce_bytes) =
            raw_token_bytes.split_last_chunk::<{ size_of::<u128>() }>()?;
        let nonce = u128::from_le_bytes(*nonce_bytes);

        let aead_key = key.aead_from_hkdf(nonce_bytes).ok()?;
        let mut sealed_token = sealed_token.to_vec();
        let data = aead_key.open(&mut sealed_token, &[]).ok()?;

        // Decode payload
        let mut reader = &data[..];
        let payload = match TokenType::from_byte((&mut reader).get::<u8>().ok()?)? {
            TokenType::Retry => TokenPayload::Retry {
                address: decode_addr(&mut reader)?,
                orig_dst_cid: ConnectionId::decode_long(&mut reader)?,
                issued: decode_unix_secs(&mut reader)?,
            },
            TokenType::Validation => TokenPayload::Validation {
                ip: decode_ip(&mut reader)?,
                issued: decode_unix_secs(&mut reader)?,
            },
        };

        if !reader.is_empty() {
            // Consider extra bytes a decoding error (it may be from an incompatible endpoint)
            return None;
        }

        Some(Self { nonce, payload })
    }
}

/// Content of a [`Token`] that is encrypted from the client
pub(crate) enum TokenPayload {
    /// Token originating from a Retry packet
    Retry {
        /// The client's address
        address: SocketAddr,
        /// The destination connection ID set in the very first packet from the client
        orig_dst_cid: ConnectionId,
        /// The time at which this token was issued
        issued: SystemTime,
    },
    /// Token originating from a NEW_TOKEN frame
    Validation {
        /// The client's IP address (its port is likely to change between sessions)
        ip: IpAddr,
        /// The time at which this token was issued
        issued: SystemTime,
    },
}

/// Variant tag for a [`TokenPayload`]
#[derive(Copy, Clone)]
#[repr(u8)]
enum TokenType {
    Retry = 0,
    Validation = 1,
}

impl TokenType {
    fn from_byte(n: u8) -> Option<Self> {
        use TokenType::*;
        [Retry, Validation].into_iter().find(|ty| *ty as u8 == n)
    }
}

fn encode_addr(buf: &mut Vec<u8>, address: SocketAddr) {
    encode_ip(buf, address.ip());
    buf.put_u16(address.port());
}

fn decode_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = decode_ip(buf)?;
    let port = buf.get().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn encode_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(x) => {
            buf.put_u8(0);
            buf.put_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            buf.put_u8(1);
            buf.put_slice(&x.octets());
        }
    }
}

fn decode_ip<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    match buf.get::<u8>().ok()? {
        0 => buf.get().ok().map(IpAddr::V4),
        1 => buf.get().ok().map(IpAddr::V6),
        _ => None,
    }
}

fn encode_unix_secs(buf: &mut Vec<u8>, time: SystemTime) {
    buf.write::<u64>(
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
}

fn decode_unix_secs<B: Buf>(buf: &mut B) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::from_secs(buf.get::<u64>().ok()?))
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[expect(
    clippy::derived_hash_with_manual_eq,
    reason = "the manual PartialEq compares the same bytes the derived Hash uses"
)]
#[derive(Debug, Copy, Clone, Hash)]
pub(crate) struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &dyn HmacKey, id: ConnectionId) -> Self {
        let mut signature = vec![0; key.signature_len()];
        key.sign(&id, &mut signature);
        // TODO: Server ID??
        let mut result = [0; RESET_TOKEN_SIZE];
        result.copy_from_slice(&signature[..RESET_TOKEN_SIZE]);
        result.into()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        crate::proto::constant_time::eq(&self.0, &other.0)
    }
}

impl Eq for ResetToken {}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[cfg(any(feature = "aws-lc", feature = "ring"))]
mod test {
    use super::*;
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    use rama_crypto::dep::aws_lc_rs::hkdf;
    #[cfg(feature = "ring")]
    use rama_crypto::dep::ring::hkdf;

    fn token_round_trip(payload: TokenPayload) -> TokenPayload {
        let rng = &mut rand::rng();
        let token = Token::new(payload, rng);
        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);
        let encoded = token.encode(&prk).unwrap();
        let decoded = Token::decode(&prk, &encoded).expect("token didn't decrypt / decode");
        assert_eq!(token.nonce, decoded.nonce);
        decoded.payload
    }

    /// Known-answer test against an independent HMAC-SHA256 implementation (Python `hmac`):
    /// the reset token is the first 16 bytes of HMAC-SHA256(key, cid).
    #[test]
    fn reset_tokens_are_the_hmac_prefix_and_differ_per_key_and_cid() {
        use crate::proto::ConnectionId;
        let key_bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let other_key_bytes: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
        let key = hkdf_free_hmac(&key_bytes);
        let other_key = hkdf_free_hmac(&other_key_bytes);
        let cid = ConnectionId::new(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02]);
        let other_cid = ConnectionId::new(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x03]);

        // Expected values computed with Python's `hmac.new(key, cid, hashlib.sha256)`.
        const KEY_CID: [u8; 16] = [
            0xc2, 0x49, 0x21, 0xe6, 0xfe, 0xbf, 0x88, 0x04, 0x48, 0xcd, 0x52, 0x22, 0x00, 0x27,
            0x98, 0xe6,
        ];
        const KEY_OTHER_CID: [u8; 16] = [
            0x9a, 0x0a, 0x98, 0xc5, 0x5c, 0x52, 0x7a, 0x42, 0xc9, 0xae, 0x39, 0x83, 0x85, 0x23,
            0xf2, 0x38,
        ];
        const OTHER_KEY_CID: [u8; 16] = [
            0xc5, 0xf7, 0x14, 0xcc, 0x23, 0x28, 0x46, 0x1c, 0x20, 0x65, 0x56, 0x9b, 0x9d, 0x5a,
            0x23, 0xa7,
        ];
        let token = ResetToken::new(&key, cid);
        assert_eq!(
            &token[..],
            &KEY_CID[..],
            "independent HMAC-SHA256(key, cid) prefix"
        );
        assert_eq!(&ResetToken::new(&key, other_cid)[..], &KEY_OTHER_CID[..]);
        assert_eq!(&ResetToken::new(&other_key, cid)[..], &OTHER_KEY_CID[..]);
        // Equality follows the bytes, not the identity of the value.
        assert_eq!(token, ResetToken::new(&key, cid));
        assert_ne!(token, ResetToken::new(&key, other_cid));
        assert_ne!(token, ResetToken::new(&other_key, cid));
        let mut flipped = [0u8; RESET_TOKEN_SIZE];
        flipped.copy_from_slice(&token);
        flipped[15] ^= 0x80;
        assert_ne!(token, ResetToken::from(flipped));
        assert_eq!(token.to_string(), "c24921e6febf880448cd5222002798e6");
    }

    fn hkdf_free_hmac(key: &[u8]) -> impl HmacKey {
        #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
        use rama_crypto::dep::aws_lc_rs::hmac;
        #[cfg(feature = "ring")]
        use rama_crypto::dep::ring::hmac;
        hmac::Key::new(hmac::HMAC_SHA256, key)
    }

    #[test]
    fn truncated_or_corrupt_tokens_decode_to_none() {
        let rng = &mut rand::rng();
        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);
        let token = Token::new(
            TokenPayload::Validation {
                ip: std::net::Ipv4Addr::LOCALHOST.into(),
                issued: crate::proto::UNIX_EPOCH,
            },
            rng,
        );
        let encoded = token.encode(&prk).unwrap();
        // Shorter than the 16-byte nonce tail, exactly the tail, and every truncation.
        for len in 0..encoded.len() {
            assert!(
                Token::decode(&prk, &encoded[..len]).is_none(),
                "{len} of {} bytes must not decode",
                encoded.len()
            );
        }
        assert!(Token::decode(&prk, &[]).is_none());
        // One flipped bit anywhere fails authentication or the nonce derivation.
        for i in 0..encoded.len() {
            let mut corrupt = encoded.clone();
            corrupt[i] ^= 0x01;
            assert!(Token::decode(&prk, &corrupt).is_none(), "bit flip at {i}");
        }
        // Trailing bytes after a valid token are a decoding error.
        let mut extended = encoded.clone();
        extended.push(0);
        assert!(Token::decode(&prk, &extended).is_none());
        assert!(Token::decode(&prk, &encoded).is_some());
    }

    #[test]
    fn retry_token_sanity() {
        use crate::proto::MAX_CID_SIZE;
        use crate::proto::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::proto::{Duration, UNIX_EPOCH};

        use std::net::Ipv6Addr;

        let address_1 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let orig_dst_cid_1 = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let issued_1 = UNIX_EPOCH + Duration::from_secs(42); // Fractional seconds would be lost
        let payload_1 = TokenPayload::Retry {
            address: address_1,
            orig_dst_cid: orig_dst_cid_1,
            issued: issued_1,
        };
        let TokenPayload::Retry {
            address: address_2,
            orig_dst_cid: orig_dst_cid_2,
            issued: issued_2,
        } = token_round_trip(payload_1)
        else {
            panic!("token decoded as wrong variant");
        };

        assert_eq!(address_1, address_2);
        assert_eq!(orig_dst_cid_1, orig_dst_cid_2);
        assert_eq!(issued_1, issued_2);
    }

    #[test]
    fn validation_token_sanity() {
        use crate::proto::{Duration, UNIX_EPOCH};

        use std::net::Ipv6Addr;

        let ip_1 = Ipv6Addr::LOCALHOST.into();
        let issued_1 = UNIX_EPOCH + Duration::from_secs(42); // Fractional seconds would be lost

        let payload_1 = TokenPayload::Validation {
            ip: ip_1,
            issued: issued_1,
        };
        let TokenPayload::Validation {
            ip: ip_2,
            issued: issued_2,
        } = token_round_trip(payload_1)
        else {
            panic!("token decoded as wrong variant");
        };

        assert_eq!(ip_1, ip_2);
        assert_eq!(issued_1, issued_2);
    }

    #[test]
    fn invalid_token_returns_err() {
        let rng = &mut rand::rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(Token::decode(&prk, &invalid_token).is_none());
    }
}
