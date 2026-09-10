use std::{io, str, sync::Arc};

use rama_core::bytes::BytesMut;
#[cfg(all(feature = "aws-lc", not(feature = "ring")))]
use rama_crypto::dep::aws_lc_rs::aead;
#[cfg(feature = "ring")]
use rama_crypto::dep::ring::aead;
use rama_net::{address::Domain, tls::ApplicationProtocol};
use rama_tls_rustls::dep::rustls::{
    self,
    pki_types::ServerName,
    quic::{Connection, HeaderProtectionKey, KeyChange, PacketKey, Secrets, Suite, Version},
};
#[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
use rama_tls_rustls::dep::rustls::{
    CipherSuite,
    client::danger::ServerCertVerifier,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use crate::proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    crypto::{
        self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, UnsupportedVersion,
    },
    transport_parameters::TransportParameters,
};

/// The name to ask a server for, as the backend spells it. What it refuses is the name itself,
/// which the error carries back.
fn server_name_of(server_name: &str) -> Result<ServerName<'static>, ConnectError> {
    match ServerName::try_from(server_name) {
        Ok(name) => Ok(name.to_owned()),
        Err(_) => Err(ConnectError::InvalidServerName(server_name.into())),
    }
}

/// The name the backend reports, as a [`Domain`].
///
/// Every shape the backend accepts as a DNS name is one `Domain` accepts, so a name that
/// reached here is not rejected. A disagreement would be between this crate and its backend, so
/// it ends the connection locally rather than being reported as no name or blamed on the peer.
fn received_server_name(name: &str) -> Result<Domain, TransportError> {
    Domain::try_from(name).map_err(|error| {
        TransportError::INTERNAL_ERROR("received server name is not a domain").with_cause(error)
    })
}

impl From<Side> for rama_tls_rustls::dep::rustls::Side {
    fn from(s: Side) -> Self {
        match s {
            Side::Client => Self::Client,
            Side::Server => Self::Server,
        }
    }
}

mod config;
pub use config::{AlpnPolicy, TlsConfigError, TlsOptions};

/// A rustls TLS session
pub(crate) struct TlsSession {
    alpn_policy: AlpnPolicy,
    version: Version,
    got_handshake_data: bool,
    /// The name the peer asked for, converted once when the backend first has it.
    server_name: Option<Domain>,
    next_secrets: Option<Secrets>,
    inner: Connection,
    suite: Suite,
}

impl TlsSession {
    fn side(&self) -> Side {
        match self.inner {
            Connection::Client(_) => Side::Client,
            Connection::Server(_) => Side::Server,
        }
    }
}

impl crypto::Session for TlsSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        initial_keys(self.version, *dst_cid, side, &self.suite)
    }

    #[cfg(test)]
    fn negotiated_key_exchange_group(&self) -> Option<u16> {
        self.inner
            .negotiated_key_exchange_group()
            .map(|group| u16::from(group.name()))
    }

    fn handshake_summary(&self) -> Option<crate::proto::crypto::HandshakeSummary> {
        if !self.got_handshake_data {
            return None;
        }
        Some(crate::proto::crypto::HandshakeSummary {
            // Read afresh: the protocol can still be settling when the name is already known.
            protocol: self.inner.alpn_protocol().map(ApplicationProtocol::from),
            server_name: self.server_name.clone(),
        })
    }

    fn peer_certificates(&self) -> Option<Vec<rama_crypto::pki_types::CertificateDer<'static>>> {
        Some(
            self.inner
                .peer_certificates()?
                .iter()
                .map(|certificate| certificate.clone().into_owned())
                .collect(),
        )
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let keys = self.inner.zero_rtt_keys()?;
        Some((Box::new(keys.header), Box::new(keys.packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        match self.inner {
            Connection::Client(ref session) => Some(session.is_early_data_accepted()),
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_hs(buf).map_err(|e| {
            if let Some(alert) = self.inner.alert() {
                TransportError {
                    code: TransportErrorCode::crypto(alert.into()),
                    frame: None,
                    reason: e.to_string().into(),
                    cause: Some(rama_core::error::ArcError::new(e)),
                }
            } else {
                TransportError::PROTOCOL_VIOLATION(format!("TLS error: {e}"))
            }
        })?;
        if !self.inner.is_handshaking()
            && self.alpn_policy == AlpnPolicy::Require
            && self.inner.alpn_protocol().is_none()
        {
            return Err(TransportError::new(
                TransportErrorCode::crypto(0x78),
                "TLS handshake completed without an application protocol",
            ));
        }
        if !self.got_handshake_data {
            // Hack around the lack of an explicit signal from rustls to reflect ClientHello being
            // ready on incoming connections, or ALPN negotiation completing on outgoing
            // connections.
            let have_server_name = match self.inner {
                Connection::Client(_) => false,
                Connection::Server(ref session) => session.server_name().is_some(),
            };
            if self.inner.alpn_protocol().is_some() || have_server_name || !self.is_handshaking() {
                if let Connection::Server(ref session) = self.inner
                    && let Some(name) = session.server_name()
                {
                    self.server_name = Some(received_server_name(name)?);
                }
                self.got_handshake_data = true;
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        match self.inner.quic_transport_parameters() {
            None => Ok(None),
            Some(buf) => match TransportParameters::read(self.side(), &mut io::Cursor::new(buf)) {
                Ok(params) => Ok(Some(params)),
                Err(e) => Err(e.into()),
            },
        }
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        let keys = match self.inner.write_hs(buf)? {
            KeyChange::Handshake { keys } => keys,
            KeyChange::OneRtt { keys, next } => {
                self.next_secrets = Some(next);
                keys
            }
        };

        Some(Keys {
            header: KeyPair {
                local: Box::new(keys.local.header),
                remote: Box::new(keys.remote.header),
            },
            packet: KeyPair {
                local: Box::new(keys.local.packet),
                remote: Box::new(keys.remote.packet),
            },
        })
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn crypto::PacketKey>>> {
        let secrets = self.next_secrets.as_mut()?;
        let keys = secrets.next_packet_keys();
        Some(KeyPair {
            local: Box::new(keys.local),
            remote: Box::new(keys.remote),
        })
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let (nonce, key) = match self.version {
            Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
            Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
            #[expect(
                clippy::unreachable,
                reason = "`interpret_version` only produces `V1` and `V1Draft`; the wildcard exists because rustls marks `Version` non-exhaustive"
            )]
            _ => unreachable!(),
        };

        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        #[expect(
            clippy::unwrap_used,
            reason = "the Retry integrity keys are 16-byte constants"
        )]
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        // The backend fails this only for an output length it cannot serve, which is what
        // this error says.
        if self
            .inner
            .export_keying_material(output, label, Some(context))
            .is_err()
        {
            return Err(ExportKeyingMaterialError);
        }
        Ok(())
    }
}

const RETRY_INTEGRITY_KEY_DRAFT: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE_DRAFT: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];

const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

impl crypto::HeaderKey for Box<dyn HeaderProtectionKey> {
    #[expect(
        clippy::unwrap_used,
        reason = "the sample has `sample_size()` bytes and the first byte plus at most four packet-number bytes are the only inputs rustls checks"
    )]
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.decrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    #[expect(
        clippy::unwrap_used,
        reason = "the sample has `sample_size()` bytes and the first byte plus at most four packet-number bytes are the only inputs rustls checks"
    )]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.encrypt_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
        )
        .unwrap();
    }

    fn sample_size(&self) -> usize {
        self.sample_len()
    }
}

/// A QUIC-compatible TLS client configuration
///
/// A `QuicClientConfig` with reasonable defaults is constructed implicitly within
/// [`ClientConfig::with_root_certificates()`][root_certs].
/// Alternatively, `QuicClientConfig`'s [`TryFrom`] implementation can be used to wrap around a
/// custom [`rama_tls_rustls::dep::rustls::ClientConfig`], in which case care should be taken around certain points:
///
/// - If `enable_early_data` is not set to true, then sending 0-RTT data will not be possible on
///   outgoing connections.
/// - The [`rama_tls_rustls::dep::rustls::ClientConfig`] must have TLS 1.3 support enabled for conversion to succeed.
///
/// The object in the `resumption` field of the inner [`rama_tls_rustls::dep::rustls::ClientConfig`] determines whether
/// calling `into_0rtt` on outgoing connections returns `Ok` or `Err`. It typically allows
/// `into_0rtt` to proceed if it recognizes the server name, and defaults to an in-memory cache of
/// 256 server names.
///
/// [root_certs]: crate::proto::config::ClientConfig::with_root_certificates()
pub(crate) struct QuicClientConfig {
    alpn_policy: AlpnPolicy,
    pub(crate) inner: Arc<rama_tls_rustls::dep::rustls::ClientConfig>,
    initial: Suite,
}

impl QuicClientConfig {
    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Initialize a sane QUIC-compatible TLS client configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled. Advanced users can use any [`rama_tls_rustls::dep::rustls::ClientConfig`] that
    /// satisfies this requirement.
    #[expect(
        clippy::expect_used,
        reason = "`inner` is built on `configured_provider()`, whose ring and aws-lc defaults include TLS13_AES_128_GCM_SHA256"
    )]
    pub(crate) fn new(verifier: Arc<dyn ServerCertVerifier>) -> Self {
        let inner = Self::inner(verifier);
        Self {
            alpn_policy: AlpnPolicy::OutOfBandAgreement,
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.crypto_provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        }
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub(crate) fn with_initial(
        inner: Arc<rama_tls_rustls::dep::rustls::ClientConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self {
                inner,
                initial,
                alpn_policy: AlpnPolicy::OutOfBandAgreement,
            }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    pub(crate) fn inner(
        verifier: Arc<dyn ServerCertVerifier>,
    ) -> rama_tls_rustls::dep::rustls::ClientConfig {
        #[expect(
            clippy::unwrap_used,
            reason = "the configured providers support TLS 1.3"
        )]
        let mut config = rama_tls_rustls::dep::rustls::ClientConfig::builder_with_provider(
            configured_provider(),
        )
        .with_protocol_versions(&[&rama_tls_rustls::dep::rustls::version::TLS13])
        .unwrap() // The default providers support TLS 1.3
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

        config.enable_early_data = true;
        config
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        Ok(Box::new(TlsSession {
            alpn_policy: self.alpn_policy,
            version,
            got_handshake_data: false,
            server_name: None,
            next_secrets: None,
            inner: rama_tls_rustls::dep::rustls::quic::Connection::Client(
                rama_tls_rustls::dep::rustls::quic::ClientConnection::new(
                    self.inner.clone(),
                    version,
                    server_name_of(server_name)?,
                    to_vec(params),
                )
                .map_err(|error| ConnectError::Crypto(session_error(error)))?,
            ),
            suite: self.initial,
        }))
    }
}

impl TryFrom<rama_tls_rustls::dep::rustls::ClientConfig> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rama_tls_rustls::dep::rustls::ClientConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rama_tls_rustls::dep::rustls::ClientConfig>> for QuicClientConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(
        inner: Arc<rama_tls_rustls::dep::rustls::ClientConfig>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            alpn_policy: AlpnPolicy::OutOfBandAgreement,
            initial: initial_suite_from_provider(inner.crypto_provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

/// The initial cipher suite (AES-128-GCM-SHA256) is not available
///
/// A configuration built with its own initial cipher suite must use
/// `TLS13_AES_128_GCM_SHA256`. When the cipher suite is derived from a config's
/// [`CryptoProvider`][provider], that provider must reference a cipher suite with the same ID.
///
/// [provider]: rama_tls_rustls::dep::rustls::crypto::CryptoProvider
#[derive(Clone, Debug)]
pub struct NoInitialCipherSuite {
    /// Whether the initial cipher suite was supplied by the caller
    specific: bool,
}

impl std::fmt::Display for NoInitialCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self.specific {
            true => "invalid cipher suite specified",
            false => "no initial cipher suite found",
        })
    }
}

impl std::error::Error for NoInitialCipherSuite {}

/// A QUIC-compatible TLS server configuration
///
/// A `QuicServerConfig` with reasonable defaults is constructed implicitly within
/// [`ServerConfig::with_single_cert()`][single]. Alternatively, `QuicServerConfig`'s [`TryFrom`]
/// implementation or `with_initial` method can be used to wrap around a custom
/// [`rama_tls_rustls::dep::rustls::ServerConfig`], in which case care should be taken around certain points:
///
/// - If `max_early_data_size` is not set to `u32::MAX`, the server will not be able to accept
///   incoming 0-RTT data. QUIC prohibits `max_early_data_size` values other than 0 or `u32::MAX`.
/// - The `rama_tls_rustls::dep::rustls::ServerConfig` must have TLS 1.3 support enabled for conversion to succeed.
///
/// [single]: crate::proto::config::ServerConfig::with_single_cert()
pub(crate) struct QuicServerConfig {
    alpn_policy: AlpnPolicy,
    inner: Arc<rama_tls_rustls::dep::rustls::ServerConfig>,
    initial: Suite,
}

impl QuicServerConfig {
    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    #[expect(
        clippy::expect_used,
        reason = "`inner` is built on `configured_provider()`, whose ring and aws-lc defaults include TLS13_AES_128_GCM_SHA256"
    )]
    pub(crate) fn new(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, rama_tls_rustls::dep::rustls::Error> {
        let inner = Self::inner(cert_chain, key)?;
        Ok(Self {
            alpn_policy: AlpnPolicy::OutOfBandAgreement,
            // We're confident that the *ring* default provider contains TLS13_AES_128_GCM_SHA256
            initial: initial_suite_from_provider(inner.crypto_provider())
                .expect("no initial cipher suite found"),
            inner: Arc::new(inner),
        })
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Initialize a QUIC-compatible TLS client configuration with a separate initial cipher suite
    ///
    /// This is useful if you want to avoid the initial cipher suite for traffic encryption.
    pub(crate) fn with_initial(
        inner: Arc<rama_tls_rustls::dep::rustls::ServerConfig>,
        initial: Suite,
    ) -> Result<Self, NoInitialCipherSuite> {
        match initial.suite.common.suite {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => Ok(Self {
                inner,
                initial,
                alpn_policy: AlpnPolicy::OutOfBandAgreement,
            }),
            _ => Err(NoInitialCipherSuite { specific: true }),
        }
    }

    #[cfg(all(test, feature = "rustls", any(feature = "aws-lc", feature = "ring")))]
    /// Initialize a sane QUIC-compatible TLS server configuration
    ///
    /// QUIC requires that TLS 1.3 be enabled, and that the maximum early data size is either 0 or
    /// `u32::MAX`. Advanced users can use any [`rama_tls_rustls::dep::rustls::ServerConfig`] that satisfies these
    /// requirements.
    pub(crate) fn inner(
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<rama_tls_rustls::dep::rustls::ServerConfig, rama_tls_rustls::dep::rustls::Error>
    {
        #[expect(
            clippy::unwrap_used,
            reason = "the configured providers support TLS 1.3"
        )]
        let mut inner = rama_tls_rustls::dep::rustls::ServerConfig::builder_with_provider(
            configured_provider(),
        )
        .with_protocol_versions(&[&rama_tls_rustls::dep::rustls::version::TLS13])
        .unwrap() // The *ring* default provider supports TLS 1.3
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;

        inner.max_early_data_size = u32::MAX;
        Ok(inner)
    }
}

impl TryFrom<rama_tls_rustls::dep::rustls::ServerConfig> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(inner: rama_tls_rustls::dep::rustls::ServerConfig) -> Result<Self, Self::Error> {
        Arc::new(inner).try_into()
    }
}

impl TryFrom<Arc<rama_tls_rustls::dep::rustls::ServerConfig>> for QuicServerConfig {
    type Error = NoInitialCipherSuite;

    fn try_from(
        inner: Arc<rama_tls_rustls::dep::rustls::ServerConfig>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            alpn_policy: AlpnPolicy::OutOfBandAgreement,
            initial: initial_suite_from_provider(inner.crypto_provider())
                .ok_or(NoInitialCipherSuite { specific: false })?,
            inner,
        })
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, TransportError> {
        let Ok(version) = interpret_version(version) else {
            // The only thing that fails here is the version, which the reason names.
            return Err(TransportError::INTERNAL_ERROR("unsupported QUIC version"));
        };
        Ok(Box::new(TlsSession {
            alpn_policy: self.alpn_policy,
            version,
            got_handshake_data: false,
            server_name: None,
            next_secrets: None,
            inner: rama_tls_rustls::dep::rustls::quic::Connection::Server(
                rama_tls_rustls::dep::rustls::quic::ServerConnection::new(
                    self.inner.clone(),
                    version,
                    to_vec(params),
                )
                .map_err(session_error)?,
            ),
            suite: self.initial,
        }))
    }

    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = interpret_version(version)?;
        Ok(initial_keys(version, *dst_cid, Side::Server, &self.initial))
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Safe: `start_session()` is never called if `initial_keys()` rejected `version`
        #[expect(
            clippy::unwrap_used,
            reason = "`initial_keys` rejected unsupported versions before the endpoint calls this with the same version"
        )]
        let version = interpret_version(version).unwrap();
        let (nonce, key) = match version {
            Version::V1 => (RETRY_INTEGRITY_NONCE_V1, RETRY_INTEGRITY_KEY_V1),
            Version::V1Draft => (RETRY_INTEGRITY_NONCE_DRAFT, RETRY_INTEGRITY_KEY_DRAFT),
            #[expect(
                clippy::unreachable,
                reason = "`interpret_version` only produces `V1` and `V1Draft`; the wildcard exists because rustls marks `Version` non-exhaustive"
            )]
            _ => unreachable!(),
        };

        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        #[expect(
            clippy::unwrap_used,
            reason = "the Retry integrity keys are 16-byte constants"
        )]
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());

        #[expect(
            clippy::unwrap_used,
            reason = "sealing an empty in-place buffer with AAD cannot fail for a valid key"
        )]
        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

pub(crate) fn initial_suite_from_provider(
    provider: &Arc<rama_tls_rustls::dep::rustls::crypto::CryptoProvider>,
) -> Option<Suite> {
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rama_tls_rustls::dep::rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(suite)) => {
                Some(suite.quic_suite())
            }
            _ => None,
        })
        .flatten()
}

pub(crate) fn configured_provider() -> Arc<rama_tls_rustls::dep::rustls::crypto::CryptoProvider> {
    #[cfg(all(feature = "aws-lc", not(feature = "ring")))]
    let provider = rama_tls_rustls::dep::rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "ring")]
    let provider = rama_tls_rustls::dep::rustls::crypto::ring::default_provider();
    Arc::new(provider)
}

fn to_vec(params: &TransportParameters) -> Vec<u8> {
    let mut bytes = Vec::new();
    params.write(&mut bytes);
    bytes
}

pub(crate) fn initial_keys(
    version: Version,
    dst_cid: ConnectionId,
    side: Side,
    suite: &Suite,
) -> Keys {
    let keys = suite.keys(&dst_cid, side.into(), version);
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}

impl crypto::PacketKey for Box<dyn PacketKey> {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        #[expect(
            clippy::unwrap_used,
            reason = "`payload` excludes the `tag_len()` bytes the caller reserved, so rustls always has room for the tag"
        )]
        let tag = self.encrypt_in_place(packet, &*header, payload).unwrap();
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        // The backend reports only that it failed, which is all `CryptoError` says.
        let Ok(plain) = self.decrypt_in_place(packet, header, payload.as_mut()) else {
            return Err(CryptoError);
        };
        let plain_len = plain.len();
        payload.truncate(plain_len);
        Ok(())
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

fn interpret_version(version: u32) -> Result<Version, UnsupportedVersion> {
    match version {
        0xff00_001d..=0xff00_0020 => Ok(Version::V1Draft),
        0x0000_0001 | 0xff00_0021..=0xff00_0022 => Ok(Version::V1),
        _ => Err(UnsupportedVersion),
    }
}

fn session_error(error: rustls::Error) -> TransportError {
    TransportError::INTERNAL_ERROR("initialize TLS session").with_cause(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_tls_rustls::dep::rustls::pki_types::DnsName;

    /// The contract the handshake summary rests on: a name this backend validated as a DNS name
    /// reads as a domain. Rustls checks label shape, length and the 253-octet total, and a
    /// domain's rules are no stricter. Each of these has to be accepted by both, so a backend
    /// that started rejecting them would fail here rather than pass quietly.
    #[test]
    fn a_name_the_backend_accepts_is_a_domain() {
        let long_label = "a".repeat(63);
        let long_name = format!("{long_label}.{long_label}.{long_label}.{}", "a".repeat(61));
        let accepted = [
            "localhost",
            "example.com",
            "EXAMPLE.com",
            "sub.example.com.",
            "under_score.example.com",
            "1.2.3.example.com",
            "xn--bcher-kva.example",
            "a",
            "a-b.example",
            long_label.as_str(),
            long_name.as_str(),
        ];
        for name in accepted {
            let validated = DnsName::try_from(name)
                .unwrap_or_else(|error| panic!("the backend accepts {name:?}: {error}"));
            let seen = received_server_name(validated.as_ref())
                .unwrap_or_else(|error| panic!("the backend accepts {name:?}: {error}"));
            assert_eq!(seen.as_str(), validated.as_ref(), "and it keeps its text");
        }
    }

    /// The other side of that boundary: what the backend refuses never reaches the adapter, and
    /// this says which shapes those are. An IP address is among them, which is why a client
    /// connecting to one sends no SNI at all (RFC 6066 §3).
    #[test]
    fn the_backend_refuses_what_is_not_a_dns_name() {
        let too_long = format!("{}.example", "a".repeat(250));
        let refused = [
            "",
            // A label of digits alone is refused, which is how a bare number and an address are
            // kept out of a name.
            "9",
            "127.0.0.1",
            "::1",
            "exa mple.com",
            "example..com",
            too_long.as_str(),
        ];
        for name in refused {
            assert!(
                DnsName::try_from(name).is_err(),
                "the backend refuses {name:?}"
            );
        }
    }

    /// If this crate and its backend ever disagreed about a name, the connection would end on a
    /// local error rather than reporting no name at all. The input here is one the backend
    /// would itself have refused.
    #[test]
    fn a_name_that_is_not_a_domain_is_a_local_error() {
        let refused = received_server_name("").expect_err("an empty name is not a domain");
        assert_eq!(refused.code(), TransportErrorCode::INTERNAL_ERROR);
        assert_eq!(refused.reason(), "received server name is not a domain");
        assert!(
            refused.cause().is_some(),
            "and it keeps what the conversion said"
        );
    }
}
