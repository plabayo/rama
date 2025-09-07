use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::address::Domain;
use crate::tls::enums::{
    AuthenticatedEncryptionWithAssociatedData, CertificateCompressionAlgorithm,
    KeyDerivationFunction,
};
use crate::tls::{
    ApplicationProtocol, CipherSuite, ECPointFormat, ExtensionId, ProtocolVersion, SignatureScheme,
    SupportedGroup, enums::CompressionAlgorithm,
};

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// When a client first connects to a server, it is required to send
/// the ClientHello as its first message.
///
/// The ClientHello contains random data, cipher suites,
/// legacy content from <= TLS.12 and extensions.
///
/// For Rama however we only focus on the parts which
/// a user might want to inspect and/or set.
pub struct ClientHello {
    pub(super) protocol_version: ProtocolVersion,
    pub(super) cipher_suites: Vec<CipherSuite>,
    pub(super) compression_algorithms: Vec<CompressionAlgorithm>,
    pub(super) extensions: Vec<ClientHelloExtension>,
}

impl ClientHello {
    #[must_use]
    pub fn new(
        protocol_version: ProtocolVersion,
        cipher_suites: Vec<CipherSuite>,
        compression_algorithms: Vec<CompressionAlgorithm>,
        extensions: Vec<ClientHelloExtension>,
    ) -> Self {
        Self {
            protocol_version,
            cipher_suites,
            compression_algorithms,
            extensions,
        }
    }

    /// Return all [`ProtocolVersion`]s defined in this [`ClientHello`].
    #[must_use]
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return all [`CipherSuite`]s defined in this [`ClientHello`].
    #[must_use]
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites[..]
    }

    /// Return all [`CompressionAlgorithm`]s defined in this [`ClientHello`].
    #[must_use]
    pub fn compression_algorithms(&self) -> &[CompressionAlgorithm] {
        &self.compression_algorithms[..]
    }

    /// Return all [`ClientHelloExtension`]s defined in this [`ClientHello`].
    #[must_use]
    pub fn extensions(&self) -> &[ClientHelloExtension] {
        &self.extensions[..]
    }

    /// Return the server name (SNI) if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ServerName`] for more information about the server name.
    #[must_use]
    pub fn ext_server_name(&self) -> Option<&Domain> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ServerName(domain) = ext {
                return domain.as_ref();
            }
        }
        None
    }

    /// Return the elliptic curves supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::SupportedGroups`] for more information about these curves.
    #[must_use]
    pub fn ext_supported_groups(&self) -> Option<&[SupportedGroup]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::SupportedGroups(groups) = ext {
                return Some(&groups[..]);
            }
        }
        None
    }

    /// Return the EC point formats supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ECPointFormats`] for more information about this.
    #[must_use]
    pub fn ext_ec_point_formats(&self) -> Option<&[ECPointFormat]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ECPointFormats(formats) = ext {
                return Some(&formats[..]);
            }
        }
        None
    }

    /// Return the signature algorithms supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::SignatureAlgorithms`] for more information about these algorithms
    #[must_use]
    pub fn ext_signature_algorithms(&self) -> Option<&[SignatureScheme]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::SignatureAlgorithms(algos) = ext {
                return Some(&algos[..]);
            }
        }
        None
    }

    /// Return the application layer protocols supported for negotiation by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ApplicationLayerProtocolNegotiation`] for more information about these protocols (ALPN).
    #[must_use]
    pub fn ext_alpn(&self) -> Option<&[ApplicationProtocol]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ApplicationLayerProtocolNegotiation(alpns) = ext {
                return Some(&alpns[..]);
            }
        }
        None
    }

    /// Return the application layer protocols for which alps is supported
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ApplicationSettings`] for more information about these protocols (ALPS).
    #[must_use]
    pub fn ext_alps(&self) -> Option<&[ApplicationProtocol]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ApplicationSettings(alpns) = ext {
                return Some(&alpns[..]);
            }
        }
        None
    }

    /// Return the TLS versions supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::SupportedVersions`] for more information about these versions
    #[must_use]
    pub fn supported_versions(&self) -> Option<&[ProtocolVersion]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::SupportedVersions(versions) = ext {
                return Some(&versions[..]);
            }
        }
        None
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// Extensions that can be set in a [`ClientHello`] message by a TLS client.
///
/// While its name may infer that an extension is by definition optional,
/// you would be wrong to think so. These extensions are also used
/// to fill historical gaps in the TLS specifications and as a consequence
/// there are a couple of extensions that are pretty much in any [`ClientHello`] message.
///
/// Most of the defined variants of this _enum_ are examples of such "required" extensions.
/// Extensions like [`ClientHelloExtension::ApplicationLayerProtocolNegotiation`]
/// are not required but due to benefits it offers it also is pretty much always present,
/// as it helps save application negotiation roundtrips;
pub enum ClientHelloExtension {
    /// name of the server the client intends to connect to
    ///
    /// TLS does not provide a mechanism for a client to tell a server the
    /// name of the server it is contacting. It may be desirable for clients
    /// to provide this information to facilitate secure connections to
    /// servers that host multiple 'virtual' servers at a single underlying
    /// network address.
    ///
    /// In order to provide any of the server names, clients MAY include an
    /// extension of type "server_name" in the (extended) client hello.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc6066>
    /// - <https://www.iana.org/go/rfc9261>
    ServerName(Option<Domain>),
    /// indicates which elliptic curves the client supports
    ///
    /// This extension is required... despite being an extension.
    ///
    /// Renamed from EllipticCurves, which some material might still reference it as.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8422>
    /// - <https://www.iana.org/go/rfc7919>
    SupportedGroups(Vec<SupportedGroup>),
    /// indicates the set of point formats that the client can parse
    ///
    /// For this extension, the opaque extension_data field contains ECPointFormatList.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8422>
    ECPointFormats(Vec<ECPointFormat>),
    /// Algorithms supported by the client for signing certificates.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SignatureAlgorithms(Vec<SignatureScheme>),
    /// Application Layer Protocol Negotiation, often referred to as ALPN.
    ///
    /// Used to indicate the application layer protocols the client supports,
    /// e.g. h2 or h3. Allowing the server to immediately serve content
    /// using one of the supported protocols avoiding otherwise
    /// wasteful upgrade roundtrips.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc7301>
    ApplicationLayerProtocolNegotiation(Vec<ApplicationProtocol>),
    /// Used by the client for negotiating application-layer protocol settings (ALPS)
    /// within the TLS handshake.
    /// Through doing that, the settings can be made available to the application
    /// as soon as the handshake completes, and can be associated with TLS session
    /// tickets automatically at the TLS layer.
    ///
    /// # Reference
    ///
    /// - <https://www.ietf.org/archive/id/draft-vvv-tls-alps-01.html>
    ApplicationSettings(Vec<ApplicationProtocol>),
    /// used by the client to indicate which versions of TLS it supports
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SupportedVersions(Vec<ProtocolVersion>),
    /// The algorithm used to compress the certificate.
    ///
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/rfc8879>
    CertificateCompression(Vec<CertificateCompressionAlgorithm>),
    /// The maximum size of a record.
    ///
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/rfc8449>
    RecordSizeLimit(u16),
    /// Delegated credentials
    ///
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/rfc9345>
    DelegatedCredentials(Vec<SignatureScheme>),
    /// Encrypted hello send by the client
    /// # Reference
    ///
    /// - <https://datatracker.ietf.org/doc/html/draft-ietf-tls-esni/>
    EncryptedClientHello(ECHClientHello),
    /// Any extension not supported by Rama,
    /// as it is still to be done or considered out of scope.
    Opaque {
        /// extension id
        id: ExtensionId,
        /// extension data
        data: Vec<u8>,
    },
}

impl ClientHelloExtension {
    /// returns the [`ExtensionId`] which identifies this [`ClientHelloExtension`].
    #[must_use]
    pub fn id(&self) -> ExtensionId {
        match self {
            Self::ServerName(_) => ExtensionId::SERVER_NAME,
            Self::SupportedGroups(_) => ExtensionId::SUPPORTED_GROUPS,
            Self::ECPointFormats(_) => ExtensionId::EC_POINT_FORMATS,
            Self::SignatureAlgorithms(_) => ExtensionId::SIGNATURE_ALGORITHMS,
            Self::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            Self::ApplicationSettings(_) => ExtensionId::APPLICATION_SETTINGS,
            Self::SupportedVersions(_) => ExtensionId::SUPPORTED_VERSIONS,
            Self::CertificateCompression(_) => ExtensionId::COMPRESS_CERTIFICATE,
            Self::DelegatedCredentials(_) => ExtensionId::DELEGATED_CREDENTIAL,
            Self::RecordSizeLimit(_) => ExtensionId::RECORD_SIZE_LIMIT,
            Self::EncryptedClientHello(_) => ExtensionId::ENCRYPTED_CLIENT_HELLO,
            Self::Opaque { id, .. } => *id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// Client Hello contents send by ech
pub enum ECHClientHello {
    /// Send when message is in the outer (unencrypted) part of client hello. It contains
    /// encryption data and the encrypted client hello.
    Outer(ECHClientHelloOuter),
    /// The inner extension has an empty payload, which is included because TLS servers are
    /// not allowed to provide extensions in ServerHello which were not included in ClientHello.
    /// And when using encrypted client hello the server will discard the outer unencrypted one,
    /// and only look at the encrypted client hello. So we have to add this extension again there so
    /// the server knows ECH is supported by the client.
    Inner,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// Data send by ech hello message when it is in the outer part
pub struct ECHClientHelloOuter {
    pub cipher_suite: HpkeSymmetricCipherSuite,
    pub config_id: u8,
    pub enc: Vec<u8>,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
/// HPKE KDF and AEAD pair used to encrypt ClientHello
pub struct HpkeSymmetricCipherSuite {
    pub kdf_id: KeyDerivationFunction,
    pub aead_id: AuthenticatedEncryptionWithAssociatedData,
}

impl Display for HpkeSymmetricCipherSuite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},{}", self.kdf_id, self.aead_id)
    }
}
