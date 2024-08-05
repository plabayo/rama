use crate::{
    net::address::Domain,
    tls::{
        ApplicationProtocol, CipherSuite, ECPointFormat, ExtensionId, ProtocolVersion,
        SignatureScheme, SupportedGroup,
    },
};

mod rustls;

#[derive(Debug, Clone)]
/// When a client first connects to a server, it is required to send
/// the ClientHello as its first message.
///
/// The ClientHello contains random data, cipher suites,
/// legacy content from <= TLS.12 and extensions.
///
/// For Rama however we only focus on the parts which
/// a user might want to inspect and/or set.
pub struct ClientHello {
    cipher_suites: Vec<CipherSuite>,
    extensions: Vec<ClientHelloExtension>,
}

impl ClientHello {
    /// Return all [`CipherSuite`]s defined in this [`ClientHello`].
    pub fn cipher_suites(&self) -> &[CipherSuite] {
        &self.cipher_suites[..]
    }

    /// Return all [`ClientHelloExtension`]s defined in this [`ClientHello`].
    pub fn extensions(&self) -> &[ClientHelloExtension] {
        &self.extensions[..]
    }

    /// Return the server name (SNI) if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ServerName`] for more information about the server name.
    pub fn ext_server_name(&self) -> Option<&Domain> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ServerName(ref domain) = ext {
                return Some(domain);
            }
        }
        None
    }

    /// Return the elliptic curves supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::SupportedGroups`] for more information about these curves.
    pub fn ext_supported_groups(&self) -> Option<&[SupportedGroup]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::SupportedGroups(ref groups) = ext {
                return Some(&groups[..]);
            }
        }
        None
    }

    /// Return the EC point formats supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ECPointFormats`] for more information about this.
    pub fn ext_ec_point_formats(&self) -> Option<&[ECPointFormat]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ECPointFormats(ref formats) = ext {
                return Some(&formats[..]);
            }
        }
        None
    }

    /// Return the signature algorithms supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::SignatureAlgorithms`] for more information about these algorithms
    pub fn ext_signature_algorithms(&self) -> Option<&[SignatureScheme]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::SignatureAlgorithms(ref algos) = ext {
                return Some(&algos[..]);
            }
        }
        None
    }

    /// Return the application layer protocols supported for negotiation by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::ApplicationLayerProtocolNegotiation`] for more information about these protocols (ALPN).
    pub fn ext_alpn(&self) -> Option<&[ApplicationProtocol]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::ApplicationLayerProtocolNegotiation(ref alpns) = ext {
                return Some(&alpns[..]);
            }
        }
        None
    }

    /// Return the TLS versions supported by this client
    /// if it is set in the [`ClientHelloExtension`] defined in this [`ClientHello`].
    ///
    /// See [`ClientHelloExtension::SupportedVersions`] for more information about these versions
    pub fn supported_versions(&self) -> Option<&[ProtocolVersion]> {
        for ext in &self.extensions {
            if let ClientHelloExtension::SupportedVersions(ref versions) = ext {
                return Some(&versions[..]);
            }
        }
        None
    }
}

#[derive(Debug, Clone)]
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
    ServerName(Domain),
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
    /// used by the client to indicate which versions of TLS it supports
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SupportedVersions(Vec<ProtocolVersion>),
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
    pub fn id(&self) -> ExtensionId {
        match self {
            ClientHelloExtension::ServerName(_) => ExtensionId::SERVER_NAME,
            ClientHelloExtension::SupportedGroups(_) => ExtensionId::SUPPORTED_GROUPS,
            ClientHelloExtension::ECPointFormats(_) => ExtensionId::EC_POINT_FORMATS,
            ClientHelloExtension::SignatureAlgorithms(_) => ExtensionId::SIGNATURE_ALGORITHMS,
            ClientHelloExtension::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            ClientHelloExtension::SupportedVersions(_) => ExtensionId::SUPPORTED_VERSIONS,
            ClientHelloExtension::Opaque { id, .. } => *id,
        }
    }
}
