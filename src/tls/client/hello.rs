use crate::tls::{
    CipherSuite, ECPointFormat, ExtensionId, ProtocolVersion, SignatureScheme, SupportedGroup,
};

#[derive(Debug, Clone)]
pub struct ClientHello {
    cipher_suites: Vec<CipherSuite>,
    extensions: Vec<Extension>,
}

#[derive(Debug, Clone)]
struct Extension(ExtensionData);

#[derive(Debug, Clone)]
enum ExtensionData {
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
    ServerName(Vec<ServerName>),
    /// indicates which versions of TLS the client supports
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
    EcPointFormats(Vec<ECPointFormat>),
    /// Algorithms supported by the client for signing certificates.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SignatureAlgorithms(Vec<SignatureScheme>),
    /// Application Layer Protocol Negotation, often referred to as ALPN.
    ///
    /// Used to indicate the application layer protocols the client supports,
    /// e.g. h2 or h3. Allowing the server to immediately serve content
    /// using one of the supported protocols avoiding otherwise
    /// wasteful upgrade roundtrips.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc7301>
    ApplicationLayerProtocolNegotiation(ApplicationLayerProtocolNegotiationData),
    /// used by the client to indicate which versions of TLS it supports
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SupportedVersions(Vec<ProtocolVersion>),
    /// Any extension not supported by Rama,
    /// as it is still to be done or considered out of scope.
    Opaque { id: u16, data: Vec<u8> },
}

impl Extension {
    /// returns the [`ExtensionId`] which identifies this [`Extension`].
    pub fn id(&self) -> ExtensionId {
        match self.0 {
            ExtensionData::ServerName(_) => ExtensionId::SERVER_NAME,
            ExtensionData::SupportedGroups(_) => ExtensionId::SUPPORTED_GROUPS,
            ExtensionData::EcPointFormats(_) => ExtensionId::EC_POINT_FORMATS,
            ExtensionData::SignatureAlgorithms(_) => ExtensionId::SIGNATURE_ALGORITHMS,
            ExtensionData::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            ExtensionData::SupportedVersions(_) => ExtensionId::SUPPORTED_VERSIONS,
            ExtensionData::Opaque { id, .. } => ExtensionId::from(id),
        }
    }
}

#[derive(Debug, Clone)]
struct ServerNameData;

#[derive(Debug, Clone)]
struct ApplicationLayerProtocolNegotiationData;
