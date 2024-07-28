#[derive(Debug, Clone)]
pub struct ClientHello {
    cipher_suites: Vec<CipherSuite>,
    extensions: Vec<Extension>,
}

#[derive(Debug, Clone)]
struct CipherSuite;

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
    ServerName(ServerNameData),
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
    SupportedGroups(SupportedGroupsData),
    /// indicates the set of point formats that the client can parse
    ///
    /// For this extension, the opaque extension_data field contains ECPointFormatList.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8422>
    EcPointFormats(EcPointFormatsData),
    /// Algorithms supported by the client for signing certificates.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SignatureAlgorithms(SignatureAlgorithmsData),
    /// Algorithms supported by the client for signing certificates.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SignatureAlgorithmsCert(SignatureAlgorithmsCertData),
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
    /// allows the client to resume a session
    ///
    /// Resumption is supported by using this key previousy shared with the server
    /// in a previously established connection.
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    PreSharedKey(PreSharedKeyData),
    /// used by the client to indicate which versions of TLS it supports
    ///
    /// # Reference
    ///
    /// - <https://www.iana.org/go/rfc8446>
    SupportedVersions(SupportedVersionsData),
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
            ExtensionData::SignatureAlgorithmsCert(_) => ExtensionId::SIGNATURE_ALGORITHMS_CERT,
            ExtensionData::ApplicationLayerProtocolNegotiation(_) => {
                ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            ExtensionData::PreSharedKey(_) => ExtensionId::PRE_SHARED_KEY,
            ExtensionData::SupportedVersions(_) => ExtensionId::SUPPORTED_VERSIONS,
            ExtensionData::Opaque { id, .. } => ExtensionId::from(id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ExtensionId(u16);

impl ExtensionId {
    pub const SERVER_NAME: ExtensionId = ExtensionId(0);
    pub const MAX_FRAGMENT_LENGTH: ExtensionId = ExtensionId(1);
    pub const CLIENT_CERTIFICATE_URL: ExtensionId = ExtensionId(2);
    pub const TRUSTED_CA_KEYS: ExtensionId = ExtensionId(3);
    pub const TRUNCATED_HMAC: ExtensionId = ExtensionId(4);
    pub const STATUS_REQUEST: ExtensionId = ExtensionId(5);
    pub const USER_MAPPING: ExtensionId = ExtensionId(6);
    pub const CLIENT_AUTHZ: ExtensionId = ExtensionId(7);
    pub const SERVER_AUTHZ: ExtensionId = ExtensionId(8);
    pub const CERT_TYPE: ExtensionId = ExtensionId(9);
    pub const SUPPORTED_GROUPS: ExtensionId = ExtensionId(10);
    pub const EC_POINT_FORMATS: ExtensionId = ExtensionId(11);
    pub const SRP: ExtensionId = ExtensionId(12);
    pub const SIGNATURE_ALGORITHMS: ExtensionId = ExtensionId(13);
    pub const USE_SRTP: ExtensionId = ExtensionId(14);
    pub const HEARTBEAT: ExtensionId = ExtensionId(15);
    pub const APPLICATION_LAYER_PROTOCOL_NEGOTIATION: ExtensionId = ExtensionId(16);
    pub const STATUS_REQUEST_V2: ExtensionId = ExtensionId(17);
    pub const SIGNED_CERTIFICATE_TIMESTAMP: ExtensionId = ExtensionId(18);
    pub const CLIENT_CERTIFICATE_TYPE: ExtensionId = ExtensionId(19);
    pub const SERVER_CERTIFICATE_TYPE: ExtensionId = ExtensionId(20);
    pub const PADDING: ExtensionId = ExtensionId(21);
    pub const ENCRYPT_THEN_MAC: ExtensionId = ExtensionId(22);
    pub const EXTENDED_MASTER_SECRET: ExtensionId = ExtensionId(23);
    pub const TOKEN_BINDING: ExtensionId = ExtensionId(24);
    pub const CACHED_INFO: ExtensionId = ExtensionId(25);
    pub const TLS_LTS: ExtensionId = ExtensionId(26);
    pub const COMPRESS_CERTIFICATE: ExtensionId = ExtensionId(27);
    pub const RECORD_SIZE_LIMIT: ExtensionId = ExtensionId(28);
    pub const PWD_PROTECT: ExtensionId = ExtensionId(29);
    pub const PWD_CLEAR: ExtensionId = ExtensionId(30);
    pub const PASSWORD_SALT: ExtensionId = ExtensionId(31);
    pub const TICKET_PINNING: ExtensionId = ExtensionId(32);
    pub const TLS_CERT_WITH_EXTERN_PSK: ExtensionId = ExtensionId(33);
    pub const DELEGATED_CREDENTIAL: ExtensionId = ExtensionId(34);
    pub const SESSION_TICKET: ExtensionId = ExtensionId(35);
    pub const TLMSP: ExtensionId = ExtensionId(36);
    pub const TLMSP_PROXYING: ExtensionId = ExtensionId(37);
    pub const TLMSP_DELEGATE: ExtensionId = ExtensionId(38);
    pub const SUPPORTED_EKT_CIPHERS: ExtensionId = ExtensionId(39);
    pub const PRE_SHARED_KEY: ExtensionId = ExtensionId(41);
    pub const EARLY_DATA: ExtensionId = ExtensionId(42);
    pub const SUPPORTED_VERSIONS: ExtensionId = ExtensionId(43);
    pub const COOKIE: ExtensionId = ExtensionId(44);
    pub const PSK_KEY_EXCHANGE_MODES: ExtensionId = ExtensionId(45);
    pub const CERTIFICATE_AUTHORITIES: ExtensionId = ExtensionId(47);
    pub const OID_FILTERS: ExtensionId = ExtensionId(48);
    pub const POST_HANDSHAKE_AUTH: ExtensionId = ExtensionId(49);
    pub const SIGNATURE_ALGORITHMS_CERT: ExtensionId = ExtensionId(50);
    pub const KEY_SHARE: ExtensionId = ExtensionId(51);
    pub const TRANSPARENCY_INFO: ExtensionId = ExtensionId(52);
    pub const CONNECTION_ID: ExtensionId = ExtensionId(54);
    pub const EXTERNAL_ID_HASH: ExtensionId = ExtensionId(55);
    pub const EXTERNAL_SESSION_ID: ExtensionId = ExtensionId(56);
    pub const QUIC_TRANSPORT_PARAMETERS: ExtensionId = ExtensionId(57);
    pub const TICKET_REQUEST: ExtensionId = ExtensionId(58);
    pub const DNSSEC_CHAIN: ExtensionId = ExtensionId(59);
    pub const SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS: ExtensionId = ExtensionId(60);
    pub const RRC: ExtensionId = ExtensionId(61);
    pub const ECH_OUTER_EXTENSIONS: ExtensionId = ExtensionId(64768);
    pub const ENCRYPTED_CLIENT_HELLO: ExtensionId = ExtensionId(65037);
    pub const RENEGOTIATION_INFO: ExtensionId = ExtensionId(65281);

    /// return this [`ExtensionId`] as an `u16`
    pub fn as_u16(&self) -> u16 {
        self.0
    }
}

impl From<u16> for ExtensionId {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<ExtensionId> for u16 {
    fn from(value: ExtensionId) -> Self {
        value.0
    }
}

#[derive(Debug, Clone)]
struct ServerNameData;

#[derive(Debug, Clone)]
struct SupportedGroupsData;

#[derive(Debug, Clone)]
struct EcPointFormatsData;

#[derive(Debug, Clone)]
struct SignatureAlgorithmsData;

#[derive(Debug, Clone)]
struct SignatureAlgorithmsCertData;

#[derive(Debug, Clone)]
struct ApplicationLayerProtocolNegotiationData;

#[derive(Debug, Clone)]
struct PreSharedKeyData;

#[derive(Debug, Clone)]
struct SupportedVersionsData;
