use rama_core::error::BoxError;
use rama_utils::macros::enums::enum_builder;

enum_builder! {
    /// Protocol version as defined by [RFC 1928].
    ///
    /// [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928
    @U8
    pub enum ProtocolVersion {
        Socks5 => 0x05,
    }
}

enum_builder! {
    /// Subnegotiation version as defined by [RFC 1929].
    ///
    /// [RFC 1929]: https://datatracker.ietf.org/doc/html/rfc1929#section-2
    @U8
    pub enum UsernamePasswordSubnegotiationVersion {
        One => 0x01,
    }
}

enum_builder! {
    /// Socks5 Method as defined by [IANA SOCKS Methods]
    ///
    /// [IANA SOCKS Methods]: https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
    @U8
    pub enum SocksMethod {
        /// No authentication required.
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
        NoAuthenticationRequired => 0x00,
        /// Generic Security Services Application Program Interface
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
        GSSAPI => 0x01,
        /// Username/Password Authentication for SOCKS V5
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1929)
        UsernamePassword => 0x02,
        /// Challenge-Handshake Authentication Protocol
        ///
        /// Reference: Marc VanHeyingen <mailto:marcvh@aventail.com>.
        ChallengeHandshakeAuthenticationProtocol => 0x03,
        /// Challenge-Response Authentication Method
        ///
        /// Reference: Marc VanHeyingen <mailto:marcvh@aventail.com>.
        ChallengeResponseAuthenticationMethod => 0x05,
        /// Secure Sockets Layer
        ///
        /// Reference: Marc VanHeyingen <mailto:marcvh@aventail.com>.
        SecureSocksLayer => 0x06,
        /// NDS Authentication
        ///
        /// Reference: Vijay Talati <mailto:VTalati@novell.com>.
        NDSAuthentication => 0x07,
        /// Multi-Authentication Framework
        ///
        /// Reference: Vijay Talati <mailto:VTalati@novell.com>.
        MultiAuthenticationFramework => 0x08,
        /// JSON Parameter Block
        ///
        /// Reference: Brandon Wiley <mailto:brandon@operatorfoundation.org>.
        JSONParameterBlock => 0x09,
        /// No acceptable methods.
        ///
        /// If the selected METHOD (by the server) is X'FF', none of the methods listed by the
        /// client are acceptable, and the client MUST close the connection.
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
        NoAcceptableMethods => 0xFF,
    }
}

enum_builder! {
    /// Request Command.
    ///
    /// Reference: <https://datatracker.ietf.org/doc/html/rfc1928#section-4>
    @U8
    pub enum Command {
        /// Request the server to establish a connection on behalf of the client
        /// with the destination address.
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
        Connect => 0x01,
        /// Used in protocols which require the client to accept connections from the server.
        ///
        /// FTP is a well-known example, which uses the primary client-to-server connection for commands and
        /// status reports, but may use a server-to-client connection for
        /// transferring data on demand (e.g. LS, GET, PUT).
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1928)
        Bind => 0x02,
        /// Used to establish an association within
        /// the UDP relay process to handle UDP datagrams.
        ///
        /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1929)
        UdpAssociate => 0x03,
    }
}

enum_builder! {
    /// Type of the address following it.
    ///
    /// Only used during encoding and decoding,
    /// but no use for the in-memory representation.
    ///
    /// Reference: <https://datatracker.ietf.org/doc/html/rfc1928>
    @U8
    pub enum AddressType {
        /// The address is a version-4 IP address, with a length of 4 octets.
        IpV4 => 0x01,
        /// The address is a length-prefixed (max 255 byte) domain name.
        ///
        /// The address field contains a fully-qualified domain name (FQDN). The first
        /// octet of the address field contains the number of octets of name that
        /// follow, there is no terminating NUL octet.
        DomainName => 0x03,
        /// The address is a version-6 IP address, with a length of 16 octets.
        IpV6 => 0x04,
    }
}

enum_builder! {
    /// Indicates success or failure as the reply to a client request.
    ///
    /// Reference: <https://datatracker.ietf.org/doc/html/rfc1928#section-6>
    @U8
    pub enum ReplyKind {
        Succeeded => 0x00,
        GeneralServerFailure => 0x01,
        ConnectionNotAllowed => 0x02,
        NetworkUnreachable => 0x03,
        HostUnreachable => 0x04,
        ConnectionRefused => 0x05,
        TtlExpired => 0x06,
        CommandNotSupported => 0x07,
        AddressTypeNotSupported => 0x08,
    }
}

impl From<&BoxError> for ReplyKind {
    fn from(err: &BoxError) -> Self {
        if let Some(err) = err.downcast_ref::<std::io::Error>() {
            match err.kind() {
                std::io::ErrorKind::PermissionDenied => Self::ConnectionNotAllowed,
                std::io::ErrorKind::HostUnreachable => Self::HostUnreachable,
                std::io::ErrorKind::NetworkUnreachable => Self::NetworkUnreachable,
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::UnexpectedEof => {
                    Self::TtlExpired
                }
                _ => Self::ConnectionRefused,
            }
        } else {
            Self::ConnectionRefused
        }
    }
}
