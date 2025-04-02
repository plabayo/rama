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
