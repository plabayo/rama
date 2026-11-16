use super::{TlsCapture, TlsCapturedExtension, TlsCapturedExtensionValue as Value};
use rama_tls::{CipherSuite, ExtensionId, ProtocolVersion, is_grease_u16};

impl TlsCapture {
    /// Predict the effective inner of a fresh BoringSSL-family ECH offer.
    ///
    /// This follows BoringSSL's `ssl_write_client_cipher_list` and
    /// `ssl_add_clienthello_tlsext_inner`: legacy offers are removed, then
    /// non-compressible extensions precede the shared extensions. It is not a
    /// rule for arbitrary TLS implementations. Unknown extensions, resumption
    /// and padding return `None` rather than claiming an exact projection.
    /// Callers must compare the result with the captured inner before replay.
    #[must_use]
    pub fn ech_inner_from_outer(&self) -> Option<Self> {
        let versions = self
            .extensions
            .iter()
            .find(|extension| extension.id == u16::from(ExtensionId::SUPPORTED_VERSIONS))?;
        let Value::U16List(versions) = &versions.value else {
            return None;
        };
        if !versions.contains(&u16::from(ProtocolVersion::TLSv1_3)) {
            return None;
        }
        let legacy_versions = versions
            .iter()
            .any(|value| !is_grease_u16(*value) && *value < u16::from(ProtocolVersion::TLSv1_3));
        if !self.extensions.iter().any(|extension| {
            extension.id == u16::from(ExtensionId::ENCRYPTED_CLIENT_HELLO)
                && matches!(extension.value, Value::EchOuter { .. })
        }) {
            return None;
        }
        let mut ciphers = Vec::with_capacity(self.ciphers.len());
        for value in self.ciphers.iter().copied() {
            if retained_inner_cipher(CipherSuite::from(value))? {
                ciphers.push(value);
            }
        }
        let mut leading = Vec::new();
        let mut shared = Vec::new();
        for extension in &self.extensions {
            let (uncompressed, value) = match ExtensionId::from(extension.id) {
                // Native TLS 1.2-only extension callbacks omit these from inner.
                ExtensionId::EC_POINT_FORMATS
                | ExtensionId::EXTENDED_MASTER_SECRET
                | ExtensionId::SESSION_TICKET
                | ExtensionId::NEXT_PROTOCOL_NEGOTIATION
                | ExtensionId::RENEGOTIATION_INFO => continue,
                ExtensionId::SERVER_NAME => (true, extension.value.clone()),
                ExtensionId::ENCRYPTED_CLIENT_HELLO => (true, Value::EchInner),
                ExtensionId::SUPPORTED_VERSIONS => {
                    let Value::U16List(values) = &extension.value else {
                        return None;
                    };
                    let value = Value::U16List(
                        values
                            .iter()
                            .copied()
                            .filter(|value| {
                                is_grease_u16(*value)
                                    || *value >= u16::from(ProtocolVersion::TLSv1_3)
                            })
                            .collect(),
                    );
                    (legacy_versions, value)
                }
                // Shared native callbacks, including QUIC parameters and ALPS.
                ExtensionId::STATUS_REQUEST
                | ExtensionId::SUPPORTED_GROUPS
                | ExtensionId::SIGNATURE_ALGORITHMS
                | ExtensionId::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
                | ExtensionId::SIGNED_CERTIFICATE_TIMESTAMP
                | ExtensionId::COMPRESS_CERTIFICATE
                | ExtensionId::PSK_KEY_EXCHANGE_MODES
                | ExtensionId::KEY_SHARE
                | ExtensionId::QUIC_TRANSPORT_PARAMETERS
                | ExtensionId::OLD_APPLICATION_SETTINGS
                | ExtensionId::APPLICATION_SETTINGS
                | ExtensionId::TRUST_ANCHORS => (false, extension.value.clone()),
                id if id.is_grease() => (false, extension.value.clone()),
                _ => return None,
            };
            let extension = TlsCapturedExtension {
                id: extension.id,
                value,
            };
            if uncompressed {
                leading.push(extension);
            } else {
                shared.push(extension);
            }
        }
        leading.extend(shared);
        Some(Self {
            completeness: self.completeness,
            transport: self.transport,
            protocol_version: self.protocol_version,
            ciphers: ciphers.into(),
            compression: self.compression.clone(),
            extensions: leading.into(),
        })
    }
}

// Only omit legacy suites verified to exist in the native cipher table. Rama's
// IANA enum also names unsupported suites and SCSV values, which the raw native
// path preserves. Those need explicit backend evidence before projecting them.
fn retained_inner_cipher(cipher: CipherSuite) -> Option<bool> {
    if cipher.is_grease() {
        return Some(true);
    }
    match cipher {
        CipherSuite::TLS13_AES_128_GCM_SHA256
        | CipherSuite::TLS13_AES_256_GCM_SHA384
        | CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS13_AES_128_CCM_SHA256
        | CipherSuite::TLS13_AES_128_CCM_8_SHA256 => Some(true),
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA
        | CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA
        | CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        | CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        | CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => Some(false),
        _ => None,
    }
}
