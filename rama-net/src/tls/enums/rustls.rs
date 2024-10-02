use super::ProtocolVersion;

macro_rules! enum_from_rustls {
    ($t:ty => $($name:ident),+$(,)?) => {
        $(
            impl From<rustls::$name> for super::$name {
                fn from(value: ::rustls::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }

            impl From<super::$name> for rustls::$name {
                fn from(value: super::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }
        )+
    };
}

enum_from_rustls!(u16 => ProtocolVersion, CipherSuite, SignatureScheme);

impl TryFrom<super::ProtocolVersion> for &rustls::SupportedProtocolVersion {
    type Error = super::ProtocolVersion;

    fn try_from(value: super::ProtocolVersion) -> Result<Self, Self::Error> {
        match value {
            ProtocolVersion::TLSv1_2 => Ok(&rustls::version::TLS12),
            ProtocolVersion::TLSv1_3 => Ok(&rustls::version::TLS13),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_rustls_to_common_to_rustls() {
        let p = rustls::ProtocolVersion::TLSv1_3;
        let p = crate::tls::ProtocolVersion::from(p);
        assert_eq!(p, crate::tls::ProtocolVersion::TLSv1_3);
        let p = rustls::ProtocolVersion::from(p);
        assert_eq!(p, rustls::ProtocolVersion::TLSv1_3);
    }
}
