macro_rules! enum_from_rustls {
    ($t:ty => $($name:ident),+$(,)?) => {
        $(
            impl From<rustls::$name> for super::$name {
                fn from(value: rustls::$name) -> Self {
                    let n: $t = value.into();
                    n.into()
                }
            }
        )+
    };
}

enum_from_rustls!(u16 => ProtocolVersion, CipherSuite, SignatureScheme);
