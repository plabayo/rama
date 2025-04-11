use crate::proto::SocksMethod;

#[derive(Debug, Clone)]
pub enum Socks5Auth {
    /// Username/Password Authentication for SOCKS V5
    ///
    /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1929)
    UsernamePassword {
        username: Vec<u8>,
        password: Option<Vec<u8>>,
    },
}

impl Socks5Auth {
    /// Use Username/Password Authentication for SOCKS V5.
    ///
    /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1929)
    pub fn username_password(username: impl Into<Vec<u8>>, password: impl Into<Vec<u8>>) -> Self {
        Self::UsernamePassword {
            username: username.into(),
            password: Some(password.into()),
        }
    }

    /// Return the [`SocksMethod`] linked to this authentication type.
    pub fn socks5_method(&self) -> SocksMethod {
        match self {
            Socks5Auth::UsernamePassword { .. } => SocksMethod::UsernamePassword,
        }
    }
}
