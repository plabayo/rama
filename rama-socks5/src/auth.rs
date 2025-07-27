use crate::proto::SocksMethod;
use rama_net::user;

#[derive(Clone, Debug)]
pub enum Socks5Auth {
    /// Username/Password Authentication for SOCKS V5
    ///
    /// Reference: [RFC 1928](https://datatracker.ietf.org/doc/html/rfc1929)
    UsernamePassword(user::Basic),
}

impl Socks5Auth {
    /// Return the [`SocksMethod`] linked to this authentication type.
    #[must_use]
    pub fn socks5_method(&self) -> SocksMethod {
        match self {
            Self::UsernamePassword(_) => SocksMethod::UsernamePassword,
        }
    }
}

impl From<user::Basic> for Socks5Auth {
    fn from(value: user::Basic) -> Self {
        Self::UsernamePassword(value)
    }
}
