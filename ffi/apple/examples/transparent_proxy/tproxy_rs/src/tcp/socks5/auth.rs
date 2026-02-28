use std::convert::Infallible;

use rama::{
    extensions::Extensions,
    net::user::{self, ProxyCredential, authority::Authorizer},
};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Socks5ProxyAuthForwarder;

impl Socks5ProxyAuthForwarder {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone)]
pub struct IngressProxyCredentials(pub ProxyCredential);

impl Authorizer<user::Basic> for Socks5ProxyAuthForwarder {
    type Error = Infallible;

    async fn authorize(
        &self,
        credentials: user::Basic,
    ) -> user::authority::AuthorizeResult<user::Basic, Self::Error> {
        let mut ext = Extensions::new();
        ext.insert(IngressProxyCredentials(ProxyCredential::Basic(
            credentials.clone(),
        )));
        user::authority::AuthorizeResult {
            credentials,
            result: Ok(Some(ext)),
        }
    }
}

impl Authorizer<user::Bearer> for Socks5ProxyAuthForwarder {
    type Error = Infallible;

    async fn authorize(
        &self,
        credentials: user::Bearer,
    ) -> user::authority::AuthorizeResult<user::Bearer, Self::Error> {
        let mut ext = Extensions::new();
        ext.insert(IngressProxyCredentials(ProxyCredential::Bearer(
            credentials.clone(),
        )));
        user::authority::AuthorizeResult {
            credentials,
            result: Ok(Some(ext)),
        }
    }
}
