use headers::authorization::Basic;

use crate::http::headers::authorization::Credentials;
use std::future::Future;

/// The `ProxyAuthority` trait is used to determine if a set of [`Credential`]s are authorized.
///
/// [`Credential`]: crate::http::headers::authorization::Credentials
pub trait ProxyAuthority<C>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, credentials: C) -> impl Future<Output = Option<C>> + Send + '_;
}

/// A synchronous version of [`ProxyAuthority`], to be used for primitive implementations.
pub trait ProxyAuthoritySync<C>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, credentials: &C) -> bool;
}

impl<A, C> ProxyAuthority<C> for A
where
    A: ProxyAuthoritySync<C>,
    C: Credentials + Send + 'static,
{
    async fn authorized(&self, credentials: C) -> Option<C> {
        if self.authorized(&credentials) {
            Some(credentials)
        } else {
            None
        }
    }
}

impl ProxyAuthoritySync<Basic> for Basic {
    fn authorized(&self, credentials: &Basic) -> bool {
        self == credentials
    }
}

impl ProxyAuthoritySync<Basic> for (&'static str, &'static str) {
    fn authorized(&self, credentials: &Basic) -> bool {
        self.0 == credentials.username() && self.1 == credentials.password()
    }
}

impl ProxyAuthoritySync<Basic> for (String, String) {
    fn authorized(&self, credentials: &Basic) -> bool {
        self.0 == credentials.username() && self.1 == credentials.password()
    }
}

macro_rules! impl_proxy_auth_sync_tuple {
    ($($T:ident),+ $(,)?) => {
        #[allow(unused_parens)]
        #[allow(non_snake_case)]
        impl<C, $($T),+> ProxyAuthoritySync<C> for ($($T),+,)
            where C: Credentials + Send + 'static,
                $(
                    $T: ProxyAuthoritySync<C>,
                )+

        {
            fn authorized(&self, credentials: &C) -> bool {
                let ($($T),+,) = self;
                $(
                    ProxyAuthoritySync::authorized($T, &credentials)
                )||+
            }
        }
    };
}

all_the_tuples_no_last_special_case!(impl_proxy_auth_sync_tuple);

impl<C, T> ProxyAuthoritySync<C> for Vec<T>
where
    C: Credentials + Send + 'static,
    T: ProxyAuthoritySync<C>,
{
    fn authorized(&self, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(credentials))
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use headers::Authorization;

    use super::ProxyAuthority;

    #[tokio::test]
    async fn basic_authorization() {
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let auths = vec![Authorization::basic("foo", "bar").0, auth.clone()];
        assert_eq!(Some(auth.clone()), auths.authorized(auth).await);
    }

    #[tokio::test]
    async fn basic_authorization_tuple() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        assert_eq!(Some(auth.clone()), auths.authorized(auth).await);
    }

    #[tokio::test]
    async fn basic_authorization_tuple_no_auth_username() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("bax", "qux");
        assert!(auths.authorized(auth).await.is_none());
    }

    #[tokio::test]
    async fn basic_authorization_tuple_no_auth_password() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("baz", "quc");
        assert!(auths.authorized(auth).await.is_none());
    }

    #[tokio::test]
    async fn basic_authorization_tuple_string() {
        let auths = vec![
            ("foo".to_owned(), "bar".to_owned()),
            ("Aladdin".to_owned(), "open sesame".to_owned()),
            ("baz".to_owned(), "qux".to_owned()),
        ];
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        assert_eq!(Some(auth.clone()), auths.authorized(auth).await);
    }

    #[tokio::test]
    async fn basic_authorization_arc_tuple_string() {
        let auths = Arc::new(vec![
            ("foo".to_owned(), "bar".to_owned()),
            ("Aladdin".to_owned(), "open sesame".to_owned()),
            ("baz".to_owned(), "qux".to_owned()),
        ]);
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        assert_eq!(Some(auth.clone()), auths.authorized(auth).await);
    }
}
