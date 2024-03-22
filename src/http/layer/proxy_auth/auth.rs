use crate::{
    http::headers::{
        authorization::{Basic, Credentials},
        Authorization,
    },
    proxy::parse_username_config,
    service::context::Extensions,
};
use std::future::Future;

/// The `ProxyAuthority` trait is used to determine if a set of [`Credential`]s are authorized.
///
/// [`Credential`]: crate::http::headers::authorization::Credentials
pub trait ProxyAuthority<C>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    ///
    /// If the `filter_char` is defined it is expected that the authority,
    /// takes into account that the username contains [`ProxyFilter`] data,
    /// and that it is extracted out prior to validation.
    ///
    /// [`ProxyFilter`]: crate::proxy::ProxyFilter
    fn authorized(
        &self,
        filter_char: Option<char>,
        credentials: C,
    ) -> impl Future<Output = Option<Extensions>> + Send + '_;
}

/// A synchronous version of [`ProxyAuthority`], to be used for primitive implementations.
pub trait ProxyAuthoritySync<C>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    ///
    /// If the `filter_char` is defined it is expected that the authority,
    /// takes into account that the username contains [`ProxyFilter`] data,
    /// and that it is extracted out prior to validation.
    ///
    /// [`ProxyFilter`]: crate::proxy::ProxyFilter
    fn authorized(&self, filter_char: Option<char>, ext: &mut Extensions, credentials: &C) -> bool;
}

impl<A, C> ProxyAuthority<C> for A
where
    A: ProxyAuthoritySync<C>,
    C: Credentials + Send + 'static,
{
    async fn authorized(&self, filter_char: Option<char>, credentials: C) -> Option<Extensions> {
        let mut ext = Extensions::new();
        if self.authorized(filter_char, &mut ext, &credentials) {
            Some(ext)
        } else {
            None
        }
    }
}

impl ProxyAuthoritySync<Basic> for Basic {
    fn authorized(
        &self,
        filter_char: Option<char>,
        ext: &mut Extensions,
        credentials: &Basic,
    ) -> bool {
        match filter_char {
            Some(c) => {
                let username = credentials.username();
                let password = credentials.password();

                if password != self.password() {
                    return false;
                }

                let (username, mut filter) = match parse_username_config(username, c) {
                    Ok(t) => t,
                    Err(_) => {
                        return if self == credentials {
                            ext.insert(self.clone());
                            true
                        } else {
                            false
                        }
                    }
                };

                if username != self.username() {
                    return false;
                }

                if let Some(filter) = filter.take() {
                    ext.insert(filter);
                }
                ext.insert(Authorization::basic(username.as_str(), password).0);
                true
            }
            None => {
                if self == credentials {
                    ext.insert(self.clone());
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl ProxyAuthoritySync<Basic> for (&'static str, &'static str) {
    fn authorized(
        &self,
        filter_char: Option<char>,
        ext: &mut Extensions,
        credentials: &Basic,
    ) -> bool {
        match filter_char {
            Some(c) => {
                let username = credentials.username();
                let password = credentials.password();

                if password != self.1 {
                    return false;
                }

                let (username, mut filter) = match parse_username_config(username, c) {
                    Ok(t) => t,
                    Err(_) => {
                        return if self.0 == credentials.username()
                            && self.1 == credentials.password()
                        {
                            ext.insert(Authorization::basic(self.0, self.1).0);
                            true
                        } else {
                            false
                        }
                    }
                };

                if username != self.0 {
                    return false;
                }

                if let Some(filter) = filter.take() {
                    ext.insert(filter);
                }
                ext.insert(Authorization::basic(username.as_str(), password).0);
                true
            }
            None => {
                if self.0 == credentials.username() && self.1 == credentials.password() {
                    ext.insert(Authorization::basic(self.0, self.1).0);
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl ProxyAuthoritySync<Basic> for (String, String) {
    fn authorized(
        &self,
        filter_char: Option<char>,
        ext: &mut Extensions,
        credentials: &Basic,
    ) -> bool {
        match filter_char {
            Some(c) => {
                let username = credentials.username();
                let password = credentials.password();

                if password != self.1 {
                    return false;
                }

                let (username, mut filter) = match parse_username_config(username, c) {
                    Ok(t) => t,
                    Err(_) => {
                        return if self.0 == credentials.username()
                            && self.1 == credentials.password()
                        {
                            ext.insert(Authorization::basic(self.0.as_str(), self.1.as_str()).0);
                            true
                        } else {
                            false
                        }
                    }
                };

                if username != self.0 {
                    return false;
                }

                if let Some(filter) = filter.take() {
                    ext.insert(filter);
                }
                ext.insert(Authorization::basic(username.as_str(), password).0);
                true
            }
            None => {
                if self.0 == credentials.username() && self.1 == credentials.password() {
                    ext.insert(Authorization::basic(self.0.as_str(), self.1.as_str()).0);
                    true
                } else {
                    false
                }
            }
        }
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
            fn authorized(&self, filter_char: Option<char>, ext: &mut Extensions, credentials: &C) -> bool {
                let ($($T),+,) = self;
                $(
                    ProxyAuthoritySync::authorized($T, filter_char, ext, &credentials)
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
    fn authorized(&self, filter_char: Option<char>, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter()
            .any(|t| t.authorized(filter_char, ext, credentials))
    }
}

#[cfg(test)]
mod test {
    use crate::proxy::ProxyFilter;

    use super::ProxyAuthority;
    use headers::{authorization::Basic, Authorization};
    use std::sync::Arc;

    #[tokio::test]
    async fn basic_authorization() {
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let auths = vec![Authorization::basic("foo", "bar").0, auth.clone()];
        let ext = auths.authorized(None, auth.clone()).await.unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);
    }

    #[tokio::test]
    async fn basic_authorization_with_filter_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = auths
            .authorized(Some('-'), Authorization::basic("john-cc-us", "secret").0)
            .await
            .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        let filter: &ProxyFilter = ext.get().unwrap();
        assert_eq!(filter.country, Some("us".to_owned()));
    }

    #[tokio::test]
    async fn basic_authorization_with_filter_not_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = auths.authorized(Some('-'), auth.clone()).await.unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        assert!(ext.get::<ProxyFilter>().is_none());
    }

    #[tokio::test]
    async fn basic_authorization_tuple() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let ext = auths.authorized(None, auth.clone()).await.unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);
    }

    #[tokio::test]
    async fn basic_authorization_tuple_no_auth_username() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("bax", "qux");
        assert!(auths.authorized(None, auth.clone()).await.is_none());
    }

    #[tokio::test]
    async fn basic_authorization_tuple_no_auth_password() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("baz", "quc");
        assert!(auths.authorized(None, auth.clone()).await.is_none())
    }

    #[tokio::test]
    async fn basic_authorization_tuple_string() {
        let auths = vec![
            ("foo".to_owned(), "bar".to_owned()),
            ("Aladdin".to_owned(), "open sesame".to_owned()),
            ("baz".to_owned(), "qux".to_owned()),
        ];
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let ext = auths.authorized(None, auth.clone()).await.unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);
    }

    #[tokio::test]
    async fn basic_authorization_arc_tuple_string() {
        let auths = Arc::new(vec![
            ("foo".to_owned(), "bar".to_owned()),
            ("Aladdin".to_owned(), "open sesame".to_owned()),
            ("baz".to_owned(), "qux".to_owned()),
        ]);
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let ext = auths.authorized(None, auth.clone()).await.unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);
    }
}
