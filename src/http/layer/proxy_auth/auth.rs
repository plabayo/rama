use crate::{
    http::headers::{
        authorization::{Basic, Credentials},
        Authorization,
    },
    service::context::Extensions,
    utils::username::{parse_username, UsernameLabelParser, DEFAULT_USERNAME_LABEL_SEPARATOR},
};
use std::future::Future;

/// The `ProxyAuthority` trait is used to determine if a set of [`Credential`]s are authorized.
///
/// [`Credential`]: crate::http::headers::authorization::Credentials
pub trait ProxyAuthority<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    ///
    /// If the `filter_char` is defined it is expected that the authority,
    /// takes into account that the username contains [`ProxyFilter`] data,
    /// and that it is extracted out prior to validation.
    ///
    /// [`ProxyFilter`]: crate::proxy::ProxyFilter
    fn authorized(&self, credentials: C) -> impl Future<Output = Option<Extensions>> + Send + '_;
}

/// A synchronous version of [`ProxyAuthority`], to be used for primitive implementations.
pub trait ProxyAuthoritySync<C, L>: Send + Sync + 'static {
    /// Returns `true` if the credentials are authorized, otherwise `false`.
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool;
}

impl<A, C, L> ProxyAuthority<C, L> for A
where
    A: ProxyAuthoritySync<C, L>,
    C: Credentials + Send + 'static,
    L: 'static,
{
    async fn authorized(&self, credentials: C) -> Option<Extensions> {
        let mut ext = Extensions::new();
        if self.authorized(&mut ext, &credentials) {
            Some(ext)
        } else {
            None
        }
    }
}

impl ProxyAuthoritySync<Basic, ()> for Basic {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        if self == credentials {
            ext.insert(self.clone());
            true
        } else {
            false
        }
    }
}

impl<T: UsernameLabelParser> ProxyAuthoritySync<Basic, T> for Basic {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.password() {
            return false;
        }

        let mut parser_ext = Extensions::new();
        let username = match parse_username(
            &mut parser_ext,
            T::default(),
            username,
            DEFAULT_USERNAME_LABEL_SEPARATOR,
        ) {
            Ok(t) => t,
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                return if self == credentials {
                    ext.insert(self.clone());
                    true
                } else {
                    false
                };
            }
        };

        if username != self.username() {
            return false;
        }

        ext.extend(parser_ext);
        ext.insert(Authorization::basic(username.as_str(), password).0);
        true
    }
}

impl ProxyAuthoritySync<Basic, ()> for (&'static str, &'static str) {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        if self.0 == credentials.username() && self.1 == credentials.password() {
            ext.insert(Authorization::basic(self.0, self.1).0);
            true
        } else {
            false
        }
    }
}

impl<T: UsernameLabelParser> ProxyAuthoritySync<Basic, T> for (&'static str, &'static str) {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.1 {
            return false;
        }

        let mut parser_ext = Extensions::new();
        let username = match parse_username(
            &mut parser_ext,
            T::default(),
            username,
            DEFAULT_USERNAME_LABEL_SEPARATOR,
        ) {
            Ok(t) => t,
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                return if self.0 == credentials.username() && self.1 == credentials.password() {
                    ext.insert(Authorization::basic(self.0, self.1).0);
                    true
                } else {
                    false
                };
            }
        };

        if username != self.0 {
            return false;
        }

        ext.extend(parser_ext);
        ext.insert(Authorization::basic(username.as_str(), password).0);
        true
    }
}

impl ProxyAuthoritySync<Basic, ()> for (String, String) {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        if self.0 == credentials.username() && self.1 == credentials.password() {
            ext.insert(Authorization::basic(self.0.as_str(), self.1.as_str()).0);
            true
        } else {
            false
        }
    }
}

impl<T: UsernameLabelParser> ProxyAuthoritySync<Basic, T> for (String, String) {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.1 {
            return false;
        }

        let mut parser_ext = Extensions::new();
        let username = match parse_username(
            &mut parser_ext,
            T::default(),
            username,
            DEFAULT_USERNAME_LABEL_SEPARATOR,
        ) {
            Ok(t) => t,
            Err(err) => {
                tracing::trace!("failed to parse username: {:?}", err);
                return if self.0 == credentials.username() && self.1 == credentials.password() {
                    ext.insert(Authorization::basic(self.0.as_str(), self.1.as_str()).0);
                    true
                } else {
                    false
                };
            }
        };

        if username != self.0 {
            return false;
        }

        ext.extend(parser_ext);
        ext.insert(Authorization::basic(username.as_str(), password).0);
        true
    }
}

impl<C, L, T, const N: usize> ProxyAuthoritySync<C, L> for [T; N]
where
    C: Credentials + Send + 'static,
    T: ProxyAuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

impl<C, L, T> ProxyAuthoritySync<C, L> for Vec<T>
where
    C: Credentials + Send + 'static,
    T: ProxyAuthoritySync<C, L>,
{
    fn authorized(&self, ext: &mut Extensions, credentials: &C) -> bool {
        self.iter().any(|t| t.authorized(ext, credentials))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        http::headers::{authorization::Basic, Authorization},
        proxy::{ProxyFilter, ProxyFilterUsernameParser},
        utils::username::{UsernameLabels, UsernameOpaqueLabelParser},
    };

    #[tokio::test]
    async fn basic_authorization() {
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let auths = vec![Authorization::basic("foo", "bar").0, auth.clone()];
        let ext = ProxyAuthority::<_, ()>::authorized(&auths, auth.clone())
            .await
            .unwrap();
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

        let ext = ProxyAuthority::<_, ProxyFilterUsernameParser>::authorized(
            &auths,
            Authorization::basic("john-country-us", "secret").0,
        )
        .await
        .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        let filter: &ProxyFilter = ext.get().unwrap();
        assert_eq!(filter.country, Some(vec!["us".into()]));
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = ProxyAuthority::<_, UsernameOpaqueLabelParser>::authorized(
            &auths,
            Authorization::basic("john-green-red", "secret").0,
        )
        .await
        .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        let labels: &UsernameLabels = ext.get().unwrap();
        assert_eq!(&labels.0, &vec!["green".to_owned(), "red".to_owned()]);
    }

    #[tokio::test]
    async fn basic_authorization_with_filter_not_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = ProxyAuthority::<_, ProxyFilterUsernameParser>::authorized(&auths, auth.clone())
            .await
            .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        assert!(ext.get::<ProxyFilter>().is_none());
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_not_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = ProxyAuthority::<_, UsernameOpaqueLabelParser>::authorized(&auths, auth.clone())
            .await
            .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        assert!(ext.get::<UsernameLabels>().is_none());
    }

    #[tokio::test]
    async fn basic_authorization_tuple() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let ext = ProxyAuthority::<_, ()>::authorized(&auths, auth.clone())
            .await
            .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);
    }

    #[tokio::test]
    async fn basic_authorization_tuple_no_auth_username() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("bax", "qux");
        assert!(ProxyAuthority::<_, ()>::authorized(&auths, auth.clone())
            .await
            .is_none());
    }

    #[tokio::test]
    async fn basic_authorization_tuple_no_auth_password() {
        let auths = vec![("foo", "bar"), ("Aladdin", "open sesame"), ("baz", "qux")];
        let Authorization(auth) = Authorization::basic("baz", "quc");
        assert!(ProxyAuthority::<_, ()>::authorized(&auths, auth.clone())
            .await
            .is_none())
    }

    #[tokio::test]
    async fn basic_authorization_tuple_string() {
        let auths = vec![
            ("foo".to_owned(), "bar".to_owned()),
            ("Aladdin".to_owned(), "open sesame".to_owned()),
            ("baz".to_owned(), "qux".to_owned()),
        ];
        let Authorization(auth) = Authorization::basic("Aladdin", "open sesame");
        let ext = ProxyAuthority::<_, ()>::authorized(&auths, auth.clone())
            .await
            .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);
    }
}
