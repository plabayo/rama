use crate::{
    http::headers::authorization::Credentials,
    net::user::{Basic, UserId},
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
            ext.insert(UserId::Username(self.username().to_owned()));
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
                    ext.insert(UserId::Username(username.to_owned()));
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
        ext.insert(UserId::Username(username));
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
        net::user::Basic,
        proxy::{ProxyFilter, ProxyFilterUsernameParser},
        utils::username::{UsernameLabels, UsernameOpaqueLabelParser},
    };

    #[tokio::test]
    async fn basic_authorization() {
        let auth = Basic::new("Aladdin", "open sesame");
        let auths = vec![Basic::new("foo", "bar"), auth.clone()];
        let ext = ProxyAuthority::<_, ()>::authorized(&auths, auth)
            .await
            .unwrap();
        let user: &UserId = ext.get().unwrap();
        assert_eq!(user, "Aladdin");
    }

    #[tokio::test]
    async fn basic_authorization_with_filter_found() {
        let auths = vec![Basic::new("foo", "bar"), Basic::new("john", "secret")];

        let ext = ProxyAuthority::<_, ProxyFilterUsernameParser>::authorized(
            &auths,
            Basic::new("john-country-us", "secret"),
        )
        .await
        .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        let filter: &ProxyFilter = ext.get().unwrap();
        assert_eq!(filter.country, Some(vec!["us".into()]));
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_found() {
        let auths = vec![Basic::new("foo", "bar"), Basic::new("john", "secret")];

        let ext = ProxyAuthority::<_, UsernameOpaqueLabelParser>::authorized(
            &auths,
            Basic::new("john-green-red", "secret"),
        )
        .await
        .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        let labels: &UsernameLabels = ext.get().unwrap();
        assert_eq!(&labels.0, &vec!["green".to_owned(), "red".to_owned()]);
    }

    #[tokio::test]
    async fn basic_authorization_with_filter_not_found() {
        let auth = Basic::new("john", "secret");
        let auths = vec![Basic::new("foo", "bar"), auth.clone()];

        let ext = ProxyAuthority::<_, ProxyFilterUsernameParser>::authorized(&auths, auth)
            .await
            .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        assert!(ext.get::<ProxyFilter>().is_none());
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_not_found() {
        let auth = Basic::new("john", "secret");
        let auths = vec![Basic::new("foo", "bar"), auth.clone()];

        let ext = ProxyAuthority::<_, UsernameOpaqueLabelParser>::authorized(&auths, auth)
            .await
            .unwrap();

        let c: &UserId = ext.get().unwrap();
        assert_eq!(c, "john");

        assert!(ext.get::<UsernameLabels>().is_none());
    }
}
