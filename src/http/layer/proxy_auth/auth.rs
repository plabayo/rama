use crate::{
    error::BoxError,
    http::headers::{
        authorization::{Basic, Credentials},
        Authorization,
    },
    proxy::{username::UsernameConfigError, ProxyFilter, UsernameConfig},
    service::context::Extensions,
};
use std::{
    future::Future,
    ops::{Deref, DerefMut},
};

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

/// A trait to convert a username into a tuple of username and meta info attached to the username.
///
/// This trait is to be implemented in case you want to define your own metadata extractor from the username.
///
/// See [`UsernameConfig`] for an example of why one might want to use this.
pub trait FromUsername {
    /// The output type of the username metadata extraction,
    /// and which will be added to the [`Request`]'s [`Extensions`].
    ///
    /// [`Request`]: crate::http::Request
    type Output: Clone + Send + Sync + 'static;

    /// The error type that can be returned when parsing the username went wrong.
    type Error;

    /// Parse the username and return the username and the metadata.
    fn from_username(username: &str) -> Result<(String, Option<Self::Output>), Self::Error>;
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

impl<T: FromUsername> ProxyAuthoritySync<Basic, T> for Basic {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.password() {
            return false;
        }

        let (username, mut metadata) = match T::from_username(username) {
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

        if let Some(metadata) = metadata.take() {
            ext.insert(metadata);
        }
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

impl<T: FromUsername> ProxyAuthoritySync<Basic, T> for (&'static str, &'static str) {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.1 {
            return false;
        }

        let (username, mut metadata) = match T::from_username(username) {
            Ok(t) => t,
            Err(_) => {
                return if self.0 == credentials.username() && self.1 == credentials.password() {
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

        if let Some(metadata) = metadata.take() {
            ext.insert(metadata);
        }
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

impl<T: FromUsername> ProxyAuthoritySync<Basic, T> for (String, String) {
    fn authorized(&self, ext: &mut Extensions, credentials: &Basic) -> bool {
        let username = credentials.username();
        let password = credentials.password();

        if password != self.1 {
            return false;
        }

        let (username, mut metadata) = match T::from_username(username) {
            Ok(t) => t,
            Err(_) => {
                return if self.0 == credentials.username() && self.1 == credentials.password() {
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

        if let Some(metadata) = metadata.take() {
            ext.insert(metadata);
        }
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

/// A wrapper type to extract username labels and store them as-is in the [`Extensions`].
#[derive(Debug, Clone)]
pub struct ProxyUsernameLabels<const C: char = '-'>(pub Vec<String>);

impl<const C: char> Deref for ProxyUsernameLabels<C> {
    type Target = Vec<String>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const C: char> DerefMut for ProxyUsernameLabels<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const C: char> FromUsername for ProxyUsernameLabels<C> {
    type Output = Self;
    type Error = BoxError;

    fn from_username(username: &str) -> Result<(String, Option<Self::Output>), Self::Error> {
        let mut it = username.split(C);
        let username = match it.next() {
            Some(username) => username.to_owned(),
            None => return Err("no username found".into()),
        };
        let labels: Vec<_> = it.map(str::to_owned).collect();
        if labels.is_empty() {
            Ok((username, None))
        } else {
            Ok((username, Some(Self(labels))))
        }
    }
}

impl<const C: char> FromUsername for UsernameConfig<C> {
    type Output = ProxyFilter;
    type Error = UsernameConfigError;

    fn from_username(username: &str) -> Result<(String, Option<Self::Output>), Self::Error> {
        let username_cfg: Self = username.parse()?;
        let (username, filter) = username_cfg.into_parts();
        Ok((username, filter))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::proxy::{ProxyFilter, UsernameConfig};
    use headers::{authorization::Basic, Authorization};

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

        let ext = ProxyAuthority::<_, UsernameConfig>::authorized(
            &auths,
            Authorization::basic("john-cc-us", "secret").0,
        )
        .await
        .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        let filter: &ProxyFilter = ext.get().unwrap();
        assert_eq!(filter.country, Some("us".to_owned()));
    }

    #[tokio::test]
    async fn basic_authorization_with_labels_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = ProxyAuthority::<_, ProxyUsernameLabels>::authorized(
            &auths,
            Authorization::basic("john-green-red", "secret").0,
        )
        .await
        .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        let labels: &ProxyUsernameLabels = ext.get().unwrap();
        assert_eq!(labels.deref(), &vec!["green".to_owned(), "red".to_owned()]);
    }

    #[tokio::test]
    async fn basic_authorization_with_filter_not_found() {
        let Authorization(auth) = Authorization::basic("john", "secret");
        let auths = vec![
            Authorization::basic("foo", "bar").0,
            Authorization::basic("john", "secret").0,
        ];

        let ext = ProxyAuthority::<_, UsernameConfig>::authorized(&auths, auth.clone())
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

        let ext = ProxyAuthority::<_, ProxyUsernameLabels>::authorized(&auths, auth.clone())
            .await
            .unwrap();
        let c: &Basic = ext.get().unwrap();
        assert_eq!(&auth, c);

        assert!(ext.get::<ProxyUsernameLabels>().is_none());
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
