use core::fmt;

use crate::std::{sync::Arc, vec::Vec};

use rama_core::{extensions::Extensions, telemetry::tracing};

/// Result of [`Authorizer::authorize`].
pub struct AuthorizeResult<C, E> {
    pub credentials: C,
    pub result: Result<Option<Extensions>, E>,
}

impl<C: fmt::Debug, E: fmt::Debug> fmt::Debug for AuthorizeResult<C, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorizeResult")
            .field("credentials", &self.credentials)
            .field("result", &self.result)
            .finish()
    }
}

/// The `Authorizer` trait is used to determine if the given credentials are authorized.
pub trait Authorizer<C>: Send + Sync + 'static {
    /// Returned in case the credentials are not authorized.
    type Error: Send + 'static;

    /// Authorize the given credentials.
    fn authorize(
        &self,
        credentials: C,
    ) -> impl Future<Output = AuthorizeResult<C, Self::Error>> + Send + '_;
}

rama_utils::macros::error::static_str_error! {
    #[doc = "credentials are unauthorized"]
    pub struct Unauthorized;
}

impl<C: Send + 'static> Authorizer<C> for () {
    type Error = Unauthorized;

    async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        AuthorizeResult {
            credentials,
            result: Err(Unauthorized),
        }
    }
}

impl<C: Send + 'static> Authorizer<C> for bool {
    type Error = Unauthorized;

    async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        if *self {
            AuthorizeResult {
                credentials,
                result: Ok(None),
            }
        } else {
            AuthorizeResult {
                credentials,
                result: Err(Unauthorized),
            }
        }
    }
}

impl<A: Authorizer<C>, C: Send + 'static> Authorizer<C> for Arc<A> {
    type Error = A::Error;

    fn authorize(
        &self,
        credentials: C,
    ) -> impl Future<Output = AuthorizeResult<C, Self::Error>> + Send + '_ {
        (**self).authorize(credentials)
    }
}

/// [`Authorizer`] that can be used to validate against static credentials.
#[derive(Debug, Clone)]
pub struct StaticAuthorizer<C>(C);

impl<C> StaticAuthorizer<C> {
    /// Create a new [`StaticAuthorizer`] for the given credentials.
    pub fn new(credentials: C) -> Self {
        Self(credentials)
    }
}

impl<C: PartialEq + Send + Sync + 'static> Authorizer<C> for StaticAuthorizer<C> {
    type Error = Unauthorized;

    async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        let result = credentials.eq(&self.0);
        result.authorize(credentials).await
    }
}

/// `None` requires no authentication and authorizes all credentials;
/// `Some` delegates to its [`Authorizer`].
///
/// Use it to express "no authorizer configured means open", as an empty list of
/// authorizers rejects all credentials.
impl<A: Authorizer<C>, C: Send + 'static> Authorizer<C> for Option<A> {
    type Error = A::Error;

    async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        match self {
            Some(authorizer) => authorizer.authorize(credentials).await,
            None => AuthorizeResult {
                credentials,
                result: Ok(None),
            },
        }
    }
}

/// Returned by a list of authorizers in case the credentials are not authorized.
#[derive(Debug, Clone)]
pub enum AuthorizerListError<E> {
    /// The list has no authorizers, so there is none to authorize the credentials.
    NoAuthorizers,
    /// No authorizer of the list authorized the credentials: the error of the last one.
    Unauthorized(E),
}

impl<E: fmt::Display> fmt::Display for AuthorizerListError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAuthorizers => f.write_str("no authorizers to authorize credentials"),
            Self::Unauthorized(err) => err.fmt(f),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for AuthorizerListError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::NoAuthorizers => None,
            Self::Unauthorized(err) => Some(err),
        }
    }
}

macro_rules! impl_authorizer_slice {
    () => {
        type Error = AuthorizerListError<A::Error>;

        async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
            let mut iter = self.iter();

            let Some(first) = iter.next() else {
                tracing::debug!("no authorizers in list: credentials rejected");
                return AuthorizeResult {
                    credentials,
                    result: Err(AuthorizerListError::NoAuthorizers),
                };
            };

            let mut last = first.authorize(credentials).await;
            for authorizer in iter {
                if last.result.is_ok() {
                    break;
                }
                last = authorizer.authorize(last.credentials).await;
            }

            AuthorizeResult {
                credentials: last.credentials,
                result: last.result.map_err(AuthorizerListError::Unauthorized),
            }
        }
    };
}

/// Authorizes the credentials which any of its authorizers authorizes.
///
/// An empty list rejects all credentials. Wrap an [`Authorizer`] in an [`Option`]
/// for authentication that is not required when nothing is configured.
impl<A: Authorizer<C>, C: Send + Sync + 'static> Authorizer<C> for Vec<A> {
    impl_authorizer_slice!();
}

/// Authorizes the credentials which any of its authorizers authorizes.
///
/// An empty list rejects all credentials. Wrap an [`Authorizer`] in an [`Option`]
/// for authentication that is not required when nothing is configured.
impl<const N: usize, A: Authorizer<C>, C: Send + Sync + 'static> Authorizer<C> for [A; N] {
    impl_authorizer_slice!();
}

impl<F, Fut, E, C> Authorizer<C> for F
where
    F: Fn(C) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = AuthorizeResult<C, E>> + Send + 'static,
    E: Send + 'static,
    C: Send + 'static,
{
    type Error = E;

    fn authorize(
        &self,
        credentials: C,
    ) -> impl Future<Output = AuthorizeResult<C, Self::Error>> + Send + '_ {
        (self)(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Token = StaticAuthorizer<&'static str>;

    async fn is_authorized<A: Authorizer<&'static str>>(
        authorizer: &A,
        credentials: &'static str,
    ) -> bool {
        authorizer.authorize(credentials).await.result.is_ok()
    }

    #[tokio::test]
    async fn a_list_without_authorizers_rejects_all_credentials() {
        assert!(!is_authorized(&Vec::<Token>::new(), "secret").await);
        assert!(!is_authorized(&[] as &[Token; 0], "secret").await);
        // What the absent authorizers would have authorized does not matter.
        assert!(!is_authorized(&Vec::<bool>::new(), "secret").await);

        let result = Vec::<Token>::new().authorize("secret").await;
        assert_eq!(result.credentials, "secret");
        assert!(matches!(
            result.result,
            Err(AuthorizerListError::NoAuthorizers)
        ));
    }

    #[tokio::test]
    async fn a_list_authorizes_what_any_of_its_authorizers_does() {
        let list = vec![Token::new("first"), Token::new("second")];
        let array = [Token::new("first"), Token::new("second")];
        for (credentials, expected) in [("first", true), ("second", true), ("third", false)] {
            assert_eq!(
                is_authorized(&list, credentials).await,
                expected,
                "{credentials}"
            );
            assert_eq!(
                is_authorized(&array, credentials).await,
                expected,
                "{credentials}"
            );
        }

        let result = list.authorize("third").await;
        assert_eq!(result.credentials, "third");
        assert!(matches!(
            result.result,
            Err(AuthorizerListError::Unauthorized(Unauthorized))
        ));
    }

    #[tokio::test]
    async fn no_authorizer_requires_no_authentication() {
        assert!(is_authorized(&None::<Token>, "anything").await);
        assert!(is_authorized(&None::<Vec<Token>>, "anything").await);

        let authorizer = Some(Token::new("secret"));
        assert!(is_authorized(&authorizer, "secret").await);
        assert!(!is_authorized(&authorizer, "other").await);
        // A configured list stays closed while empty.
        assert!(!is_authorized(&Some(Vec::<Token>::new()), "secret").await);
    }
}
