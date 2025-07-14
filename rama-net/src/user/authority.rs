use std::{fmt, sync::Arc};

use rama_core::context::Extensions;

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
pub struct StaticAuthorizer<C>(C);

impl<C: fmt::Debug> fmt::Debug for StaticAuthorizer<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("StaticAuthorizer").field(&self.0).finish()
    }
}

impl<C: Clone> Clone for StaticAuthorizer<C> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

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

impl<A: Authorizer<C>, C: Send + Sync + 'static> Authorizer<C> for Vec<A> {
    type Error = A::Error;

    async fn authorize(&self, mut credentials: C) -> AuthorizeResult<C, Self::Error> {
        let mut error = None;
        for authorizer in self {
            let AuthorizeResult {
                credentials: c,
                result,
            } = authorizer.authorize(credentials).await;
            match result {
                Ok(maybe_ext) => {
                    return AuthorizeResult {
                        credentials: c,
                        result: Ok(maybe_ext),
                    };
                }
                Err(err) => {
                    error = Some(err);
                    credentials = c;
                }
            }
        }
        AuthorizeResult {
            credentials,
            result: Err(error.unwrap()),
        }
    }
}

impl<const N: usize, A: Authorizer<C>, C: Send + Sync + 'static> Authorizer<C> for [A; N] {
    type Error = A::Error;

    async fn authorize(&self, mut credentials: C) -> AuthorizeResult<C, Self::Error> {
        let mut error = None;
        for authorizer in self {
            let AuthorizeResult {
                credentials: c,
                result,
            } = authorizer.authorize(credentials).await;
            match result {
                Ok(maybe_ext) => {
                    return AuthorizeResult {
                        credentials: c,
                        result: Ok(maybe_ext),
                    };
                }
                Err(err) => {
                    error = Some(err);
                    credentials = c;
                }
            }
        }
        AuthorizeResult {
            credentials,
            result: Err(error.unwrap()),
        }
    }
}

impl<F, Fut, E, C> Authorizer<C> for F
where
    F: FnOnce(C) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = AuthorizeResult<C, E>> + Send + 'static,
    E: Send + 'static,
    C: Send + 'static,
{
    type Error = E;

    fn authorize(
        &self,
        credentials: C,
    ) -> impl Future<Output = AuthorizeResult<C, Self::Error>> + Send + '_ {
        self.clone()(credentials)
    }
}
