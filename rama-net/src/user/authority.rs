use std::{fmt, sync::Arc};

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

macro_rules! impl_authorizer_slice {
    () => {
        async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
            let mut iter = self.iter();

            let mut last_authorize_result = match iter.next() {
                Some(authorizer) => authorizer.authorize(credentials).await,
                None => {
                    tracing::debug!(
                        "no authorizers in array found: assume all credentials are fine incl... this one... (fail-open)"
                    );
                    return AuthorizeResult {
                        credentials,
                        result: Ok(None),
                    };
                }
            };
            if last_authorize_result.result.is_ok() {
                return last_authorize_result;
            }

            for authorizer in iter {
                last_authorize_result = authorizer
                    .authorize(last_authorize_result.credentials)
                    .await;

                if last_authorize_result.result.is_ok() {
                    return last_authorize_result;
                }
            }

            last_authorize_result
        }
    };
}

impl<A: Authorizer<C>, C: Send + Sync + 'static> Authorizer<C> for Vec<A> {
    type Error = A::Error;
    impl_authorizer_slice!();
}

impl<const N: usize, A: Authorizer<C>, C: Send + Sync + 'static> Authorizer<C> for [A; N] {
    type Error = A::Error;
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
