//! Authorize requests using [`ValidateRequest`].

use std::{fmt, marker::PhantomData};

use rama_core::{Context, telemetry::tracing};
use rama_http_headers::{Authorization, HeaderMapExt, authorization::Credentials};
use rama_http_types::{Body, HeaderValue, Request, Response, StatusCode, header};
use rama_net::user::{
    Basic, Bearer, UserId,
    authority::{AuthorizeResult, Authorizer, StaticAuthorizer},
};

use crate::{
    layer::validate_request::{ValidateRequest, ValidateRequestHeader, ValidateRequestHeaderLayer},
    service::web::response::IntoResponse,
};

/// Utility type to allow you to use any [`Authorizer`]
/// that works with [`Credentials`] to authorize the [`Authorization`] header,
/// and return [`StatusCode::UNAUTHORIZED`] response with [`header::WWW_AUTHENTICATE`] for unauthorized request,
/// tracing the original error for your convenience.
pub struct HttpAuthorizer<A, C> {
    authorizer: A,
    allow_anonymous: bool,
    _credentials: PhantomData<fn() -> C>,
}

impl From<Basic> for HttpAuthorizer<StaticAuthorizer<Basic>, Basic> {
    fn from(value: Basic) -> Self {
        Self::new(StaticAuthorizer::new(value))
    }
}

impl From<Bearer> for HttpAuthorizer<StaticAuthorizer<Bearer>, Bearer> {
    fn from(value: Bearer) -> Self {
        Self::new(StaticAuthorizer::new(value))
    }
}

impl<C: Credentials> From<Vec<C>> for HttpAuthorizer<Vec<C>, C> {
    fn from(value: Vec<C>) -> Self {
        Self::new(value)
    }
}

impl<const N: usize, C: Credentials> From<[C; N]> for HttpAuthorizer<[C; N], C> {
    fn from(value: [C; N]) -> Self {
        Self::new(value)
    }
}

impl<A, C> HttpAuthorizer<A, C> {
    pub fn new(authorizer: A) -> Self {
        Self {
            authorizer,
            allow_anonymous: false,
            _credentials: PhantomData,
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Defines whether or not to allow anonymous.
        ///
        /// This means that the request is will be authorized automatically,
        /// if no [`Authorization`] header was passed in.
        pub fn allow_anonymous(mut self, allow: bool) -> Self {
            self.allow_anonymous = allow;
            self
        }
    }
}

impl<A: fmt::Debug, C> fmt::Debug for HttpAuthorizer<A, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpAuthorizer")
            .field("authorizer", &self.authorizer)
            .field("allow_anonymous", &self.allow_anonymous)
            .field(
                "_credentials",
                &format_args!("{}", std::any::type_name::<fn() -> C>()),
            )
            .finish()
    }
}

impl<A: Clone, C> Clone for HttpAuthorizer<A, C> {
    fn clone(&self) -> Self {
        Self {
            authorizer: self.authorizer.clone(),
            allow_anonymous: self.allow_anonymous,
            _credentials: PhantomData,
        }
    }
}

impl<A, C> Authorizer<C> for HttpAuthorizer<A, C>
where
    A: Authorizer<C, Error: fmt::Debug>,
    C: Credentials + Send + 'static,
{
    type Error = Response;

    async fn authorize(&self, credentials: C) -> AuthorizeResult<C, Self::Error> {
        let AuthorizeResult {
            credentials,
            result,
        } = self.authorizer.authorize(credentials).await;

        let result = result.map_err(|err| {
            tracing::trace!("input credentials were not authorized: {err:?}");
            let mut res = Response::new(Body::empty());
            *res.status_mut() = StatusCode::UNAUTHORIZED;
            res.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(C::SCHEME),
            );
            res
        });

        AuthorizeResult {
            credentials,
            result,
        }
    }
}

impl<ReqBody, A, C> ValidateRequest<ReqBody> for HttpAuthorizer<A, C>
where
    ReqBody: Send + 'static,
    A: Authorizer<C, Error: fmt::Debug>,
    C: Credentials + Send + 'static,
{
    type ResponseBody = Body;

    async fn validate(
        &self,
        mut ctx: Context,
        request: Request<ReqBody>,
    ) -> Result<(Context, Request<ReqBody>), Response<Self::ResponseBody>> {
        match request.headers().typed_get::<Authorization<C>>() {
            Some(auth) => {
                let AuthorizeResult { result, .. } = self.authorize(auth.into_inner()).await;
                match result {
                    Ok(maybe_ext) => {
                        if let Some(ext) = maybe_ext {
                            ctx.extend(ext);
                        }
                        Ok((ctx, request))
                    }
                    Err(response) => Err(response),
                }
            }
            None => {
                if self.allow_anonymous {
                    let mut ctx = ctx;
                    ctx.insert(UserId::Anonymous);
                    Ok((ctx, request))
                } else {
                    Err(StatusCode::UNAUTHORIZED.into_response())
                }
            }
        }
    }
}

impl<S, A, C> ValidateRequestHeader<S, HttpAuthorizer<A, C>> {
    #[inline]
    /// Validate the request with an [`HttpAuthorizer`].
    pub fn auth(inner: S, authorizer: impl Into<HttpAuthorizer<A, C>>) -> Self {
        Self::custom(inner, authorizer.into())
    }
}

impl<A, C> ValidateRequestHeaderLayer<HttpAuthorizer<A, C>> {
    #[inline]
    /// Validate the request with an [`HttpAuthorizer`].
    pub fn auth(authorizer: impl Into<HttpAuthorizer<A, C>>) -> Self {
        Self::custom(authorizer.into())
    }
}
