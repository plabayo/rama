use rama_core::error::{BoxError, ErrorContext};
use rama_http_types::body::OptionalBody;

use super::ValidateRequest;
use crate::{
    Body, Request, Response, StatusCode, header,
    mime::{Mime, MimeIter},
};
use std::{fmt, marker::PhantomData, sync::Arc};

/// Type that performs validation of the Accept header.
pub struct AcceptHeader<ResBody = Body> {
    header_value: Arc<Mime>,
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> AcceptHeader<ResBody> {
    /// Create a new `AcceptHeader` from the given Mime.
    pub(super) fn new(mime: Mime) -> Self {
        Self {
            header_value: Arc::new(mime),
            _ty: PhantomData,
        }
    }

    /// Try a new `AcceptHeader` from the given header utf-8 value.
    ///
    /// # Errors
    ///
    /// Errors if `header_value` is not in the form: `type/subtype`, such as `application/json`
    pub(super) fn try_new(header_value: &str) -> Result<Self, BoxError> {
        Ok(Self {
            header_value: Arc::new(
                header_value
                    .parse::<Mime>()
                    .context("value is not a valid header value")?,
            ),
            _ty: PhantomData,
        })
    }
}

impl<ResBody> Clone for AcceptHeader<ResBody> {
    fn clone(&self) -> Self {
        Self {
            header_value: self.header_value.clone(),
            _ty: PhantomData,
        }
    }
}

impl<ResBody> fmt::Debug for AcceptHeader<ResBody> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcceptHeader")
            .field("header_value", &self.header_value)
            .finish()
    }
}

impl<B, ResBody> ValidateRequest<B> for AcceptHeader<ResBody>
where
    B: Send + Sync + 'static,
    ResBody: Send + 'static,
{
    type ResponseBody = OptionalBody<ResBody>;

    async fn validate(&self, req: Request<B>) -> Result<Request<B>, Response<Self::ResponseBody>> {
        if !req.headers().contains_key(header::ACCEPT) {
            return Ok(req);
        }
        if req
            .headers()
            .get_all(header::ACCEPT)
            .into_iter()
            .filter_map(|header| header.to_str().ok())
            .any(|h| {
                MimeIter::new(h)
                    .map(|mim| {
                        if let Ok(mim) = mim {
                            let typ = self.header_value.type_();
                            let subtype = self.header_value.subtype();
                            match (mim.type_(), mim.subtype()) {
                                (t, s) if t == typ && s == subtype => true,
                                (t, crate::mime::STAR) if t == typ => true,
                                (crate::mime::STAR, crate::mime::STAR) => true,
                                _ => false,
                            }
                        } else {
                            false
                        }
                    })
                    .reduce(|acc, mim| acc || mim)
                    .unwrap_or(false)
            })
        {
            return Ok(req);
        }
        let mut res = Response::new(OptionalBody::none());
        *res.status_mut() = StatusCode::NOT_ACCEPTABLE;
        Err(res)
    }
}
