use super::ValidateRequest;
use crate::{
    http::dep::mime::{Mime, MimeIter},
    http::{header, Request, Response, StatusCode},
    service::Context,
};
use std::{fmt, marker::PhantomData, sync::Arc};

/// Type that performs validation of the Accept header.
pub struct AcceptHeader<ResBody = crate::http::Body> {
    header_value: Arc<Mime>,
    _ty: PhantomData<fn() -> ResBody>,
}

impl<ResBody> AcceptHeader<ResBody> {
    /// Create a new `AcceptHeader`.
    ///
    /// # Panics
    ///
    /// Panics if `header_value` is not in the form: `type/subtype`, such as `application/json`
    pub(super) fn new(header_value: &str) -> Self
    where
        ResBody: Default,
    {
        Self {
            header_value: Arc::new(
                header_value
                    .parse::<Mime>()
                    .expect("value is not a valid header value"),
            ),
            _ty: PhantomData,
        }
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

impl<S, B, ResBody> ValidateRequest<S, B> for AcceptHeader<ResBody>
where
    S: Send + Sync + 'static,
    B: Send + Sync + 'static,
    ResBody: Default + Send + 'static,
{
    type ResponseBody = ResBody;

    async fn validate(
        &self,
        ctx: Context<S>,
        req: Request<B>,
    ) -> Result<(Context<S>, Request<B>), Response<Self::ResponseBody>> {
        if !req.headers().contains_key(header::ACCEPT) {
            return Ok((ctx, req));
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
                                (t, mime::STAR) if t == typ => true,
                                (mime::STAR, mime::STAR) => true,
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
            return Ok((ctx, req));
        }
        let mut res = Response::new(ResBody::default());
        *res.status_mut() = StatusCode::NOT_ACCEPTABLE;
        Err(res)
    }
}
