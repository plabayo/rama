use rama_core::{Service, error::BoxError};
use rama_http_types::{
    Request, Uri,
    uri::{Authority, Scheme},
};

#[derive(Debug)]
pub(crate) struct AddOrigin<T> {
    inner: T,
    scheme: Option<Scheme>,
    authority: Option<Authority>,
}

impl<T> AddOrigin<T> {
    pub(crate) fn new(inner: T, origin: Uri) -> Self {
        let rama_http_types::uri::Parts {
            scheme, authority, ..
        } = origin.into_parts();

        Self {
            inner,
            scheme,
            authority,
        }
    }
}

impl<T, ReqBody> Service<Request<ReqBody>> for AddOrigin<T>
where
    T: Service<Request<ReqBody>>,
    T::Error: Into<BoxError>,
{
    type Output = T::Output;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        if self.scheme.is_none() || self.authority.is_none() {
            let err = crate::transport::Error::new_invalid_uri();
            return Err(err.into());
        }

        // Split the request into the head and the body.
        let (mut head, body) = req.into_parts();

        // Update the request URI
        head.uri = {
            // Split the request URI into parts.
            let mut uri: rama_http_types::uri::Parts = head.uri.into();
            // Update the URI parts, setting the scheme and authority
            uri.scheme = self.scheme.clone();
            uri.authority = self.authority.clone();

            rama_http_types::Uri::from_parts(uri).expect("valid uri")
        };

        let request = Request::from_parts(head, body);

        self.inner.serve(request).await.map_err(Into::into)
    }
}
