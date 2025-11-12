use rama::{
    Service,
    error::{BoxError, ErrorContext, OpaqueError},
    http::{Request, Response, StreamingBody, body::util::BodyExt},
};

use super::writer::Writer;

#[derive(Debug)]
pub(super) struct ResponseBodyLogger<S> {
    pub(super) inner: S,
    pub(super) writer: Writer,
}

impl<S: Clone> Clone for ResponseBodyLogger<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            writer: self.writer.clone(),
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyLogger<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data: Send + 'static, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Error = OpaqueError;
    type Response = Response;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        let res = self
            .inner
            .serve(req)
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))?;

        let (parts, body) = res.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|err| OpaqueError::from_boxed(err.into()))
            .context("collect res body as bytes")?
            .to_bytes();

        self.writer
            .write_bytes(bytes.as_ref())
            .await
            .context("write response bytes")?;

        let res = Response::from_parts(parts, bytes.into());
        Ok(res)
    }
}
