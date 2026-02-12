use rama::{
    Service,
    error::{BoxError, ErrorContext},
    http::{Request, Response, StreamingBody, body::util::BodyExt},
};

use super::writer::Writer;

#[derive(Debug, Clone)]
pub(super) struct ResponseBodyLogger<S> {
    pub(super) inner: S,
    pub(super) writer: Writer,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyLogger<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data: Send + 'static, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Error = BoxError;
    type Output = Response;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await.into_box_error()?;

        let (parts, body) = res.into_parts();
        let bytes = body
            .collect()
            .await
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
