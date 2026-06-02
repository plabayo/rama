use rama::{
    Service,
    error::{BoxError, ErrorContext},
    http::{Body, Request, Response, StreamingBody, body::util::BodyExt},
};

use super::super::feed::{self, FeedKind, FeedTuiCandidate};
use super::writer::Writer;

#[derive(Debug, Clone)]
pub(super) struct ResponseBodyLogger<S> {
    pub(super) inner: S,
    pub(super) writer: Writer,
    /// When set, feed responses are passed through unwritten (tagged with
    /// [`FeedTuiCandidate`]) so the caller can render them in the reader.
    pub(super) feed_tui: bool,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ResponseBodyLogger<S>
where
    S: Service<Request<ReqBody>, Output = Response<ResBody>, Error: Into<BoxError>>,
    ReqBody: Send + 'static,
    ResBody: StreamingBody<Data = rama::bytes::Bytes, Error: Into<BoxError> + Send + Sync + 'static>
        + Send
        + 'static,
{
    type Error = BoxError;
    type Output = Response;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let res = self.inner.serve(req).await.into_box_error()?;

        let (parts, body) = res.into_parts();

        // A feed bound for an interactive terminal must reach the reader
        // unconsumed — don't write it, just tag it and pass the body through.
        if self.feed_tui
            && let Some(kind) = feed::feed_kind(&parts.headers)
        {
            parts.extensions.insert(FeedTuiCandidate {
                generic: kind == FeedKind::GenericXml,
            });
            let res = Response::from_parts(parts, Body::from_stream(body.into_data_stream()));
            return Ok(res);
        }

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
