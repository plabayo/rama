use rama_core::{bytes::Bytes, error::BoxError, Context, Service};
use rama_http_types::{Request, Response};
use rama_http_types::dep::http_body;
use crate::layer::har::spec;
use crate::layer::traffic_writer::RequestWriter;
use tokio::sync::Mutex;
use std::sync::Arc;

#[derive(Default)]
pub struct Recorder {
    data: Vec<spec::Log>,
}

impl Recorder {
    pub fn record_request<B>(&mut self, _req: &Request<B>) -> Result<(), BoxError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
    {
        // logic to record the request
        Ok(())
    }

    pub fn record_response<B>(&mut self, _res: &Response<B>) -> Result<(), BoxError>
    where
        B: http_body::Body<Data = Bytes> + Send + 'static,
    {
        // logic to record the response
        Ok(())
    }
}

pub struct HARExportService<S, T> {
    pub(crate) inner: S,
    pub(crate) toggle: T,
    pub(crate) recorder: Arc<Mutex<Recorder>>,
}

impl<State, S, W, ReqBody, ResBody> Service<State, Request<ReqBody>> for HARExportService<S, W>
where
    State: Clone + Send + Sync + 'static,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: Into<BoxError> + Send + Sync + std::error::Error + 'static,
    W: RequestWriter,
    ReqBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        {
            let mut guard = self.recorder.lock().await;
            guard.record_request(&req)?;
        }

        let response = self.inner.serve(ctx, req).await?;

        {
            let mut guard = self.recorder.lock().await;
            guard.record_response(&response)?;
        }

        Ok(response)
    }
}
