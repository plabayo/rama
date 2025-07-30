use crate::layer::har::Toggle;
use crate::layer::har::spec::{
    Entry,
    Log as HarLog,
    Request as HarRequest, //Response as HarResponse,
};
use crate::layer::traffic_writer::RequestWriter;
use rama_core::{Context, Service, bytes::Bytes, error::BoxError};
use rama_http_types::dep::http_body;
use rama_http_types::{Request, Response};

pub trait Recorder: Clone + Send + Sync + 'static {
    fn record(&self, line: HarLog);
    fn data(&self) -> Vec<HarLog>;
}

pub struct HARExportService<R, S, T> {
    pub(crate) inner: S,
    pub(crate) toggle: T,
    pub(crate) recorder: R,
}

impl<State, R, S, W, ReqBody, ResBody> Service<State, Request<ReqBody>>
    for HARExportService<R, S, W>
where
    State: Clone + Send + Sync + 'static,
    R: Recorder,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: Into<BoxError> + Send + Sync + std::error::Error + 'static,
    W: RequestWriter + Toggle,
    ReqBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Clone + Send + Sync + 'static,
    ResBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let response = self.inner.serve(ctx, req.clone()).await?;

        if self.toggle.is_recording_on() {
            let mut entry = Entry::default();
            let mut log_line = HarLog::default();
            entry.request = HarRequest::from_rama_request::<ReqBody>(&req)?;
            // TODO
            // entry.response = HarResponse::from_rama_response(req);

            // NOTE: This assumes that there is only ever one pair of request/response
            // might need more customization on how entries are pushed/composed
            log_line.entries = vec![entry];
            self.recorder.record(log_line);
        }

        Ok(response)
    }
}
