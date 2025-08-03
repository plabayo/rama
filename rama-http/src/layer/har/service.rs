use crate::layer::har::Recorder;
use crate::layer::har::spec::{
    Entry,
    Log as HarLog,
    Request as HarRequest,
    //Response as HarResponse,
};
use crate::layer::har::toggle::Toggle;
use rama_core::{Context, Service, bytes::Bytes, error::BoxError};
use rama_http_types::dep::http_body;
use rama_http_types::{Request, Response};

pub struct HARExportService<R, S, T> {
    pub(crate) recorder: R,
    pub(crate) service: S,
    pub(crate) toggle: T,
}

impl<State, R, S, W, ReqBody, ResBody> Service<State, Request<ReqBody>>
    for HARExportService<R, S, W>
where
    State: Clone + Send + Sync + 'static,
    R: Recorder,
    S: Service<State, Request<ReqBody>, Response = Response<ResBody>>,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    W: Toggle,
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
        let result = self.service.serve(ctx, req.clone()).await;

        if self.toggle.status().await {
            let mut entry = Entry::default();
            let mut log_line = HarLog::default();
            entry.request = HarRequest::from_rama_request::<ReqBody>(&req)?;

            if let Ok(ref _response) = result {
                // TODO
                // entry.response = HarResponse::from_rama_response(response);
            }

            // Push the entry into the log even on service error
            log_line.entries = vec![entry];
            self.recorder.record(log_line).await;
        }

        result.map_err(Into::into)
    }
}
