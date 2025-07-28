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
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct Recorder {
    data: Vec<HarLog>,
}

impl Recorder {
    pub fn push_new_line(&mut self, line: HarLog) {
        self.data.push(line);
    }
    // might be overkill -v-

    // pub fn record_request<B>(&mut self, req: &Request<B>, entry: &mut Entry) -> Result<(), BoxError>
    // where
    //     B: http_body::Body<Data = Bytes> + Send + 'static,
    // {
    //     Ok(())
    // }

    // pub fn record_response<B>(&mut self, _res: &Response<B>, entry: &mut Entry) -> Result<(), BoxError>
    // where
    //     B: http_body::Body<Data = Bytes> + Send + 'static,
    // {
    //     entry.response = HarRequest::from_rama_response(req);
    //     Ok(())
    // }
}

pub struct HARExportService<S, T> {
    pub(crate) inner: S,
    // tokio Signal instead?
    pub(crate) toggle: T,
    pub(crate) recorder: Arc<Mutex<Recorder>>,
}

impl<State, S, W, ReqBody, ResBody> Service<State, Request<ReqBody>> for HARExportService<S, W>
where
    State: Clone + Send + Sync + 'static,
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
            entry.request = HarRequest::from_rama_request(&req);
            // TODO
            // entry.response = HarResponse::from_rama_response(req);

            // NOTE: This assumes that there is only ever one pair of request/response
            // might need more customization on how entries are pushed/composed
            log_line.entries = vec![entry];

            {
                let mut guard = self.recorder.lock().await;
                guard.push_new_line(log_line)
            }
        }

        Ok(response)
    }
}
