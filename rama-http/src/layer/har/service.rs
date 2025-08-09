use crate::layer::har::Recorder;
use crate::layer::har::spec::{
    Cache, Entry, Log as HarLog, Request as HarRequest, Response as HarResponse, Timings,
};
use crate::layer::har::toggle::Toggle;
use rama_core::{Context, Service, bytes::Bytes, error::BoxError};
use rama_http_types::dep::http_body;
use rama_http_types::{Request, Response};
use rama_net::stream::SocketInfo;

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
    ResBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Clone + Send + Sync + 'static,
{
    type Response = Response<ResBody>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {

        let server_ip_address = ctx
            .get::<SocketInfo>()
            .and_then(|socket| socket.local_addr().copied());

        let result = self.service.serve(ctx, req.clone()).await;

        if self.toggle.status().await {
            let mut log_line = HarLog::default();
            let request = HarRequest::from_rama_request::<ReqBody>(&req).await?;
            let mut response: Option<HarResponse> = None;

            if let Ok(ref resp) = result {
                response = Some(HarResponse::from_rama_response::<ResBody>(resp).await?);
            }

            // dummy information
            let timings = Timings {
                blocked: None,
                dns: None,
                connect: None,
                send: 0,
                wait: 0,
                receive: 0,
                ssl: None,
                comment: None,
            };

            // dummy info
            let cache = Cache {
                before_request: None,
                after_request: None,
                comment: None,
            };

            let entry = Entry::new(
                "started_date_time".to_owned(),
                0, // time elapsed
                request,
                response,
                cache,
                timings,
                server_ip_address,
            );

            // Push the entry into the log even on service error
            log_line.entries = vec![entry];
            self.recorder.record(log_line).await;
        }

        result.map_err(Into::into)
    }
}
