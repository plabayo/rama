use crate::dep::http_body;
use crate::dep::http_body_util::BodyExt;
use crate::layer::har::Recorder;
use crate::layer::har::spec::{
    Cache, Entry, Log as HarLog, Request as HarRequest, Response as HarResponse, Timings,
};
use crate::layer::har::toggle::Toggle;
use crate::{Body, Request, Response};

use chrono::Utc;

use rama_core::telemetry::tracing;
use rama_core::{Context, Service, bytes::Bytes, error::BoxError};
use rama_error::{ErrorExt, OpaqueError};
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
    S: Service<State, Request, Response = Response<ResBody>>,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    W: Toggle,
    ReqBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: http_body::Body<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        let server_ip_address = ctx
            .get::<SocketInfo>()
            .and_then(|socket| socket.local_addr().copied());

        // need to collect it first as bodies are (potentially) streaming
        let (req_parts, req_body) = req.into_parts();
        let req_body_bytes = req_body
            .collect()
            .await
            .map_err(|err| {
                OpaqueError::from_boxed(err.into())
                    .context("collect request body for HAR recording and inner svc")
            })?
            .to_bytes();

        let request = if self.toggle.status().await {
            match HarRequest::from_rama_request_parts(&ctx, req_parts.clone(), &req_body_bytes) {
                Err(err) => {
                    tracing::debug!(
                        "failed to create HAR request from incoming HTTP Request: {err}"
                    );
                    None
                }
                Ok(request) => Some(request),
            }
        } else {
            None
        };

        let svc_req = Request::from_parts(req_parts.clone(), Body::from(req_body_bytes));
        let result = self.service.serve(ctx, svc_req).await;

        if let Some(request) = request {
            let (result, response) = match result {
                Ok(resp) => {
                    let (resp_parts, resp_body) = resp.into_parts();
                    let resp_body_bytes = resp_body
                        .collect()
                        .await
                        .map_err(|err| {
                            OpaqueError::from_boxed(err.into())
                                .context("collect response body for HAR recording and return value")
                        })?
                        .to_bytes();

                    let maybe_response = match HarResponse::from_rama_response_parts(
                        resp_parts.clone(),
                        &resp_body_bytes,
                    ) {
                        Err(err) => {
                            tracing::debug!(
                                "failed to create HAR response from returned HTTP Response: {err}"
                            );
                            None
                        }
                        Ok(resp) => Some(resp),
                    };

                    let result = Ok(Response::from_parts(
                        resp_parts,
                        Body::from(resp_body_bytes),
                    ));

                    (result, maybe_response)
                }
                Err(err) => (Err(err.into()), None),
            };

            let timings = Timings::default();
            let cache = Cache::default();

            let entry = Entry::new(
                Utc::now(),
                0, // time elapsed
                request,
                response,
                cache,
                timings,
                server_ip_address,
            );

            let log_line = HarLog {
                entries: vec![entry],
                ..Default::default()
            };

            self.recorder.record(log_line).await;

            return result;
        }

        match result {
            Ok(response) => Ok(response.map(Body::new)),
            Err(err) => Err(err.into()),
        }
    }
}
