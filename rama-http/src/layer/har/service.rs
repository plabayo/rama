use crate::body::util::BodyExt;
use crate::layer::har::recorder::Recorder;
use crate::layer::har::spec::{
    Cache, Entry, Log as HarLog, Request as HarRequest, Response as HarResponse, Timings,
};
use crate::layer::har::toggle::Toggle;
use crate::{Body, Request, Response, StreamingBody};

use chrono::{DateTime, Utc};

use rama_core::telemetry::tracing;
use rama_core::{Context, Service, bytes::Bytes, error::BoxError};
use rama_error::{ErrorExt, OpaqueError};
use tokio::time::Instant;

pub struct HARExportService<R, S, T> {
    pub(super) recorder: R,
    pub(super) service: S,
    pub(super) toggle: T,
}

impl<R, S, W, ReqBody, ResBody> Service<Request<ReqBody>> for HARExportService<R, S, W>
where
    R: Recorder,
    S: Service<Request, Response = Response<ResBody>>,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    W: Toggle,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Response = Response;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context,
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        struct EntryStartInfo {
            start_time: DateTime<Utc>,
            begin: Instant, // TODO: replace with total time
            request: HarRequest,
        }

        let (request, maybe_entry_start_info) = if self.toggle.status().await {
            let start_time = Utc::now();
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

            let har_req_result =
                HarRequest::from_http_request_parts(&ctx, &req_parts, &req_body_bytes);
            let request = Request::from_parts(req_parts, Body::from(req_body_bytes));

            match har_req_result {
                Err(err) => {
                    tracing::debug!(
                        "failed to create HAR request from incoming HTTP Request: {err}"
                    );
                    (request, None)
                }
                Ok(har_request) => {
                    let info = EntryStartInfo {
                        start_time,
                        begin: Instant::now(),
                        request: har_request,
                    };
                    (request, Some(info))
                }
            }
        } else {
            self.recorder.stop_record().await;
            (req.map(Body::new), None)
        };

        let result = self.service.serve(ctx, request).await;

        if let Some(entry_start_info) = maybe_entry_start_info {
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

                    let maybe_response = match HarResponse::from_http_response_parts(
                        &resp_parts,
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

            // TODO: populate these in future
            let timings = Timings::default();
            let cache = Cache::default();

            let entry = Entry {
                page_ref: None,
                started_date_time: entry_start_info.start_time,
                time: entry_start_info.begin.elapsed().as_millis() as u64,
                request: entry_start_info.request,
                response,
                cache,
                timings,
                // TODO: when used as server middleware it is SocketInfo local addr,
                //       but when used via client middleware it is supposed to be the resolved address,
                //       which I am not sure is already exposed (TODO^2)
                server_address: None,
                connection: None, // TODO
                comment: None,
            };

            let log_line = HarLog {
                entries: vec![entry],
                ..Default::default()
            };

            let maybe_resp_extensions = self.recorder.record(log_line).await;

            let result = match (result, maybe_resp_extensions) {
                (Ok(mut resp), Some(resp_extensions)) => {
                    tracing::trace!("extend (ok) response with HAR recorder extensions");
                    resp.extensions_mut().extend(resp_extensions);
                    Ok(resp)
                }
                (result, _) => result,
            };

            return result;
        }

        match result {
            Ok(response) => Ok(response.map(Body::new)),
            Err(err) => Err(err.into()),
        }
    }
}
