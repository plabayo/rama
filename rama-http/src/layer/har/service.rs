use crate::body::util::BodyExt;
use crate::layer::har::recorder::Recorder;
use crate::layer::har::spec::{
    Cache, Entry, Log as HarLog, Request as HarRequest, Response as HarResponse, Timings,
};
use crate::layer::har::toggle::Toggle;
use crate::{Body, Request, Response, StreamingBody};

use jiff::Timestamp;

use rama_core::error::{BoxError, ErrorContext as _};
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_core::{Service, bytes::Bytes};
use tokio::time::Instant;

#[derive(Clone)]
pub struct HARExportService<R, S, T> {
    pub(super) recorder: R,
    pub(super) service: S,
    pub(super) toggle: T,

    pub(super) preserve_sensitive: bool,
}

impl<R, S, T> HARExportService<R, S, T> {
    pub fn recorder(&self) -> &R {
        &self.recorder
    }

    pub fn toggle(&self) -> &T {
        &self.toggle
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to preserve sensitive headers (false by default).
        pub fn preserve_sensitive(mut self) -> Self {
            self.preserve_sensitive = true;
            self
        }
    }
}

impl<R, S, W, ReqBody, ResBody> Service<Request<ReqBody>> for HARExportService<R, S, W>
where
    R: Recorder,
    S: Service<Request, Output = Response<ResBody>>,
    S::Error: Into<BoxError> + Send + Sync + 'static,
    W: Toggle,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        struct EntryStartInfo {
            start_time: Timestamp,
            begin: Instant, // TODO: replace with total time
            request: HarRequest,
        }

        let (request, maybe_entry_start_info) = if self.toggle.status().await {
            let start_time = Timestamp::now();
            // need to collect it first as bodies are (potentially) streaming
            let (req_parts, req_body) = req.into_parts();
            let req_body_bytes = req_body
                .collect()
                .await
                .context("collect request body for HAR recording and inner svc")?
                .to_bytes();

            let har_req_result = HarRequest::from_http_request_parts(
                &req_parts,
                &req_body_bytes,
                self.preserve_sensitive,
            );
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

        // Grab the collector before the request is consumed. It is an Arc handle, so
        // the clone stays tied to the buffer the relay pushes into. Note this is read
        // again below as soon as the inner service returns: for an upgrade that is
        // before the relay has run, so the buffer is still empty there.
        #[cfg(feature = "ws-har")]
        let ws_collector = request
            .extensions()
            .get_ref::<super::extensions::WebSocketMessages>()
            .cloned();

        let result = self.service.serve(request).await;

        if let Some(entry_start_info) = maybe_entry_start_info {
            let (result, response) = match result {
                Ok(resp) => {
                    let (resp_parts, resp_body) = resp.into_parts();
                    let resp_body_bytes = resp_body
                        .collect()
                        .await
                        .context("collect response body for HAR recording and return value")?
                        .to_bytes();

                    let maybe_response = match HarResponse::from_http_response_parts(
                        &resp_parts,
                        &resp_body_bytes,
                        self.preserve_sensitive,
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

            #[cfg(feature = "ws-har")]
            let ws_messages = ws_collector.as_ref().and_then(|c| c.take());

            // TODO: populate these in future
            let timings = Timings::default();
            let cache = Cache::default();

            let entry = Entry {
                page_ref: None,
                started_date_time: entry_start_info.start_time,
                time: entry_start_info
                    .begin
                    .elapsed()
                    .as_millis()
                    .min(i64::MAX as u128) as i64,
                request: entry_start_info.request,
                response,
                cache,
                timings,
                // TODO: when used as server middleware it is SocketInfo local addr,
                //       but when used via client middleware it is supposed to be the resolved address,
                //       which I am not sure is already exposed (TODO^2)
                server_ip_address: None,
                connection: None, // TODO
                comment: None,
                // Present only when a relay collected frames for this connection; an
                // ordinary entry leaves it None and serialises exactly as before.
                #[cfg(feature = "ws-har")]
                web_socket_messages: ws_messages,
            };

            let log_line = HarLog {
                entries: vec![entry],
                ..Default::default()
            };

            let maybe_resp_extensions = self.recorder.record(log_line).await;

            let result = match (result, maybe_resp_extensions) {
                (Ok(resp), Some(resp_extensions)) => {
                    tracing::trace!("extend (ok) response with HAR recorder extensions");
                    resp.extensions().extend(&resp_extensions);
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
