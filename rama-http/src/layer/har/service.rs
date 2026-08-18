use crate::layer::har::recorder::{
    HttpRequestCapture, HttpResponseCapture, RecorderSession, StreamingRecorder, WebSocketCapture,
    body_capture_channel,
};
use crate::layer::har::spec::{Request as HarRequest, Response as HarResponse};
use crate::layer::har::toggle::Toggle;
use crate::{Body, Request, Response, StreamingBody};

use jiff::Timestamp;
use rama_core::error::BoxError;
use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing;
use rama_core::{Service, bytes::Bytes};
use rama_http_types::proto::h2::ext::Protocol;
use tokio::time::Instant;

#[derive(Clone)]
pub struct HARExportService<R, S, T> {
    pub(super) recorder: R,
    pub(super) service: S,
    pub(super) toggle: T,

    pub(super) preserve_sensitive: bool,
}

struct ActiveRecording<S> {
    session: S,
    web_socket_capture: Option<WebSocketCapture>,
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
    R: StreamingRecorder,
    S: Service<Request, Output = Response<ResBody>, Error: Into<BoxError> + Send + Sync + 'static>,
    W: Toggle,
    ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
{
    type Output = Response;
    type Error = BoxError;

    async fn serve(&self, req: Request<ReqBody>) -> Result<Self::Output, Self::Error> {
        let (request, recording) = if self.toggle.status().await {
            self.start_recording(req).await
        } else {
            self.recorder.stop_record().await;
            (req.map(Body::new), None)
        };

        let result = self.service.serve(request).await;
        let Some(recording) = recording else {
            return result
                .map(|response| response.map(Body::new))
                .map_err(Into::into);
        };

        match result {
            Ok(response) => self.record_response(recording, response).await,
            Err(err) => {
                if let Some(capture) = recording.web_socket_capture {
                    capture.close();
                }
                _ = recording.session.record_request_only().await;
                Err(err.into())
            }
        }
    }
}

impl<R, S, W> HARExportService<R, S, W>
where
    R: StreamingRecorder,
{
    async fn start_recording<ReqBody>(
        &self,
        request: Request<ReqBody>,
    ) -> (Request, Option<ActiveRecording<R::Session>>)
    where
        ReqBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        let start_time = Timestamp::now();
        let begin = Instant::now();
        let (parts, body) = request.into_parts();
        let har_request =
            match HarRequest::from_http_request_parts(&parts, &[], self.preserve_sensitive) {
                Ok(request) => request,
                Err(err) => {
                    tracing::debug!(
                        "failed to create HAR request from incoming HTTP Request: {err}"
                    );
                    return (Request::from_parts(parts, Body::new(body)), None);
                }
            };

        let mime_type = super::spec::get_mime(&parts.headers);
        let web_socket = is_web_socket_request(&parts);
        let (sink, body_stream) = body_capture_channel();
        let capture = HttpRequestCapture {
            started_date_time: start_time,
            begin,
            request: har_request,
            body_mime_type: mime_type,
            body: body_stream,
            web_socket,
        };

        match self.recorder.start_http_recording(capture).await {
            Some(session) => {
                let web_socket_capture = if web_socket {
                    session.web_socket_capture()
                } else {
                    None
                };
                if let Some(capture) = &web_socket_capture {
                    parts.extensions.insert(capture.clone());
                }
                (
                    Request::from_parts(parts, Body::new(body).capture(sink)),
                    Some(ActiveRecording {
                        session,
                        web_socket_capture,
                    }),
                )
            }
            None => (Request::from_parts(parts, Body::new(body)), None),
        }
    }

    async fn record_response<ResBody>(
        &self,
        recording: ActiveRecording<R::Session>,
        response: Response<ResBody>,
    ) -> Result<Response, BoxError>
    where
        ResBody: StreamingBody<Data = Bytes, Error: Into<BoxError>> + Send + Sync + 'static,
    {
        let (parts, body) = response.into_parts();
        let har_response =
            match HarResponse::from_http_response_parts(&parts, &[], self.preserve_sensitive) {
                Ok(response) => response,
                Err(err) => {
                    tracing::debug!(
                        "failed to create HAR response from returned HTTP Response: {err}"
                    );
                    if let Some(capture) = recording.web_socket_capture {
                        capture.close();
                    }
                    let extensions = recording.session.record_request_only().await;
                    let response = Response::from_parts(parts, Body::new(body));
                    extend_response(&response, extensions);
                    return Ok(response);
                }
            };

        let (sink, body_stream) = body_capture_channel();
        if let Some(capture) = recording.web_socket_capture {
            if is_successful_web_socket_response(&parts) {
                parts.extensions.insert(capture);
            } else {
                capture.close();
            }
        }
        let extensions = recording
            .session
            .record_response(HttpResponseCapture {
                response: har_response,
                body: body_stream,
            })
            .await;
        let response = Response::from_parts(parts, Body::new(body).capture(sink));
        extend_response(&response, extensions);
        Ok(response)
    }
}

fn is_web_socket_request(parts: &rama_http_types::request::Parts) -> bool {
    parts
        .extensions
        .get_ref::<Protocol>()
        .is_some_and(|protocol| protocol.as_str().eq_ignore_ascii_case("websocket"))
        || parts
            .headers
            .get_all(rama_http_types::header::UPGRADE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|protocol| protocol.trim().eq_ignore_ascii_case("websocket"))
}

fn is_successful_web_socket_response(parts: &rama_http_types::response::Parts) -> bool {
    match parts.version {
        rama_http_types::Version::HTTP_2 | rama_http_types::Version::HTTP_3 => {
            parts.status.is_success()
        }
        _ => parts.status == rama_http_types::StatusCode::SWITCHING_PROTOCOLS,
    }
}

fn extend_response(response: &Response, extensions: Option<rama_core::extensions::Extensions>) {
    if let Some(extensions) = extensions {
        tracing::trace!("extend response with HAR recorder extensions");
        response.extensions().extend(&extensions);
    }
}

#[cfg(test)]
mod tests {
    use super::{is_successful_web_socket_response, is_web_socket_request};
    use crate::{Request, Response, StatusCode, Version, proto::h2::ext::Protocol};
    use rama_core::extensions::ExtensionsRef;

    fn response_parts(status: StatusCode, version: Version) -> rama_http_types::response::Parts {
        let (mut parts, _) = Response::new(()).into_parts();
        parts.status = status;
        parts.version = version;
        parts
    }

    #[test]
    fn validates_web_socket_response_by_http_version() {
        assert!(is_successful_web_socket_response(&response_parts(
            StatusCode::SWITCHING_PROTOCOLS,
            Version::HTTP_11,
        )));
        assert!(!is_successful_web_socket_response(&response_parts(
            StatusCode::OK,
            Version::HTTP_11,
        )));
        assert!(is_successful_web_socket_response(&response_parts(
            StatusCode::OK,
            Version::HTTP_2,
        )));
        assert!(is_successful_web_socket_response(&response_parts(
            StatusCode::CREATED,
            Version::HTTP_2,
        )));
        assert!(!is_successful_web_socket_response(&response_parts(
            StatusCode::BAD_REQUEST,
            Version::HTTP_2,
        )));
    }

    #[test]
    fn detects_h1_upgrade_and_h2_extended_connect_requests() {
        let (h1, _) = Request::builder()
            .header("upgrade", "h2c, WebSocket")
            .body(())
            .unwrap()
            .into_parts();
        assert!(is_web_socket_request(&h1));

        let mut h2 = Request::new(());
        *h2.version_mut() = Version::HTTP_2;
        h2.extensions().insert(Protocol::from_static("websocket"));
        let (h2, _) = h2.into_parts();
        assert!(is_web_socket_request(&h2));

        let (plain, _) = Request::new(()).into_parts();
        assert!(!is_web_socket_request(&plain));
    }
}
