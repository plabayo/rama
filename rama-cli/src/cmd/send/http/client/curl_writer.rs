use rama::{
    Service,
    error::{ErrorContext as _, OpaqueError},
    http::{
        Request, Response, StatusCode, body::util::BodyExt as _, convert::curl,
        service::web::response::IntoResponse as _,
    },
    service::MirrorService,
    ua::layer::emulate::UserAgentEmulateHttpRequestModifier,
};

use super::writer::Writer;

#[derive(Debug, Clone)]
pub(super) struct CurlWriter {
    pub(super) writer: Writer,
}

impl Service<Request> for CurlWriter {
    type Error = OpaqueError;
    type Output = Response;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let req = UserAgentEmulateHttpRequestModifier::new(MirrorService::new())
            .serve(req)
            .await
            .map_err(OpaqueError::from_boxed)
            .context("rama: (curl-writer) emulate UA")?;

        let (parts, body) = req.into_parts();
        let payload = body
            .collect()
            .await
            .context("rama: (curl-writer) collect req payload")?
            .to_bytes();
        let curl_cmd = curl::cmd_string_for_request_parts_and_payload(&parts, &payload);

        self.writer
            .write_bytes(curl_cmd.as_bytes())
            .await
            .context("rama: write curl command")?;

        Ok(StatusCode::OK.into_response())
    }
}
