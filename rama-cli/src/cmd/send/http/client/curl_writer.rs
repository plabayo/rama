use rama::{
    Service,
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    http::{
        Request, Response, StatusCode, body::util::BodyExt as _, convert::curl,
        service::web::response::IntoResponse as _,
    },
    net::client::ProxyRoutes,
    service::MirrorService,
    ua::layer::emulate::UserAgentEmulateHttpRequestModifier,
};

use super::writer::Writer;

#[derive(Debug, Clone)]
pub(super) struct CurlWriter {
    pub(super) writer: Writer,
}

impl Service<Request> for CurlWriter {
    type Error = BoxError;
    type Output = Response;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let req = UserAgentEmulateHttpRequestModifier::new(MirrorService::new())
            .serve(req)
            .await
            .context("rama: (curl-writer) emulate UA")?;

        let (parts, body) = req.into_parts();
        if let Some(routes) = parts.extensions.get_ref::<ProxyRoutes>()
            && routes.as_slice().len() > 1
        {
            return Err(BoxError::from_static_str(
                "cannot export an ordered multi-route proxy plan as one curl command",
            )
            .context_field("proxy_route_count", routes.as_slice().len()));
        }
        let payload = body
            .collect()
            .await
            .context("rama: (curl-writer) collect req payload")?
            .to_bytes();
        let compatibility = if cfg!(windows) {
            curl::CurlScriptCompatibility::PowerShell
        } else {
            curl::CurlScriptCompatibility::Unix
        };
        let curl_cmd = curl::try_cmd_string_for_request_parts_and_payload_with_options(
            &parts,
            &payload,
            curl::CurlExportOptions::default().with_script_compatibility(compatibility),
            &curl::CurlScriptPayloadMode::Inline,
        )
        .context("rama: (curl-writer) create curl command")?;

        self.writer
            .write_bytes(curl_cmd.as_bytes())
            .await
            .context("rama: write curl command")?;

        Ok(StatusCode::OK.into_response())
    }
}
