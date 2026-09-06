use rama::{
    Service,
    error::{BoxError, ErrorContext as _},
    extensions::ExtensionsRef as _,
    http::{
        Request, Response, StatusCode, body::util::BodyExt as _, convert::curl,
        header::PROXY_AUTHORIZATION, proxy::PlaintextHttpProxyMode,
        service::web::response::IntoResponse as _,
    },
    net::{ProtocolInputExt as _, client::ProxyRoute},
    service::MirrorService,
    ua::layer::emulate::UserAgentEmulateHttpRequestModifier,
};

use super::writer::Writer;

#[derive(Debug, Clone)]
pub(super) struct CurlWriter {
    pub(super) writer: Writer,
    pub(super) proxy_tunnel: bool,
    pub(super) forward_proxy_auth: bool,
}

impl Service<Request> for CurlWriter {
    type Error = BoxError;
    type Output = Response;

    async fn serve(&self, req: Request) -> Result<Self::Output, Self::Error> {
        let req = UserAgentEmulateHttpRequestModifier::new(MirrorService::new())
            .serve(req)
            .await
            .context("rama: (curl-writer) emulate UA")?;

        let (mut parts, body) = req.into_parts();
        let selected_proxy = parts
            .extensions()
            .get_ref::<ProxyRoute>()
            .and_then(ProxyRoute::proxy_address)
            .filter(|proxy| {
                proxy
                    .protocol
                    .as_ref()
                    .is_none_or(|protocol| protocol.is_http())
            });
        let proxy_mode = if self.proxy_tunnel {
            PlaintextHttpProxyMode::Tunnel
        } else {
            PlaintextHttpProxyMode::Forward
        };
        let is_forward_proxy =
            proxy_mode.should_forward(parts.protocol()) && selected_proxy.is_some();
        let configured_forward_credential = is_forward_proxy
            && self.forward_proxy_auth
            && selected_proxy.is_some_and(|proxy| proxy.credential.is_some());

        // Mirror the live client's credential boundary. A regular request
        // header can authenticate an established forward proxy, but it must
        // never be replayed to a direct, SOCKS, or CONNECT-tunneled origin.
        // A configured forward credential also wins over a manual value.
        if !is_forward_proxy || configured_forward_credential {
            parts.headers.remove(PROXY_AUTHORIZATION);
        }

        if is_forward_proxy
            && !self.forward_proxy_auth
            && let Some(ProxyRoute::Proxy(mut proxy)) =
                parts.extensions().get_ref::<ProxyRoute>().cloned()
        {
            proxy.credential = None;
            parts.extensions().insert(ProxyRoute::Proxy(proxy));
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
            curl::CurlExportOptions::default()
                .with_proxy_tunnel(self.proxy_tunnel)
                .with_script_compatibility(compatibility),
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
