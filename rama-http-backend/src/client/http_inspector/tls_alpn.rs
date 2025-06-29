use rama_core::telemetry::tracing::trace;
use rama_core::{
    Context, Service,
    error::{BoxError, OpaqueError},
};
use rama_http::Method;
use rama_http_headers::HeaderMapExt;
use rama_http_types::Request;
use rama_net::tls::{ApplicationProtocol, client::NegotiatedTlsParameters};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Modifier that is used to adapt the http [`Request`]
/// version based on agreed upon TLS ALPN.
pub struct HttpsAlpnModifier;

impl HttpsAlpnModifier {
    #[inline]
    pub fn new() -> Self {
        Self
    }
}

impl<State, ReqBody> Service<State, Request<ReqBody>> for HttpsAlpnModifier
where
    State: Clone + Send + Sync + 'static,
    ReqBody: Send + 'static,
{
    type Error = BoxError;
    type Response = (Context<State>, Request<ReqBody>);

    async fn serve(
        &self,
        ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proto) = ctx
            .get::<NegotiatedTlsParameters>()
            .and_then(|params| params.application_layer_protocol.as_ref())
        {
            let new_version = match proto {
                ApplicationProtocol::HTTP_09 => rama_http_types::Version::HTTP_09,
                ApplicationProtocol::HTTP_10 => rama_http_types::Version::HTTP_10,
                ApplicationProtocol::HTTP_11 => rama_http_types::Version::HTTP_11,
                ApplicationProtocol::HTTP_2 => rama_http_types::Version::HTTP_2,
                ApplicationProtocol::HTTP_3 => rama_http_types::Version::HTTP_3,
                _ => {
                    return Err(OpaqueError::from_display(
                        "HttpsAlpnModifier: unsupported negotiated ALPN: {proto}",
                    )
                    .into_boxed());
                }
            };
            trace!(
                "setting request version to {:?} based on negotiated APLN (was: {:?})",
                new_version,
                req.version(),
            );
            if (req.version() == rama_http_types::Version::HTTP_10
                || req.version() == rama_http_types::Version::HTTP_11)
                && new_version == rama_http_types::Version::HTTP_2
                && req
                    .headers()
                    .typed_get::<rama_http_headers::Upgrade>()
                    .is_some()
            {
                *req.method_mut() = Method::CONNECT;
            }
            *req.version_mut() = new_version;
        }
        Ok((ctx, req))
    }
}
