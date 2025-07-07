use rama_core::telemetry::tracing::trace;
use rama_core::{Context, Service, error::BoxError};
use rama_http::conn::OriginalHttpVersion;
use rama_http::utils::RequestSwitchVersionExt;
use rama_http_types::Request;
use rama_net::tls::client::NegotiatedTlsParameters;

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
        mut ctx: Context<State>,
        mut req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proto) = ctx
            .get::<NegotiatedTlsParameters>()
            .and_then(|params| params.application_layer_protocol.as_ref())
        {
            let new_version = proto.try_into()?;
            trace!(
                "setting request version to {:?} based on negotiated APLN (was: {:?})",
                new_version,
                req.version(),
            );

            if req.version() != new_version {
                ctx.insert(OriginalHttpVersion(req.version()));
                req.switch_version(new_version)?;
            }
        }
        Ok((ctx, req))
    }
}
