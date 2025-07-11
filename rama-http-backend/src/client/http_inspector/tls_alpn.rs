use rama_core::error::OpaqueError;
use rama_core::telemetry::tracing::trace;
use rama_core::{Context, Service, error::BoxError};
use rama_http::Version;
use rama_http::conn::TargetHttpVersion;
use rama_http_types::Request;
use rama_net::tls::client::NegotiatedTlsParameters;

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
/// Modifier that is used to configure [`TargetHttpVersion`]
/// with the negotiated version from tls alpn
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
        req: Request<ReqBody>,
    ) -> Result<Self::Response, Self::Error> {
        if let Some(proto) = ctx
            .get::<NegotiatedTlsParameters>()
            .and_then(|params| params.application_layer_protocol.as_ref())
        {
            let neg_version: Version = proto.try_into()?;
            if let Some(target_version) = ctx.get::<TargetHttpVersion>()
                && target_version.0 != neg_version
            {
                return Err(OpaqueError::from_display(format!(
                    "TargetHttpVersion was set to {target_version:?} but tls alpn negotiated {neg_version:?}"
                )).into_boxed());
            }

            trace!(
                "setting request TargetHttpVersion to {:?} based on negotiated APLN",
                neg_version,
            );
            ctx.insert(TargetHttpVersion(neg_version));
        }
        Ok((ctx, req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http::{Body, dep::http::Request};
    use tokio_test::assert_err;

    #[tokio::test]
    async fn test_should_set_target_version() {
        let modifier = HttpsAlpnModifier::new();
        let req = Request::new(Body::empty());

        let mut ctx = Context::default();
        ctx.insert(NegotiatedTlsParameters {
            application_layer_protocol: Some(rama_net::tls::ApplicationProtocol::HTTP_11),
            peer_certificate_chain: None,
            protocol_version: rama_net::tls::ProtocolVersion::TLSv1_3,
        });

        let (ctx, req) = modifier.serve(ctx, req).await.unwrap();

        let target_version = ctx.get::<TargetHttpVersion>().unwrap();
        assert_eq!(target_version.0, Version::HTTP_11);

        let mut ctx = Context::default();
        ctx.insert(NegotiatedTlsParameters {
            application_layer_protocol: Some(rama_net::tls::ApplicationProtocol::HTTP_2),
            peer_certificate_chain: None,
            protocol_version: rama_net::tls::ProtocolVersion::TLSv1_3,
        });

        let (ctx, _req) = modifier.serve(ctx, req).await.unwrap();

        let target_version = ctx.get::<TargetHttpVersion>().unwrap();
        assert_eq!(target_version.0, Version::HTTP_2);
    }

    #[tokio::test]
    async fn test_should_error_if_wrong_version_was_negotiated() {
        let modifier = HttpsAlpnModifier::new();
        let req = Request::new(Body::empty());

        let mut ctx = Context::default();

        ctx.insert(NegotiatedTlsParameters {
            application_layer_protocol: Some(rama_net::tls::ApplicationProtocol::HTTP_11),
            peer_certificate_chain: None,
            protocol_version: rama_net::tls::ProtocolVersion::TLSv1_3,
        });
        ctx.insert(TargetHttpVersion(Version::HTTP_2));

        let result = modifier.serve(ctx, req).await;
        assert_err!(result);
    }
}
