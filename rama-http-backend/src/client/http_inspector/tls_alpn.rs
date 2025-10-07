use rama_core::error::OpaqueError;
use rama_core::extensions::{ExtensionsMut, ExtensionsRef};
use rama_core::telemetry::tracing::trace;
use rama_core::{Service, error::BoxError};
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
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl<ReqBody> Service<Request<ReqBody>> for HttpsAlpnModifier
where
    ReqBody: Send + 'static,
{
    type Error = BoxError;
    type Response = Request<ReqBody>;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        if let Some(proto) = req
            .extensions()
            .get::<NegotiatedTlsParameters>()
            .and_then(|params| params.application_layer_protocol.as_ref())
        {
            let neg_version: Version = proto.try_into()?;
            if let Some(target_version) = req.extensions().get::<TargetHttpVersion>()
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
            req.extensions_mut().insert(TargetHttpVersion(neg_version));
        }
        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http::{Body, Request};
    use tokio_test::assert_err;

    #[tokio::test]
    async fn test_should_set_target_version() {
        let modifier = HttpsAlpnModifier::new();
        let mut req = Request::new(Body::empty());

        req.extensions_mut().insert(NegotiatedTlsParameters {
            application_layer_protocol: Some(rama_net::tls::ApplicationProtocol::HTTP_11),
            peer_certificate_chain: None,
            protocol_version: rama_net::tls::ProtocolVersion::TLSv1_3,
        });

        let req = modifier.serve(req).await.unwrap();

        let target_version = req.extensions().get::<TargetHttpVersion>().unwrap();
        assert_eq!(target_version.0, Version::HTTP_11);

        let mut req = Request::new(Body::empty());
        req.extensions_mut().insert(NegotiatedTlsParameters {
            application_layer_protocol: Some(rama_net::tls::ApplicationProtocol::HTTP_2),
            peer_certificate_chain: None,
            protocol_version: rama_net::tls::ProtocolVersion::TLSv1_3,
        });

        let req = modifier.serve(req).await.unwrap();

        let target_version = req.extensions().get::<TargetHttpVersion>().unwrap();
        assert_eq!(target_version.0, Version::HTTP_2);
    }

    #[tokio::test]
    async fn test_should_error_if_wrong_version_was_negotiated() {
        let modifier = HttpsAlpnModifier::new();
        let mut req = Request::new(Body::empty());

        req.extensions_mut().insert(NegotiatedTlsParameters {
            application_layer_protocol: Some(rama_net::tls::ApplicationProtocol::HTTP_11),
            peer_certificate_chain: None,
            protocol_version: rama_net::tls::ProtocolVersion::TLSv1_3,
        });
        req.extensions_mut()
            .insert(TargetHttpVersion(Version::HTTP_2));

        let result = modifier.serve(req).await;
        assert_err!(result);
    }
}
