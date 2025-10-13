use rama_core::extensions::ExtensionsRef;
use rama_core::telemetry::tracing::trace;
use rama_core::{Service, error::BoxError};
use rama_http::utils::RequestSwitchVersionExt;
use rama_http::{Request, Version, conn::TargetHttpVersion};
use rama_utils::macros::generate_set_and_with;

#[derive(Debug, Clone, Default)]
/// Modifier that is used to adapt the http [`Request`]
/// version to the configured [`TargetHttpVersion`] if one
/// is set
///
/// [`TargetHttpVersion`] can be set manually on the context
/// or by layers such as tls alpn
pub struct HttpVersionAdapter {
    default_version: Option<Version>,
}

impl HttpVersionAdapter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_version: None,
        }
    }

    generate_set_and_with! {
        pub fn default_version(mut self, version: Option<Version>) -> Self {
            self.default_version = version;
            self
        }
    }
}

impl<ReqBody> Service<Request<ReqBody>> for HttpVersionAdapter
where
    ReqBody: Send + 'static,
{
    type Error = BoxError;
    type Response = Request<ReqBody>;

    async fn serve(&self, mut req: Request<ReqBody>) -> Result<Self::Response, Self::Error> {
        match (
            req.extensions().get::<TargetHttpVersion>(),
            self.default_version,
        ) {
            (Some(version), _) => {
                trace!(
                    "setting request version to {:?} based on configured TargetHttpVersion (was: {:?})",
                    version,
                    req.version(),
                );
                req.switch_version(version.0)?;
            }
            (_, Some(version)) => {
                trace!(
                    "setting request version to {:?} based on configured default http version (was: {:?})",
                    version,
                    req.version(),
                );
                req.switch_version(version)?;
            }
            (None, None) => {
                trace!(
                    "no TargetHttpVersion or default http version configured, leaving request version {:?}",
                    req.version(),
                );
            }
        }

        Ok(req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_core::extensions::ExtensionsMut;
    use rama_http::{Body, Request};

    #[tokio::test]
    async fn test_should_change_if_needed() {
        let adapter = HttpVersionAdapter::new();
        let mut req = Request::new(Body::empty());

        assert_eq!(req.version(), Version::HTTP_11);

        req.extensions_mut()
            .insert(TargetHttpVersion(Version::HTTP_2));
        let mut req = adapter.serve(req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_2);

        req.extensions_mut()
            .insert(TargetHttpVersion(Version::HTTP_11));
        let mut req = adapter.serve(req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_11);

        req.extensions_mut()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let req = adapter.serve(req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_3);
    }

    #[tokio::test]
    async fn test_default_fallback() {
        let adapter = HttpVersionAdapter::new().with_default_version(Version::HTTP_11);
        let mut req = Request::new(Body::empty());
        *req.version_mut() = Version::HTTP_2;

        assert_eq!(req.version(), Version::HTTP_2);
        let req = adapter.serve(req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_11);
    }
}
