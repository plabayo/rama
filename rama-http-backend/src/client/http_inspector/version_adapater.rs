use rama_core::telemetry::tracing::trace;
use rama_core::{Context, Service, error::BoxError};
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
pub struct HttpVersionAdapater {
    default_version: Option<Version>,
}

impl HttpVersionAdapater {
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

impl<State, ReqBody> Service<State, Request<ReqBody>> for HttpVersionAdapater
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
        match (ctx.get::<TargetHttpVersion>(), self.default_version) {
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

        Ok((ctx, req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rama_http::{Body, dep::http::Request};

    #[tokio::test]
    async fn test_should_change_if_needed() {
        let adapter = HttpVersionAdapater::new();
        let req = Request::new(Body::empty());
        let mut ctx = Context::default();

        assert_eq!(req.version(), Version::HTTP_11);

        ctx.insert(TargetHttpVersion(Version::HTTP_2));
        let (mut ctx, req) = adapter.serve(ctx, req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_2);

        ctx.insert(TargetHttpVersion(Version::HTTP_11));
        let (mut ctx, req) = adapter.serve(ctx, req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_11);

        ctx.insert(TargetHttpVersion(Version::HTTP_3));
        let (_ctx, req) = adapter.serve(ctx, req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_3);
    }

    #[tokio::test]
    async fn test_default_fallback() {
        let adapter = HttpVersionAdapater::new().with_default_version(Version::HTTP_11);
        let mut req = Request::new(Body::empty());
        *req.version_mut() = Version::HTTP_2;

        assert_eq!(req.version(), Version::HTTP_2);
        let (_ctx, req) = adapter.serve(Context::default(), req).await.unwrap();
        assert_eq!(req.version(), Version::HTTP_11);
    }
}
