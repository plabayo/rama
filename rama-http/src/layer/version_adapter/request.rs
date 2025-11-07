use rama_core::Layer;
use rama_core::Service;
use rama_core::extensions::ChainableExtensions;
use rama_core::telemetry::tracing;
use rama_error::BoxError;
use rama_error::OpaqueError;
use rama_http_headers::HeaderMapExt;
use rama_http_headers::Upgrade;
use rama_http_types::Method;
use rama_http_types::Request;
use rama_http_types::Version;
use rama_http_types::conn::TargetHttpVersion;
use rama_net::client::{ConnectorService, EstablishedClientConnection};
use rama_utils::macros::generate_set_and_with;

#[derive(Clone, Debug)]
/// [`ConnectorService`] which will adapt the request version if needed.
///
/// It will adapt the request version to [`TargetHttpVersion`], or the configured
/// default version
pub struct RequestVersionAdapter<S> {
    inner: S,
    default_http_version: Option<Version>,
}

impl<S> RequestVersionAdapter<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            default_http_version: None,
        }
    }

    generate_set_and_with! {
        /// Set default request [`Version`] which will be used if [`TargetHttpVersion`] is
        /// is not present in extensions
        pub fn default_version(mut self, version: Option<Version>) -> Self {
            self.default_http_version = version;
            self
        }
    }
}

impl<S, Body> Service<Request<Body>> for RequestVersionAdapter<S>
where
    S: ConnectorService<Request<Body>, Error: Into<BoxError>>,
    Body: Send + 'static,
{
    type Response = EstablishedClientConnection<S::Connection, Request<Body>>;
    type Error = BoxError;

    async fn serve(&self, req: Request<Body>) -> Result<Self::Response, Self::Error> {
        let EstablishedClientConnection { conn, mut req } =
            self.inner.connect(req).await.map_err(Into::into)?;

        let ext_chain = (&conn, &req);
        let version = ext_chain
            .get::<TargetHttpVersion>()
            .map(|version| version.0);

        match (version, self.default_http_version) {
            (Some(version), _) => {
                tracing::trace!(
                    "setting request version to {:?} based on configured TargetHttpVersion (was: {:?})",
                    version,
                    req.version(),
                );
                adapt_request_version(&mut req, version)?;
            }
            (_, Some(version)) => {
                tracing::trace!(
                    "setting request version to {:?} based on configured default http version (was: {:?})",
                    version,
                    req.version(),
                );
                adapt_request_version(&mut req, version)?;
            }
            (None, None) => {
                tracing::trace!(
                    "no TargetHttpVersion or default http version configured, leaving request version {:?}",
                    req.version(),
                );
            }
        }

        Ok(EstablishedClientConnection { req, conn })
    }
}

#[derive(Clone, Debug, Default)]
/// [`ConnectorService`] layer which will adapt the request version if needed.
///
/// It will adapt the request version to [`TargetHttpVersion`], or the configured
/// default version
pub struct RequestVersionAdapterLayer {
    default_http_version: Option<Version>,
}

impl RequestVersionAdapterLayer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_http_version: None,
        }
    }

    generate_set_and_with! {
        /// Set default request [`Version`] which will be used if [`TargetHttpVersion`] is
        /// is not present in extensions
        pub fn default_version(mut self, version: Option<Version>) -> Self {
            self.default_http_version = version;
            self
        }
    }
}

impl<S> Layer<S> for RequestVersionAdapterLayer {
    type Service = RequestVersionAdapter<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequestVersionAdapter {
            inner,
            default_http_version: self.default_http_version,
        }
    }
}

/// Adapt request to match the provided [`Version`]
pub fn adapt_request_version<Body>(
    request: &mut Request<Body>,
    target_version: Version,
) -> Result<(), OpaqueError> {
    let request_version = request.version();
    if request_version == target_version {
        tracing::trace!(
            "request version is already {target_version:?}, no version switching needed",
        );
        return Ok(());
    }

    tracing::trace!(
        "changing request version from {:?} to {:?}",
        request_version,
        target_version,
    );

    // TODO full implementation: https://github.com/plabayo/rama/issues/624

    if (request_version == Version::HTTP_10 || request_version == Version::HTTP_11)
        && target_version == Version::HTTP_2
        && request.headers().typed_get::<Upgrade>().is_some()
    {
        *request.method_mut() = Method::CONNECT;
    }

    *request.version_mut() = target_version;
    Ok(())
}
