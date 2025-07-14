use rama_core::telemetry::tracing::trace;
use rama_error::OpaqueError;
use rama_http_headers::{HeaderMapExt, Upgrade};
use rama_http_types::{Method, Version, dep::http};

pub trait RequestSwitchVersionExt {
    fn switch_version(&mut self, target_version: Version) -> Result<(), OpaqueError>;
}

impl<Body> RequestSwitchVersionExt for http::Request<Body> {
    fn switch_version(&mut self, target_version: Version) -> Result<(), OpaqueError> {
        if self.version() == target_version {
            trace!("request version is already {target_version:?}, no version switching needed",);
            return Ok(());
        }

        trace!(
            "changing request version from {:?} to {:?}",
            self.version(),
            target_version,
        );

        // TODO full implementation: https://github.com/plabayo/rama/issues/624

        if (self.version() == Version::HTTP_10 || self.version() == Version::HTTP_11)
            && target_version == Version::HTTP_2
            && self.headers().typed_get::<Upgrade>().is_some()
        {
            *self.method_mut() = Method::CONNECT;
        }

        *self.version_mut() = target_version;
        Ok(())
    }
}
