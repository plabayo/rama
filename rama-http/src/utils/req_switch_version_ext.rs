use rama_core::{
    extensions::{ChainableExtensions, ExtensionsMut, ExtensionsRef},
    telemetry::tracing::trace,
};
use rama_error::OpaqueError;
use rama_http_headers::{HeaderMapExt, Upgrade};
use rama_http_types::{
    Method, Request, Version,
    conn::{DefaultTargetHttpVersion, OriginalRequestVersion, TargetHttpVersion},
};

pub trait RequestSwitchVersionExt {
    fn switch_version(&mut self, target_version: Version) -> Result<(), OpaqueError>;
}

impl<Body> RequestSwitchVersionExt for Request<Body> {
    fn switch_version(&mut self, target_version: Version) -> Result<(), OpaqueError> {
        let request_version = self.version();
        if request_version == target_version {
            trace!("request version is already {target_version:?}, no version switching needed",);
            return Ok(());
        }

        trace!(
            "changing request version from {:?} to {:?}",
            request_version, target_version,
        );

        if !self.extensions().contains::<OriginalRequestVersion>() {
            self.extensions_mut()
                .insert(OriginalRequestVersion(request_version));
        }

        // TODO full implementation: https://github.com/plabayo/rama/issues/624

        if (request_version == Version::HTTP_10 || request_version == Version::HTTP_11)
            && target_version == Version::HTTP_2
            && self.headers().typed_get::<Upgrade>().is_some()
        {
            *self.method_mut() = Method::CONNECT;
        }

        *self.version_mut() = target_version;
        Ok(())
    }
}

pub trait RequestApplyTargetVersionExt {
    fn apply_target_version(&mut self) -> Result<(), OpaqueError>;

    fn apply_connection_target_version(
        &mut self,
        connection: &impl ExtensionsRef,
    ) -> Result<(), OpaqueError>;
}

impl<Body> RequestApplyTargetVersionExt for Request<Body> {
    fn apply_target_version(&mut self) -> Result<(), OpaqueError> {
        let version = self
            .extensions()
            .get::<TargetHttpVersion>()
            .map(|version| {
                trace!("found TargetHttpVersion {:?}", version);
                version.0
            })
            .or_else(|| {
                self.extensions()
                    .get::<DefaultTargetHttpVersion>()
                    .map(|version| {
                        trace!("not TargetHttpVersion found using default: {:?}", version);
                        version.0
                    })
            });

        if let Some(version) = version {
            self.switch_version(version)?;
        } else {
            trace!(
                "no TargetHttpVersion or DefaultTargetHttpVersion configured, leaving request as is"
            );
        }
        Ok(())
    }

    fn apply_connection_target_version(
        &mut self,
        connection: &impl ExtensionsRef,
    ) -> Result<(), OpaqueError> {
        let ext_chain = (connection, &self);
        let version = ext_chain
            .get::<TargetHttpVersion>()
            .map(|version| {
                trace!("found TargetHttpVersion {:?}", version);
                version.0
            })
            .or_else(|| {
                ext_chain.get::<DefaultTargetHttpVersion>().map(|version| {
                    trace!("not TargetHttpVersion found using default: {:?}", version);
                    version.0
                })
            });

        if let Some(version) = version {
            self.switch_version(version)?;
        } else {
            trace!(
                "no TargetHttpVersion or DefaultTargetHttpVersion configured, leaving request as is"
            );
        }
        Ok(())
    }
}
