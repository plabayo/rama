//! Freeze only a reference to the first capture-safe request joint.

use super::H3ProfileRequest;
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        http3::bootstrap::{H3BootstrapLimits, request::H3BootstrapRequest},
        joint::{CaptureLevel, JointCapture},
    },
    format::canonical::ProfileDataError,
};
use rama_core::extensions::Extension;
use rama_http::{Version, proto::h3::observation::H3RequestObservation, request::Parts};

#[derive(Debug, Extension)]
pub(super) struct H3ProfileBootstrap(pub Result<H3BootstrapRequest, ProfileDataError>);

pub(super) fn capture(
    parts: &Parts,
    request: &H3ProfileRequest,
) -> Result<H3BootstrapRequest, ProfileDataError> {
    if parts.version != Version::HTTP_3 {
        return Err(ProfileDataError::Invalid("H3 bootstrap protocol"));
    }
    let observed = parts
        .extensions
        .get_ref::<H3RequestObservation>()
        .ok_or(ProfileDataError::Incomplete("H3 bootstrap request"))?;
    let joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: request.0.as_ref().map_err(Clone::clone)?.clone(),
    };
    H3BootstrapRequest::capture(
        &joint,
        &parts.method,
        observed,
        H3BootstrapLimits::default(),
    )
}
