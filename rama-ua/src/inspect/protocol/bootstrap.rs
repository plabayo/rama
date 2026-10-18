//! Freeze only a reference to the first capture-safe request joint.

use super::H3ProfileRequest;
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        http3::bootstrap::H3BootstrapLimits,
        joint::{CaptureLevel, JointCapture, JointCaptureLimits},
    },
    format::canonical::{ProfileDataError, ValueId},
};
use rama_core::extensions::Extension;
use rama_http::{Method, Version, proto::h3::observation::H3RequestObservation, request::Parts};

#[derive(Debug, Extension)]
pub(super) struct H3ProfileBootstrap(pub Result<InitialRequest, ProfileDataError>);

#[derive(Debug)]
pub(super) struct InitialRequest {
    pub request: ValueId,
    pub method: Method,
    pub fields: usize,
    pub stream_id: u64,
}

pub(super) fn capture(
    parts: &Parts,
    request: &H3ProfileRequest,
) -> Result<InitialRequest, ProfileDataError> {
    if parts.version != Version::HTTP_3 {
        return Err(ProfileDataError::Invalid("H3 bootstrap protocol"));
    }
    let observed = parts
        .extensions
        .get_ref::<H3RequestObservation>()
        .ok_or(ProfileDataError::Incomplete("H3 bootstrap request"))?;
    let bindings = observed
        .connection
        .encoder_bindings
        .as_ref()
        .ok_or(ProfileDataError::Incomplete("H3 bootstrap associations"))?;
    if bindings.stream_id != observed.stream_id {
        return Err(ProfileDataError::Invalid("H3 bootstrap request identity"));
    }
    let limits = H3BootstrapLimits::default();
    if !observed.fields_complete || !bindings.complete {
        return Err(ProfileDataError::Incomplete("H3 bootstrap fields"));
    }
    if observed.fields.len() > limits.fields || bindings.insertions.len() > limits.instructions {
        return Err(ProfileDataError::LimitExceeded("H3 bootstrap fields"));
    }
    // Reuse the same privacy policy and canonical request joint as export. The
    // bounded temporary slots are discarded; the connection retains only its ID.
    let joint = JointCapture {
        completeness: ProfileCaptureCompleteness::Complete,
        level: CaptureLevel::Request,
        slots: request.0.as_ref().map_err(Clone::clone)?.clone(),
    }
    .canonical(JointCaptureLimits::default())?;
    Ok(InitialRequest {
        request: joint.id,
        method: parts.method.clone(),
        fields: observed.fields.len(),
        stream_id: observed.stream_id,
    })
}
