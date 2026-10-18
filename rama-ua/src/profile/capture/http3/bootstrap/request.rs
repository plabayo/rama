//! Capture a bounded reference before request headers are rewritten or dropped.

use rama_http::{
    Method,
    proto::h3::observation::{H3RequestObservation, ObservedEncoderBindings},
};

use super::{H3BootstrapCapture, H3BootstrapLimits, H3ClientSequenceCapture};
use crate::profile::{
    capture::{
        completeness::ProfileCaptureCompleteness,
        joint::{CaptureLevel, JointCapture, JointCaptureLimits},
    },
    format::canonical::{ProfileDataError, ValueId},
};

/// The first request's safe joint identity and native field coordinates.
/// No header values or URI are retained here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct H3BootstrapRequest {
    request: ValueId,
    method: Method,
    fields: usize,
    stream_id: u64,
}

impl H3BootstrapRequest {
    /// Identity of the existing safe request joint that must also be retained.
    #[must_use]
    pub const fn request_id(&self) -> ValueId {
        self.request
    }

    pub fn capture(
        request: &JointCapture,
        method: &Method,
        observed: &H3RequestObservation,
        limits: H3BootstrapLimits,
    ) -> Result<Self, ProfileDataError> {
        let bindings = observed
            .connection
            .encoder_bindings
            .as_ref()
            .ok_or(ProfileDataError::Incomplete("H3 bootstrap associations"))?;
        if bindings.stream_id != observed.stream_id {
            return Err(ProfileDataError::Invalid("H3 bootstrap request identity"));
        }
        if !observed.fields_complete || !bindings.complete {
            return Err(ProfileDataError::Incomplete("H3 bootstrap fields"));
        }
        if observed.fields.is_empty()
            || observed.fields.len() > limits.fields
            || bindings.insertions.len() > limits.instructions
        {
            return Err(ProfileDataError::LimitExceeded("H3 bootstrap fields"));
        }
        if request.level != CaptureLevel::Request
            || request.completeness != ProfileCaptureCompleteness::Complete
        {
            return Err(ProfileDataError::Invalid("H3 bootstrap request joint"));
        }
        let value = request.canonical(JointCaptureLimits {
            value_bytes: limits.bytes,
            ..JointCaptureLimits::default()
        })?;
        Ok(Self {
            request: value.id,
            method: method.clone(),
            fields: observed.fields.len(),
            stream_id: observed.stream_id,
        })
    }

    /// Join the original request identity with its frozen connection prefix.
    pub fn bind(
        &self,
        bindings: &ObservedEncoderBindings,
        sequence: &H3ClientSequenceCapture,
    ) -> Result<H3BootstrapCapture, ProfileDataError> {
        if bindings.stream_id != self.stream_id {
            return Err(ProfileDataError::Invalid("H3 bootstrap request identity"));
        }
        if !bindings.complete {
            return Err(ProfileDataError::Incomplete("H3 bootstrap associations"));
        }
        let capture = H3BootstrapCapture {
            request: self.request,
            method: self.method.clone(),
            fields: self.fields,
            bindings: bindings.clone(),
        };
        capture.validate_sequence(sequence)?;
        Ok(capture)
    }
}
