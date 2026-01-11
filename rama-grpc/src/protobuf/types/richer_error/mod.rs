use rama_core::bytes::{Bytes, BytesMut};
use rama_utils::str::arcstr::ArcStr;

use crate::{
    Code, Status,
    metadata::MetadataMap,
    protobuf::{
        prost::{DecodeError, EncodeError, Message, types::Any},
        types::sealed,
    },
};

mod error_details;
mod std_messages;

use super::pb;

pub use error_details::{ErrorDetails, vec::ErrorDetail};
pub use std_messages::{
    BadRequest, DebugInfo, ErrorInfo, FieldViolation, Help, HelpLink, LocalizedMessage,
    PreconditionFailure, PreconditionViolation, QuotaFailure, QuotaViolation, RequestInfo,
    ResourceInfo, RetryInfo,
};

trait IntoAny {
    fn into_any(self) -> Any;
}

#[allow(dead_code)]
trait FromAny {
    fn from_any(any: Any) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

trait FromAnyRef {
    fn from_any_ref(any: &Any) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

fn gen_details_bytes(code: Code, message: &str, details: Vec<Any>) -> Result<Bytes, EncodeError> {
    let status = pb::Status {
        code: code as i32,
        message: message.to_owned(),
        details,
    };

    let mut buf = BytesMut::with_capacity(status.encoded_len());

    status.encode(&mut buf)?;

    Ok(buf.freeze())
}

/// Used to implement associated functions and methods on `Status`, that
/// allow the addition and extraction of standard error details. This trait is
/// sealed and not meant to be implemented outside of `rama::grpc::protobuf::types`.
pub trait StatusExt: sealed::Sealed {
    /// Generates a `Status` with error details obtained from an
    /// [`ErrorDetails`] struct, and custom metadata.
    fn try_with_error_details_and_metadata(
        code: Code,
        message: impl Into<ArcStr>,
        details: ErrorDetails,
        metadata: MetadataMap,
    ) -> Result<Status, EncodeError>;

    /// Generates a `Status` with error details obtained from an
    /// [`ErrorDetails`] struct.
    fn try_with_error_details(
        code: Code,
        message: impl Into<ArcStr>,
        details: ErrorDetails,
    ) -> Result<Status, EncodeError>;

    /// Generates a `Status` with error details provided in a vector of
    /// [`ErrorDetail`] enums, and custom metadata.
    fn try_with_error_details_vec_and_metadata(
        code: Code,
        message: impl Into<ArcStr>,
        details: impl IntoIterator<Item = ErrorDetail>,
        metadata: MetadataMap,
    ) -> Result<Status, EncodeError>;

    /// Generates a `Status` with error details provided in a vector of
    /// [`ErrorDetail`] enums.
    fn try_with_error_details_vec(
        code: Code,
        message: impl Into<ArcStr>,
        details: impl IntoIterator<Item = ErrorDetail>,
    ) -> Result<Status, EncodeError>;

    /// Can be used to check if the error details contained in `Status`
    /// are malformed or not. Tries to get an [`ErrorDetails`] struct from a
    /// `Status`. If some `prost::DecodeError` occurs, it will be
    /// returned. If not debugging, consider using
    /// [`StatusExt::get_error_details`] or
    /// [`StatusExt::get_error_details_vec`].
    fn check_error_details(&self) -> Result<ErrorDetails, DecodeError>;

    /// Get an [`ErrorDetails`] struct from `Status`. If some
    /// `prost::DecodeError` occurs, an empty [`ErrorDetails`] struct will be
    /// returned.
    fn get_error_details(&self) -> ErrorDetails;

    /// Can be used to check if the error details contained in `Status`
    /// are malformed or not. Tries to get a vector of [`ErrorDetail`] enums
    /// from a `Status`. If some `prost::DecodeError` occurs, it will be
    /// returned. If not debugging, consider using
    /// [`StatusExt::get_error_details_vec`] or
    /// [`StatusExt::get_error_details`].
    fn check_error_details_vec(&self) -> Result<Vec<ErrorDetail>, DecodeError>;

    /// Get a vector of [`ErrorDetail`] enums from `Status`. If some
    /// `prost::DecodeError` occurs, an empty vector will be returned.
    fn get_error_details_vec(&self) -> Vec<ErrorDetail>;

    /// Get first [`RetryInfo`] details found on `Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_retry_info(&self) -> Option<RetryInfo>;

    /// Get first [`DebugInfo`] details found on `Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_debug_info(&self) -> Option<DebugInfo>;

    /// Get first [`QuotaFailure`] details found on `Status`, if any.
    /// If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_quota_failure(&self) -> Option<QuotaFailure>;

    /// Get first [`ErrorInfo`] details found on `Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_error_info(&self) -> Option<ErrorInfo>;

    /// Get first [`PreconditionFailure`] details found on `Status`,
    /// if any. If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_precondition_failure(&self) -> Option<PreconditionFailure>;

    /// Get first [`BadRequest`] details found on `Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_bad_request(&self) -> Option<BadRequest>;

    /// Get first [`RequestInfo`] details found on `Status`, if any.
    /// If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_request_info(&self) -> Option<RequestInfo>;

    /// Get first [`ResourceInfo`] details found on `Status`, if any.
    /// If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_resource_info(&self) -> Option<ResourceInfo>;

    /// Get first [`Help`] details found on `Status`, if any. If some
    /// `prost::DecodeError` occurs, returns `None`.
    fn get_details_help(&self) -> Option<Help>;

    /// Get first [`LocalizedMessage`] details found on `Status`, if
    /// any. If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_localized_message(&self) -> Option<LocalizedMessage>;
}

impl sealed::Sealed for Status {}

impl StatusExt for Status {
    fn try_with_error_details_and_metadata(
        code: Code,
        message: impl Into<ArcStr>,
        details: ErrorDetails,
        metadata: MetadataMap,
    ) -> Result<Self, EncodeError> {
        let message = message.into();

        let mut conv_details: Vec<Any> = Vec::with_capacity(10);

        if let Some(retry_info) = details.retry_info {
            conv_details.push(retry_info.into_any());
        }

        if let Some(debug_info) = details.debug_info {
            conv_details.push(debug_info.into_any());
        }

        if let Some(quota_failure) = details.quota_failure {
            conv_details.push(quota_failure.into_any());
        }

        if let Some(error_info) = details.error_info {
            conv_details.push(error_info.into_any());
        }

        if let Some(precondition_failure) = details.precondition_failure {
            conv_details.push(precondition_failure.into_any());
        }

        if let Some(bad_request) = details.bad_request {
            conv_details.push(bad_request.into_any());
        }

        if let Some(request_info) = details.request_info {
            conv_details.push(request_info.into_any());
        }

        if let Some(resource_info) = details.resource_info {
            conv_details.push(resource_info.into_any());
        }

        if let Some(help) = details.help {
            conv_details.push(help.into_any());
        }

        if let Some(localized_message) = details.localized_message {
            conv_details.push(localized_message.into_any());
        }

        let details = gen_details_bytes(code, &message, conv_details)?;

        Ok(Self::with_details_and_metadata(
            code, message, details, metadata,
        ))
    }

    #[inline(always)]
    fn try_with_error_details(
        code: Code,
        message: impl Into<ArcStr>,
        details: ErrorDetails,
    ) -> Result<Self, EncodeError> {
        Self::try_with_error_details_and_metadata(code, message, details, MetadataMap::new())
    }

    fn try_with_error_details_vec_and_metadata(
        code: Code,
        message: impl Into<ArcStr>,
        details: impl IntoIterator<Item = ErrorDetail>,
        metadata: MetadataMap,
    ) -> Result<Self, EncodeError> {
        let message = message.into();

        let mut conv_details: Vec<Any> = Vec::new();

        for error_detail in details.into_iter() {
            match error_detail {
                ErrorDetail::RetryInfo(retry_info) => {
                    conv_details.push(retry_info.into_any());
                }
                ErrorDetail::DebugInfo(debug_info) => {
                    conv_details.push(debug_info.into_any());
                }
                ErrorDetail::QuotaFailure(quota_failure) => {
                    conv_details.push(quota_failure.into_any());
                }
                ErrorDetail::ErrorInfo(error_info) => {
                    conv_details.push(error_info.into_any());
                }
                ErrorDetail::PreconditionFailure(prec_failure) => {
                    conv_details.push(prec_failure.into_any());
                }
                ErrorDetail::BadRequest(bad_req) => {
                    conv_details.push(bad_req.into_any());
                }
                ErrorDetail::RequestInfo(req_info) => {
                    conv_details.push(req_info.into_any());
                }
                ErrorDetail::ResourceInfo(res_info) => {
                    conv_details.push(res_info.into_any());
                }
                ErrorDetail::Help(help) => {
                    conv_details.push(help.into_any());
                }
                ErrorDetail::LocalizedMessage(loc_message) => {
                    conv_details.push(loc_message.into_any());
                }
            }
        }

        let details = gen_details_bytes(code, &message, conv_details)?;

        Ok(Self::with_details_and_metadata(
            code, message, details, metadata,
        ))
    }

    fn try_with_error_details_vec(
        code: Code,
        message: impl Into<ArcStr>,
        details: impl IntoIterator<Item = ErrorDetail>,
    ) -> Result<Self, EncodeError> {
        Self::try_with_error_details_vec_and_metadata(code, message, details, MetadataMap::new())
    }

    fn check_error_details(&self) -> Result<ErrorDetails, DecodeError> {
        let status = pb::Status::decode(self.details())?;

        status.check_error_details()
    }

    fn get_error_details(&self) -> ErrorDetails {
        self.check_error_details().unwrap_or_default()
    }

    fn check_error_details_vec(&self) -> Result<Vec<ErrorDetail>, DecodeError> {
        let status = pb::Status::decode(self.details())?;

        status.check_error_details_vec()
    }

    fn get_error_details_vec(&self) -> Vec<ErrorDetail> {
        self.check_error_details_vec().unwrap_or_default()
    }

    fn get_details_retry_info(&self) -> Option<RetryInfo> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_retry_info()
    }

    fn get_details_debug_info(&self) -> Option<DebugInfo> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_debug_info()
    }

    fn get_details_quota_failure(&self) -> Option<QuotaFailure> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_quota_failure()
    }

    fn get_details_error_info(&self) -> Option<ErrorInfo> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_error_info()
    }

    fn get_details_precondition_failure(&self) -> Option<PreconditionFailure> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_precondition_failure()
    }

    fn get_details_bad_request(&self) -> Option<BadRequest> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_bad_request()
    }

    fn get_details_request_info(&self) -> Option<RequestInfo> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_request_info()
    }

    fn get_details_resource_info(&self) -> Option<ResourceInfo> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_resource_info()
    }

    fn get_details_help(&self) -> Option<Help> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_help()
    }

    fn get_details_localized_message(&self) -> Option<LocalizedMessage> {
        let status = pb::Status::decode(self.details()).ok()?;

        status.get_details_localized_message()
    }
}

impl sealed::Sealed for pb::Status {}

/// Used to implement associated functions and methods on `pb::Status`, that
/// allow the extraction of standard error details. This trait is
/// sealed and not meant to be implemented outside of `rama::grpc::protobuf::types`.
pub trait RpcStatusExt: sealed::Sealed {
    /// Can be used to check if the error details contained in `pb::Status`
    /// are malformed or not. Tries to get an [`ErrorDetails`] struct from a
    /// `pb::Status`. If some `prost::DecodeError` occurs, it will be
    /// returned. If not debugging, consider using
    /// [`RpcStatusExt::get_error_details`] or
    /// [`RpcStatusExt::get_error_details_vec`].
    fn check_error_details(&self) -> Result<ErrorDetails, DecodeError>;

    /// Get an [`ErrorDetails`] struct from `pb::Status`. If some
    /// `prost::DecodeError` occurs, an empty [`ErrorDetails`] struct will be
    /// returned.
    fn get_error_details(&self) -> ErrorDetails;

    /// Can be used to check if the error details contained in `pb::Status`
    /// are malformed or not. Tries to get a vector of [`ErrorDetail`] enums
    /// from a `pb::Status`. If some `prost::DecodeError` occurs, it will be
    /// returned. If not debugging, consider using
    /// [`StatusExt::get_error_details_vec`] or
    /// [`StatusExt::get_error_details`].
    fn check_error_details_vec(&self) -> Result<Vec<ErrorDetail>, DecodeError>;

    /// Get a vector of [`ErrorDetail`] enums from `pb::Status`. If some
    /// `prost::DecodeError` occurs, an empty vector will be returned.
    fn get_error_details_vec(&self) -> Vec<ErrorDetail>;

    /// Get first [`RetryInfo`] details found on `pb::Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_retry_info(&self) -> Option<RetryInfo>;

    /// Get first [`DebugInfo`] details found on `pb::Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_debug_info(&self) -> Option<DebugInfo>;

    /// Get first [`QuotaFailure`] details found on `pb::Status`, if any.
    /// If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_quota_failure(&self) -> Option<QuotaFailure>;

    /// Get first [`ErrorInfo`] details found on `pb::Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_error_info(&self) -> Option<ErrorInfo>;

    /// Get first [`PreconditionFailure`] details found on `pb::Status`,
    /// if any. If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_precondition_failure(&self) -> Option<PreconditionFailure>;

    /// Get first [`BadRequest`] details found on `pb::Status`, if any. If
    /// some `prost::DecodeError` occurs, returns `None`.
    fn get_details_bad_request(&self) -> Option<BadRequest>;

    /// Get first [`RequestInfo`] details found on `pb::Status`, if any.
    /// If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_request_info(&self) -> Option<RequestInfo>;

    /// Get first [`ResourceInfo`] details found on `pb::Status`, if any.
    /// If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_resource_info(&self) -> Option<ResourceInfo>;

    /// Get first [`Help`] details found on `pb::Status`, if any. If some
    /// `prost::DecodeError` occurs, returns `None`.
    fn get_details_help(&self) -> Option<Help>;

    /// Get first [`LocalizedMessage`] details found on `pb::Status`, if
    /// any. If some `prost::DecodeError` occurs, returns `None`.
    fn get_details_localized_message(&self) -> Option<LocalizedMessage>;
}

impl RpcStatusExt for pb::Status {
    fn check_error_details(&self) -> Result<ErrorDetails, DecodeError> {
        let mut details = ErrorDetails::new();

        for any in self.details.iter() {
            match any.type_url.as_str() {
                RetryInfo::TYPE_URL => {
                    details.retry_info = Some(RetryInfo::from_any_ref(any)?);
                }
                DebugInfo::TYPE_URL => {
                    details.debug_info = Some(DebugInfo::from_any_ref(any)?);
                }
                QuotaFailure::TYPE_URL => {
                    details.quota_failure = Some(QuotaFailure::from_any_ref(any)?);
                }
                ErrorInfo::TYPE_URL => {
                    details.error_info = Some(ErrorInfo::from_any_ref(any)?);
                }
                PreconditionFailure::TYPE_URL => {
                    details.precondition_failure = Some(PreconditionFailure::from_any_ref(any)?);
                }
                BadRequest::TYPE_URL => {
                    details.bad_request = Some(BadRequest::from_any_ref(any)?);
                }
                RequestInfo::TYPE_URL => {
                    details.request_info = Some(RequestInfo::from_any_ref(any)?);
                }
                ResourceInfo::TYPE_URL => {
                    details.resource_info = Some(ResourceInfo::from_any_ref(any)?);
                }
                Help::TYPE_URL => {
                    details.help = Some(Help::from_any_ref(any)?);
                }
                LocalizedMessage::TYPE_URL => {
                    details.localized_message = Some(LocalizedMessage::from_any_ref(any)?);
                }
                _ => {}
            }
        }

        Ok(details)
    }

    fn get_error_details(&self) -> ErrorDetails {
        self.check_error_details().unwrap_or_default()
    }

    fn check_error_details_vec(&self) -> Result<Vec<ErrorDetail>, DecodeError> {
        let mut details: Vec<ErrorDetail> = Vec::with_capacity(self.details.len());

        for any in self.details.iter() {
            match any.type_url.as_str() {
                RetryInfo::TYPE_URL => {
                    details.push(RetryInfo::from_any_ref(any)?.into());
                }
                DebugInfo::TYPE_URL => {
                    details.push(DebugInfo::from_any_ref(any)?.into());
                }
                QuotaFailure::TYPE_URL => {
                    details.push(QuotaFailure::from_any_ref(any)?.into());
                }
                ErrorInfo::TYPE_URL => {
                    details.push(ErrorInfo::from_any_ref(any)?.into());
                }
                PreconditionFailure::TYPE_URL => {
                    details.push(PreconditionFailure::from_any_ref(any)?.into());
                }
                BadRequest::TYPE_URL => {
                    details.push(BadRequest::from_any_ref(any)?.into());
                }
                RequestInfo::TYPE_URL => {
                    details.push(RequestInfo::from_any_ref(any)?.into());
                }
                ResourceInfo::TYPE_URL => {
                    details.push(ResourceInfo::from_any_ref(any)?.into());
                }
                Help::TYPE_URL => {
                    details.push(Help::from_any_ref(any)?.into());
                }
                LocalizedMessage::TYPE_URL => {
                    details.push(LocalizedMessage::from_any_ref(any)?.into());
                }
                _ => {}
            }
        }

        Ok(details)
    }

    fn get_error_details_vec(&self) -> Vec<ErrorDetail> {
        self.check_error_details_vec().unwrap_or_default()
    }

    fn get_details_retry_info(&self) -> Option<RetryInfo> {
        for any in self.details.iter() {
            if any.type_url.as_str() == RetryInfo::TYPE_URL
                && let Ok(detail) = RetryInfo::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_debug_info(&self) -> Option<DebugInfo> {
        for any in self.details.iter() {
            if any.type_url.as_str() == DebugInfo::TYPE_URL
                && let Ok(detail) = DebugInfo::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_quota_failure(&self) -> Option<QuotaFailure> {
        for any in self.details.iter() {
            if any.type_url.as_str() == QuotaFailure::TYPE_URL
                && let Ok(detail) = QuotaFailure::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_error_info(&self) -> Option<ErrorInfo> {
        for any in self.details.iter() {
            if any.type_url.as_str() == ErrorInfo::TYPE_URL
                && let Ok(detail) = ErrorInfo::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_precondition_failure(&self) -> Option<PreconditionFailure> {
        for any in self.details.iter() {
            if any.type_url.as_str() == PreconditionFailure::TYPE_URL
                && let Ok(detail) = PreconditionFailure::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_bad_request(&self) -> Option<BadRequest> {
        for any in self.details.iter() {
            if any.type_url.as_str() == BadRequest::TYPE_URL
                && let Ok(detail) = BadRequest::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_request_info(&self) -> Option<RequestInfo> {
        for any in self.details.iter() {
            if any.type_url.as_str() == RequestInfo::TYPE_URL
                && let Ok(detail) = RequestInfo::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_resource_info(&self) -> Option<ResourceInfo> {
        for any in self.details.iter() {
            if any.type_url.as_str() == ResourceInfo::TYPE_URL
                && let Ok(detail) = ResourceInfo::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_help(&self) -> Option<Help> {
        for any in self.details.iter() {
            if any.type_url.as_str() == Help::TYPE_URL
                && let Ok(detail) = Help::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }

    fn get_details_localized_message(&self) -> Option<LocalizedMessage> {
        for any in self.details.iter() {
            if any.type_url.as_str() == LocalizedMessage::TYPE_URL
                && let Ok(detail) = LocalizedMessage::from_any_ref(any)
            {
                return Some(detail);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, time::Duration};

    use crate::{Code, Status};

    use super::{
        BadRequest, DebugInfo, ErrorDetails, ErrorInfo, Help, LocalizedMessage,
        PreconditionFailure, QuotaFailure, RequestInfo, ResourceInfo, RetryInfo, StatusExt,
    };

    #[test]
    fn gen_status_with_details() {
        let mut metadata = HashMap::new();
        metadata.insert("limitPerRequest".into(), "100".into());

        let mut err_details = ErrorDetails::new();

        err_details
            .set_retry_info(Some(Duration::from_secs(5)))
            .set_debug_info(
                vec!["trace3".into(), "trace2".into(), "trace1".into()],
                "details",
            )
            .add_quota_failure_violation("clientip:<ip address>", "description")
            .set_error_info("SOME_INFO", "example.local", metadata.clone())
            .add_precondition_failure_violation("TOS", "example.local", "description")
            .add_bad_request_violation("field", "description")
            .set_request_info("request-id", "some-request-data")
            .set_resource_info("resource-type", "resource-name", "owner", "description")
            .add_help_link("link to resource", "resource.example.local")
            .set_localized_message("en-US", "message for the user");

        let fmt_details = format!("{err_details:?}");

        let err_details_vec = vec![
            RetryInfo::new(Some(Duration::from_secs(5))).into(),
            DebugInfo::new(
                vec!["trace3".into(), "trace2".into(), "trace1".into()],
                "details",
            )
            .into(),
            QuotaFailure::with_violation("clientip:<ip address>", "description").into(),
            ErrorInfo::new("SOME_INFO", "example.local", metadata).into(),
            PreconditionFailure::with_violation("TOS", "example.local", "description").into(),
            BadRequest::with_violation("field", "description").into(),
            RequestInfo::new("request-id", "some-request-data").into(),
            ResourceInfo::new("resource-type", "resource-name", "owner", "description").into(),
            Help::with_link("link to resource", "resource.example.local").into(),
            LocalizedMessage::new("en-US", "message for the user").into(),
        ];

        let fmt_details_vec = format!("{err_details_vec:?}");

        let status_from_struct = Status::try_with_error_details(
            Code::InvalidArgument,
            "error with bad request details",
            err_details,
        )
        .unwrap();

        let status_from_vec = Status::try_with_error_details_vec(
            Code::InvalidArgument,
            "error with bad request details",
            err_details_vec,
        )
        .unwrap();

        let ext_details = match status_from_vec.check_error_details() {
            Ok(ext_details) => ext_details,
            Err(err) => panic!("Error extracting details struct from status_from_vec: {err:?}"),
        };

        let fmt_ext_details = format!("{ext_details:?}");

        assert!(
            fmt_ext_details.eq(&fmt_details),
            "Extracted details struct differs from original details struct"
        );

        let ext_details_vec = match status_from_struct.check_error_details_vec() {
            Ok(ext_details) => ext_details,
            Err(err) => panic!("Error extracting details_vec from status_from_struct: {err:?}"),
        };

        let fmt_ext_details_vec = format!("{ext_details_vec:?}");

        assert!(
            fmt_ext_details_vec.eq(&fmt_details_vec),
            "Extracted details vec differs from original details vec"
        );
    }
}
