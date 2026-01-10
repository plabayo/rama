use super::super::std_messages::{
    BadRequest, DebugInfo, ErrorInfo, Help, LocalizedMessage, PreconditionFailure, QuotaFailure,
    RequestInfo, ResourceInfo, RetryInfo,
};

/// Wraps the structs corresponding to the standard error messages, allowing
/// the implementation and handling of vectors containing any of them.
#[non_exhaustive]
#[derive(Clone, Debug)]
pub enum ErrorDetail {
    /// Wraps the [`RetryInfo`] struct.
    RetryInfo(RetryInfo),

    /// Wraps the [`DebugInfo`] struct.
    DebugInfo(DebugInfo),

    /// Wraps the [`QuotaFailure`] struct.
    QuotaFailure(QuotaFailure),

    /// Wraps the [`ErrorInfo`] struct.
    ErrorInfo(ErrorInfo),

    /// Wraps the [`PreconditionFailure`] struct.
    PreconditionFailure(PreconditionFailure),

    /// Wraps the [`BadRequest`] struct.
    BadRequest(BadRequest),

    /// Wraps the [`RequestInfo`] struct.
    RequestInfo(RequestInfo),

    /// Wraps the [`ResourceInfo`] struct.
    ResourceInfo(ResourceInfo),

    /// Wraps the [`Help`] struct.
    Help(Help),

    /// Wraps the [`LocalizedMessage`] struct.
    LocalizedMessage(LocalizedMessage),
}

impl From<RetryInfo> for ErrorDetail {
    fn from(err_detail: RetryInfo) -> Self {
        Self::RetryInfo(err_detail)
    }
}

impl From<DebugInfo> for ErrorDetail {
    fn from(err_detail: DebugInfo) -> Self {
        Self::DebugInfo(err_detail)
    }
}

impl From<QuotaFailure> for ErrorDetail {
    fn from(err_detail: QuotaFailure) -> Self {
        Self::QuotaFailure(err_detail)
    }
}

impl From<ErrorInfo> for ErrorDetail {
    fn from(err_detail: ErrorInfo) -> Self {
        Self::ErrorInfo(err_detail)
    }
}

impl From<PreconditionFailure> for ErrorDetail {
    fn from(err_detail: PreconditionFailure) -> Self {
        Self::PreconditionFailure(err_detail)
    }
}

impl From<BadRequest> for ErrorDetail {
    fn from(err_detail: BadRequest) -> Self {
        Self::BadRequest(err_detail)
    }
}

impl From<RequestInfo> for ErrorDetail {
    fn from(err_detail: RequestInfo) -> Self {
        Self::RequestInfo(err_detail)
    }
}

impl From<ResourceInfo> for ErrorDetail {
    fn from(err_detail: ResourceInfo) -> Self {
        Self::ResourceInfo(err_detail)
    }
}

impl From<Help> for ErrorDetail {
    fn from(err_detail: Help) -> Self {
        Self::Help(err_detail)
    }
}

impl From<LocalizedMessage> for ErrorDetail {
    fn from(err_detail: LocalizedMessage) -> Self {
        Self::LocalizedMessage(err_detail)
    }
}
