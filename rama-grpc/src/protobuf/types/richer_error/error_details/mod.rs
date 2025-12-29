use std::{collections::HashMap, time};

use super::std_messages::{
    BadRequest, DebugInfo, ErrorInfo, FieldViolation, Help, HelpLink, LocalizedMessage,
    PreconditionFailure, PreconditionViolation, QuotaFailure, QuotaViolation, RequestInfo,
    ResourceInfo, RetryInfo,
};

pub(crate) mod vec;

/// Groups the standard error messages structs. Provides associated
/// functions and methods to setup and edit each error message independently.
/// Used when extracting error details from [`crate::Status`], and when
/// creating a [`crate::Status`] with error details.
#[non_exhaustive]
#[derive(Clone, Debug, Default)]
pub struct ErrorDetails {
    /// This field stores [`RetryInfo`] data, if any.
    pub(crate) retry_info: Option<RetryInfo>,

    /// This field stores [`DebugInfo`] data, if any.
    pub(crate) debug_info: Option<DebugInfo>,

    /// This field stores [`QuotaFailure`] data, if any.
    pub(crate) quota_failure: Option<QuotaFailure>,

    /// This field stores [`ErrorInfo`] data, if any.
    pub(crate) error_info: Option<ErrorInfo>,

    /// This field stores [`PreconditionFailure`] data, if any.
    pub(crate) precondition_failure: Option<PreconditionFailure>,

    /// This field stores [`BadRequest`] data, if any.
    pub(crate) bad_request: Option<BadRequest>,

    /// This field stores [`RequestInfo`] data, if any.
    pub(crate) request_info: Option<RequestInfo>,

    /// This field stores [`ResourceInfo`] data, if any.
    pub(crate) resource_info: Option<ResourceInfo>,

    /// This field stores [`Help`] data, if any.
    pub(crate) help: Option<Help>,

    /// This field stores [`LocalizedMessage`] data, if any.
    pub(crate) localized_message: Option<LocalizedMessage>,
}

impl ErrorDetails {
    /// Generates an [`ErrorDetails`] struct with all fields set to `None`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Generates an [`ErrorDetails`] struct with [`RetryInfo`] details and
    /// remaining fields set to `None`.
    #[must_use]
    pub fn with_retry_info(retry_delay: Option<time::Duration>) -> Self {
        Self {
            retry_info: Some(RetryInfo::new(retry_delay)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`DebugInfo`] details and
    /// remaining fields set to `None`.
    pub fn with_debug_info(
        stack_entries: impl Into<Vec<String>>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            debug_info: Some(DebugInfo::new(stack_entries, detail)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`QuotaFailure`] details and
    /// remaining fields set to `None`.
    pub fn with_quota_failure(violations: impl Into<Vec<QuotaViolation>>) -> Self {
        Self {
            quota_failure: Some(QuotaFailure::new(violations)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`QuotaFailure`] details (one
    /// [`QuotaViolation`] set) and remaining fields set to `None`.
    pub fn with_quota_failure_violation(
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            quota_failure: Some(QuotaFailure::with_violation(subject, description)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`ErrorInfo`] details and
    /// remaining fields set to `None`.
    pub fn with_error_info(
        reason: impl Into<String>,
        domain: impl Into<String>,
        metadata: impl Into<HashMap<String, String>>,
    ) -> Self {
        Self {
            error_info: Some(ErrorInfo::new(reason, domain, metadata)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`PreconditionFailure`]
    /// details and remaining fields set to `None`.
    pub fn with_precondition_failure(violations: impl Into<Vec<PreconditionViolation>>) -> Self {
        Self {
            precondition_failure: Some(PreconditionFailure::new(violations)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`PreconditionFailure`]
    /// details (one [`PreconditionViolation`] set) and remaining fields set to
    /// `None`.
    pub fn with_precondition_failure_violation(
        violation_type: impl Into<String>,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            precondition_failure: Some(PreconditionFailure::with_violation(
                violation_type,
                subject,
                description,
            )),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`BadRequest`] details and
    /// remaining fields set to `None`.
    pub fn with_bad_request(field_violations: impl Into<Vec<FieldViolation>>) -> Self {
        Self {
            bad_request: Some(BadRequest::new(field_violations)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`BadRequest`] details (one
    /// [`FieldViolation`] set) and remaining fields set to `None`.
    pub fn with_bad_request_violation(
        field: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            bad_request: Some(BadRequest::with_violation(field, description)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`RequestInfo`] details and
    /// remaining fields set to `None`.
    pub fn with_request_info(
        request_id: impl Into<String>,
        serving_data: impl Into<String>,
    ) -> Self {
        Self {
            request_info: Some(RequestInfo::new(request_id, serving_data)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`ResourceInfo`] details and
    /// remaining fields set to `None`.
    pub fn with_resource_info(
        resource_type: impl Into<String>,
        resource_name: impl Into<String>,
        owner: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            resource_info: Some(ResourceInfo::new(
                resource_type,
                resource_name,
                owner,
                description,
            )),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`Help`] details and
    /// remaining fields set to `None`.
    pub fn with_help(links: impl Into<Vec<HelpLink>>) -> Self {
        Self {
            help: Some(Help::new(links)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`Help`] details (one
    /// [`HelpLink`] set) and remaining fields set to `None`.
    pub fn with_help_link(description: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            help: Some(Help::with_link(description, url)),
            ..Self::new()
        }
    }

    /// Generates an [`ErrorDetails`] struct with [`LocalizedMessage`] details
    /// and remaining fields set to `None`.
    pub fn with_localized_message(locale: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            localized_message: Some(LocalizedMessage::new(locale, message)),
            ..Self::new()
        }
    }

    /// Get [`RetryInfo`] details, if any.
    #[must_use]
    pub fn retry_info(&self) -> Option<&RetryInfo> {
        self.retry_info.as_ref()
    }

    /// Get [`DebugInfo`] details, if any.
    #[must_use]
    pub fn debug_info(&self) -> Option<&DebugInfo> {
        self.debug_info.as_ref()
    }

    /// Get [`QuotaFailure`] details, if any.
    #[must_use]
    pub fn quota_failure(&self) -> Option<&QuotaFailure> {
        self.quota_failure.as_ref()
    }

    /// Get [`ErrorInfo`] details, if any.
    #[must_use]
    pub fn error_info(&self) -> Option<&ErrorInfo> {
        self.error_info.as_ref()
    }

    /// Get [`PreconditionFailure`] details, if any.
    #[must_use]
    pub fn precondition_failure(&self) -> Option<&PreconditionFailure> {
        self.precondition_failure.as_ref()
    }

    /// Get [`BadRequest`] details, if any.
    #[must_use]
    pub fn bad_request(&self) -> Option<&BadRequest> {
        self.bad_request.as_ref()
    }

    /// Get [`RequestInfo`] details, if any.
    #[must_use]
    pub fn request_info(&self) -> Option<&RequestInfo> {
        self.request_info.as_ref()
    }

    /// Get [`ResourceInfo`] details, if any.
    #[must_use]
    pub fn resource_info(&self) -> Option<&ResourceInfo> {
        self.resource_info.as_ref()
    }

    /// Get [`Help`] details, if any.
    #[must_use]
    pub fn help(&self) -> Option<&Help> {
        self.help.as_ref()
    }

    /// Get [`LocalizedMessage`] details, if any.
    #[must_use]
    pub fn localized_message(&self) -> Option<&LocalizedMessage> {
        self.localized_message.as_ref()
    }

    /// Set [`RetryInfo`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_retry_info(&mut self, retry_delay: Option<time::Duration>) -> &mut Self {
        self.retry_info = Some(RetryInfo::new(retry_delay));
        self
    }

    /// Set [`DebugInfo`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_debug_info(
        &mut self,
        stack_entries: impl Into<Vec<String>>,
        detail: impl Into<String>,
    ) -> &mut Self {
        self.debug_info = Some(DebugInfo::new(stack_entries, detail));
        self
    }

    /// Set [`QuotaFailure`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_quota_failure(&mut self, violations: impl Into<Vec<QuotaViolation>>) -> &mut Self {
        self.quota_failure = Some(QuotaFailure::new(violations));
        self
    }

    /// Adds a [`QuotaViolation`] to [`QuotaFailure`] details. Sets
    /// [`QuotaFailure`] details if it is not set yet. Can be chained with
    /// other `.set_` and `.add_` [`ErrorDetails`] methods.
    pub fn add_quota_failure_violation(
        &mut self,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> &mut Self {
        match &mut self.quota_failure {
            Some(quota_failure) => {
                quota_failure.add_violation(subject, description);
            }
            None => {
                self.quota_failure = Some(QuotaFailure::with_violation(subject, description));
            }
        };
        self
    }

    /// Returns `true` if [`QuotaFailure`] is set and its `violations` vector
    /// is not empty, otherwise returns `false`.
    #[must_use]
    pub fn has_quota_failure_violations(&self) -> bool {
        if let Some(quota_failure) = &self.quota_failure {
            return !quota_failure.violations.is_empty();
        }
        false
    }

    /// Set [`ErrorInfo`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_error_info(
        &mut self,
        reason: impl Into<String>,
        domain: impl Into<String>,
        metadata: impl Into<HashMap<String, String>>,
    ) -> &mut Self {
        self.error_info = Some(ErrorInfo::new(reason, domain, metadata));
        self
    }

    /// Set [`PreconditionFailure`] details. Can be chained with other `.set_`
    /// and `.add_` [`ErrorDetails`] methods.
    pub fn set_precondition_failure(
        &mut self,
        violations: impl Into<Vec<PreconditionViolation>>,
    ) -> &mut Self {
        self.precondition_failure = Some(PreconditionFailure::new(violations));
        self
    }

    /// Adds a [`PreconditionViolation`] to [`PreconditionFailure`] details.
    /// Sets [`PreconditionFailure`] details if it is not set yet. Can be
    /// chained with other `.set_` and `.add_` [`ErrorDetails`] methods.
    pub fn add_precondition_failure_violation(
        &mut self,
        violation_type: impl Into<String>,
        subject: impl Into<String>,
        description: impl Into<String>,
    ) -> &mut Self {
        match &mut self.precondition_failure {
            Some(precondition_failure) => {
                precondition_failure.add_violation(violation_type, subject, description);
            }
            None => {
                self.precondition_failure = Some(PreconditionFailure::with_violation(
                    violation_type,
                    subject,
                    description,
                ));
            }
        };
        self
    }

    /// Returns `true` if [`PreconditionFailure`] is set and its `violations`
    /// vector is not empty, otherwise returns `false`.
    #[must_use]
    pub fn has_precondition_failure_violations(&self) -> bool {
        if let Some(precondition_failure) = &self.precondition_failure {
            return !precondition_failure.violations.is_empty();
        }
        false
    }

    /// Set [`BadRequest`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_bad_request(&mut self, violations: impl Into<Vec<FieldViolation>>) -> &mut Self {
        self.bad_request = Some(BadRequest::new(violations));
        self
    }

    /// Adds a [`FieldViolation`] to [`BadRequest`] details. Sets
    /// [`BadRequest`] details if it is not set yet. Can be chained with other
    /// `.set_` and `.add_` [`ErrorDetails`] methods.
    pub fn add_bad_request_violation(
        &mut self,
        field: impl Into<String>,
        description: impl Into<String>,
    ) -> &mut Self {
        match &mut self.bad_request {
            Some(bad_request) => {
                bad_request.add_violation(field, description);
            }
            None => {
                self.bad_request = Some(BadRequest::with_violation(field, description));
            }
        };
        self
    }

    /// Returns `true` if [`BadRequest`] is set and its `field_violations`
    /// vector is not empty, otherwise returns `false`.
    #[must_use]
    pub fn has_bad_request_violations(&self) -> bool {
        if let Some(bad_request) = &self.bad_request {
            return !bad_request.field_violations.is_empty();
        }
        false
    }

    /// Set [`RequestInfo`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_request_info(
        &mut self,
        request_id: impl Into<String>,
        serving_data: impl Into<String>,
    ) -> &mut Self {
        self.request_info = Some(RequestInfo::new(request_id, serving_data));
        self
    }

    /// Set [`ResourceInfo`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_resource_info(
        &mut self,
        resource_type: impl Into<String>,
        resource_name: impl Into<String>,
        owner: impl Into<String>,
        description: impl Into<String>,
    ) -> &mut Self {
        self.resource_info = Some(ResourceInfo::new(
            resource_type,
            resource_name,
            owner,
            description,
        ));
        self
    }

    /// Set [`Help`] details. Can be chained with other `.set_` and `.add_`
    /// [`ErrorDetails`] methods.
    pub fn set_help(&mut self, links: impl Into<Vec<HelpLink>>) -> &mut Self {
        self.help = Some(Help::new(links));
        self
    }

    /// Adds a [`HelpLink`] to [`Help`] details. Sets [`Help`] details if it is
    /// not set yet. Can be chained with other `.set_` and `.add_`
    /// [`ErrorDetails`] methods.
    pub fn add_help_link(
        &mut self,
        description: impl Into<String>,
        url: impl Into<String>,
    ) -> &mut Self {
        match &mut self.help {
            Some(help) => {
                help.add_link(description, url);
            }
            None => {
                self.help = Some(Help::with_link(description, url));
            }
        };
        self
    }

    /// Returns `true` if [`Help`] is set and its `links` vector is not empty,
    /// otherwise returns `false`.
    #[must_use]
    pub fn has_help_links(&self) -> bool {
        if let Some(help) = &self.help {
            return !help.links.is_empty();
        }
        false
    }

    /// Set [`LocalizedMessage`] details. Can be chained with other `.set_` and
    /// `.add_` [`ErrorDetails`] methods.
    pub fn set_localized_message(
        &mut self,
        locale: impl Into<String>,
        message: impl Into<String>,
    ) -> &mut Self {
        self.localized_message = Some(LocalizedMessage::new(locale, message));
        self
    }
}
