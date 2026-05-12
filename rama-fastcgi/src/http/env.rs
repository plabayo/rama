//! CGI-environment overrides for the HTTP adapter layer.
//!
//! Attach via [`Request::extensions_mut`][rama_http_types::Request::extensions_mut]
//! before serving through [`FastCgiHttpClient`][super::FastCgiHttpClient]
//! to override the spec-default values rama emits in the FastCGI PARAMS
//! environment. Absent or `None` fields fall through to the defaults
//! documented on [`crate::proto::cgi`].

use rama_core::bytes::Bytes;
use rama_core::extensions::Extension;

/// Per-request override of selected CGI environment variables.
///
/// Default-instance leaves every field `None`, so the convert layer uses the
/// spec/nginx defaults. Mostly useful for backends that need non-standard
/// `GATEWAY_INTERFACE` strings, alternate `REDIRECT_STATUS` semantics, or a
/// custom `SERVER_SOFTWARE` banner.
#[derive(Debug, Clone, Default, Extension)]
#[extension(tags(http))]
pub struct FastCgiHttpEnv {
    /// Override the `REDIRECT_STATUS` CGI variable.
    /// Default: [`cgi::REDIRECT_STATUS_OK`][crate::proto::cgi::REDIRECT_STATUS_OK] (`"200"`).
    pub redirect_status: Option<Bytes>,
    /// Override the `GATEWAY_INTERFACE` CGI variable.
    /// Default: [`cgi::GATEWAY_INTERFACE_CGI_1_1`][crate::proto::cgi::GATEWAY_INTERFACE_CGI_1_1] (`"CGI/1.1"`).
    pub gateway_interface: Option<Bytes>,
    /// Override the `SERVER_SOFTWARE` CGI variable.
    /// Default: omitted (the convert layer doesn't emit it).
    pub server_software: Option<Bytes>,
}

impl FastCgiHttpEnv {
    /// Create a fresh override with every field unset.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set `REDIRECT_STATUS`.
    #[must_use]
    pub fn with_redirect_status(mut self, value: impl Into<Bytes>) -> Self {
        self.redirect_status = Some(value.into());
        self
    }

    /// Set `GATEWAY_INTERFACE`.
    #[must_use]
    pub fn with_gateway_interface(mut self, value: impl Into<Bytes>) -> Self {
        self.gateway_interface = Some(value.into());
        self
    }

    /// Set `SERVER_SOFTWARE`.
    #[must_use]
    pub fn with_server_software(mut self, value: impl Into<Bytes>) -> Self {
        self.server_software = Some(value.into());
        self
    }
}
