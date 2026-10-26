use core::fmt::{self, Write as _};

use crate::{
    address::Host,
    std::string::String,
    uri::{
        TemplateOperator, TemplateVariable, UriTemplate, UriTemplateError, encode_template_value_to,
    },
};

/// The path-and-query URI Template of a MASQUE proxy.
///
/// It locates CONNECT-UDP tunnels on the proxy ([RFC 9298 §2]): scheme, host, port
/// and credentials come from the [`ProxyAddress`] carrying it. The template is
/// validated on construction: a level 3 or lower template whose path starts with
/// `/`, naming both `target_host` and `target_port`, and using only simple
/// (`{x}`) and form-style query (`{?x}`, `{&x}`) expressions. Other variables are
/// allowed and expand empty. Cloning is cheap.
///
/// [`ProxyAddress`]: super::ProxyAddress
/// [RFC 9298 §2]: https://datatracker.ietf.org/doc/html/rfc9298#section-2
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProxyPathTemplate {
    template: UriTemplate,
    target_host: TemplateVariable,
    target_port: TemplateVariable,
}

/// Why a [`ProxyPathTemplate`] was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProxyPathTemplateError {
    /// Not a valid URI Template.
    Template(UriTemplateError),
    /// The path does not start with `/`.
    NotAbsolutePath,
    /// A literal `#`: a request target carries no fragment.
    Fragment,
    /// The template does not name `target_host`.
    MissingTargetHost,
    /// The template does not name `target_port`.
    MissingTargetPort,
    /// An operator RFC 9298 forbids (`+`, `#`, `.`, `/`, `;`).
    ForbiddenOperator(TemplateOperator),
}

impl fmt::Display for ProxyPathTemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Template(err) => write!(f, "invalid proxy path template: {err}"),
            Self::NotAbsolutePath => f.write_str("proxy path template must start with '/'"),
            Self::Fragment => f.write_str("proxy path template may not contain a fragment"),
            Self::MissingTargetHost => {
                f.write_str("proxy path template must contain the target_host variable")
            }
            Self::MissingTargetPort => {
                f.write_str("proxy path template must contain the target_port variable")
            }
            Self::ForbiddenOperator(operator) => {
                write!(
                    f,
                    "proxy path template uses forbidden operator {operator:?}"
                )
            }
        }
    }
}

impl core::error::Error for ProxyPathTemplateError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Template(err) => Some(err),
            _ => None,
        }
    }
}

impl From<UriTemplateError> for ProxyPathTemplateError {
    fn from(err: UriTemplateError) -> Self {
        Self::Template(err)
    }
}

impl ProxyPathTemplate {
    /// The default CONNECT-UDP template a proxy serves ([RFC 9298 §2]).
    ///
    /// [RFC 9298 §2]: https://datatracker.ietf.org/doc/html/rfc9298#section-2
    pub const CONNECT_UDP_DEFAULT: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";

    /// Parse and validate a path-and-query template.
    pub fn try_new(template: impl AsRef<str>) -> Result<Self, ProxyPathTemplateError> {
        let template = UriTemplate::try_new(template)?;
        if !template.as_str().starts_with('/') {
            return Err(ProxyPathTemplateError::NotAbsolutePath);
        }
        // `{#...}` is reported as a forbidden operator below.
        if template.as_str().contains('#') && !template.as_str().contains("{#") {
            return Err(ProxyPathTemplateError::Fragment);
        }
        if let Some(operator) = template.operators().find(|operator| {
            !matches!(
                operator,
                TemplateOperator::Simple
                    | TemplateOperator::Query
                    | TemplateOperator::QueryContinuation
            )
        }) {
            return Err(ProxyPathTemplateError::ForbiddenOperator(operator));
        }
        let target_host = template
            .variable("target_host")
            .ok_or(ProxyPathTemplateError::MissingTargetHost)?;
        let target_port = template
            .variable("target_port")
            .ok_or(ProxyPathTemplateError::MissingTargetPort)?;
        Ok(Self {
            template,
            target_host,
            target_port,
        })
    }

    /// Whether this is the RFC 9298 default CONNECT-UDP template.
    #[must_use]
    pub fn is_connect_udp_default(&self) -> bool {
        self.template.as_str() == Self::CONNECT_UDP_DEFAULT
    }

    /// The underlying URI Template.
    #[must_use]
    pub fn template(&self) -> &UriTemplate {
        &self.template
    }

    /// The `target_host` variable.
    #[must_use]
    pub fn target_host(&self) -> TemplateVariable {
        self.target_host
    }

    /// The `target_port` variable.
    #[must_use]
    pub fn target_port(&self) -> TemplateVariable {
        self.target_port
    }

    /// The template text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.template.as_str()
    }

    /// Append the path and query for a target, leaving other variables empty.
    pub fn expand_target_to(&self, out: &mut String, host: &Host, port: u16) {
        let host = target_host_text(host);
        let mut port_text = String::new();
        _ = write!(port_text, "{port}");
        self.template.expand_to(out, |variable| {
            if variable == self.target_host {
                Some(host.as_str())
            } else if variable == self.target_port {
                Some(port_text.as_str())
            } else {
                None
            }
        });
    }

    /// Append the default CONNECT-UDP path for a target without parsing a template.
    pub fn expand_connect_udp_default_to(out: &mut String, host: &Host, port: u16) {
        out.push_str("/.well-known/masque/udp/");
        encode_template_value_to(out, &target_host_text(host));
        _ = write!(out, "/{port}/");
    }
}

/// IP literals without brackets ([RFC 9298 §3]); names verbatim.
///
/// [RFC 9298 §3]: https://datatracker.ietf.org/doc/html/rfc9298#section-3
fn target_host_text(host: &Host) -> String {
    match host {
        Host::Name(domain) => domain.as_str().into(),
        Host::Address(ip) => {
            let mut text = String::new();
            _ = write!(text, "{ip}");
            text
        }
        Host::Uninterpreted(host) => host.as_str().into(),
    }
}

impl fmt::Debug for ProxyPathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ProxyPathTemplate")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for ProxyPathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
