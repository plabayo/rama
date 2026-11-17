use core::fmt::{self, Write as _};

use crate::{
    address::Host,
    std::string::String,
    uri::{
        TemplateOperator, TemplateVariable, UriTemplate, UriTemplateError, encode_template_value_to,
    },
};

/// The path-and-query URI Template of a proxy.
///
/// It locates the tunnels on the proxy: scheme, host, port and credentials come from
/// the [`ProxyAddress`] carrying it. Its variables say which protocol, see
/// [`ProxyPathProtocolTemplate`].
///
/// The template is validated on construction: a level 3 or lower template whose path
/// starts with `/` and using only simple (`{x}`) and form-style query (`{?x}`, `{&x}`)
/// expressions. Other variables are allowed and expand empty. Cloning is cheap.
///
/// The syntax is RFC 6570 ([`UriTemplate`]), not [`PathPattern`] route syntax.
///
/// [`PathPattern`]: crate::uri::PathPattern
/// [`ProxyAddress`]: super::ProxyAddress
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProxyPathTemplate {
    template: UriTemplate,
    protocol: ProxyPathProtocolTemplate,
}

/// The protocol a [`ProxyPathTemplate`] is for, with its variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyPathProtocolTemplate {
    /// `target_host` and `target_port` ([RFC 9298 §2]).
    ///
    /// [RFC 9298 §2]: https://datatracker.ietf.org/doc/html/rfc9298#section-2
    ConnectUdp {
        target_host: TemplateVariable,
        target_port: TemplateVariable,
    },
    /// Neither of those, with the optional `target` and `ipproto` ([RFC 9484 §3]).
    ///
    /// [RFC 9484 §3]: https://datatracker.ietf.org/doc/html/rfc9484#section-3
    ConnectIp {
        target: Option<TemplateVariable>,
        ip_proto: Option<TemplateVariable>,
    },
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
    /// The template names `target_port` but not `target_host`.
    MissingTargetHost,
    /// The template names `target_host` but not `target_port`.
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

    /// The default CONNECT-IP template a proxy serves ([RFC 9484 §3]).
    ///
    /// [RFC 9484 §3]: https://datatracker.ietf.org/doc/html/rfc9484#section-3
    pub const CONNECT_IP_DEFAULT: &str = "/.well-known/masque/ip/{target}/{ipproto}/";

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
        let protocol = match (
            template.variable("target_host"),
            template.variable("target_port"),
        ) {
            (Some(target_host), Some(target_port)) => ProxyPathProtocolTemplate::ConnectUdp {
                target_host,
                target_port,
            },
            (Some(_), None) => return Err(ProxyPathTemplateError::MissingTargetPort),
            (None, Some(_)) => return Err(ProxyPathTemplateError::MissingTargetHost),
            (None, None) => ProxyPathProtocolTemplate::ConnectIp {
                target: template.variable("target"),
                ip_proto: template.variable("ipproto"),
            },
        };
        Ok(Self { template, protocol })
    }

    /// The RFC 9298 default CONNECT-UDP template, parsed once.
    #[must_use]
    pub fn connect_udp_default() -> Self {
        #[cfg(feature = "std")]
        {
            static DEFAULT: std::sync::LazyLock<ProxyPathTemplate> =
                std::sync::LazyLock::new(|| {
                    ProxyPathTemplate::parse_constant(ProxyPathTemplate::CONNECT_UDP_DEFAULT)
                });
            DEFAULT.clone()
        }
        #[cfg(not(feature = "std"))]
        {
            Self::parse_constant(Self::CONNECT_UDP_DEFAULT)
        }
    }

    /// The RFC 9484 default CONNECT-IP template, parsed once.
    #[must_use]
    pub fn connect_ip_default() -> Self {
        #[cfg(feature = "std")]
        {
            static DEFAULT: std::sync::LazyLock<ProxyPathTemplate> =
                std::sync::LazyLock::new(|| {
                    ProxyPathTemplate::parse_constant(ProxyPathTemplate::CONNECT_IP_DEFAULT)
                });
            DEFAULT.clone()
        }
        #[cfg(not(feature = "std"))]
        {
            Self::parse_constant(Self::CONNECT_IP_DEFAULT)
        }
    }

    fn parse_constant(template: &'static str) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "a constant of this crate, covered by its own test"
        )]
        Self::try_new(template).expect("a default MASQUE template is a valid template")
    }

    /// Whether this is the RFC 9298 default CONNECT-UDP template.
    #[must_use]
    pub fn is_connect_udp_default(&self) -> bool {
        self.template.as_str() == Self::CONNECT_UDP_DEFAULT
    }

    /// Whether this is the RFC 9484 default CONNECT-IP template.
    #[must_use]
    pub fn is_connect_ip_default(&self) -> bool {
        self.template.as_str() == Self::CONNECT_IP_DEFAULT
    }

    #[must_use]
    pub fn protocol(&self) -> ProxyPathProtocolTemplate {
        self.protocol
    }

    #[must_use]
    pub fn is_connect_udp(&self) -> bool {
        matches!(self.protocol, ProxyPathProtocolTemplate::ConnectUdp { .. })
    }

    #[must_use]
    pub fn is_connect_ip(&self) -> bool {
        matches!(self.protocol, ProxyPathProtocolTemplate::ConnectIp { .. })
    }

    /// The underlying URI Template.
    #[must_use]
    pub fn template(&self) -> &UriTemplate {
        &self.template
    }

    /// The template text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.template.as_str()
    }

    /// Append the CONNECT-UDP path and query for a target, leaving other variables empty.
    ///
    /// A CONNECT-IP template expands with every variable empty.
    pub fn expand_target_to(&self, out: &mut String, host: &Host, port: u16) {
        let ProxyPathProtocolTemplate::ConnectUdp {
            target_host,
            target_port,
        } = self.protocol
        else {
            self.template.expand_to(out, |_| None);
            return;
        };
        let host = target_host_text(host);
        let mut port_text = String::new();
        _ = write!(port_text, "{port}");
        self.template.expand_to(out, |variable| {
            if variable == target_host {
                Some(host.as_str())
            } else if variable == target_port {
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

impl core::str::FromStr for ProxyPathTemplate {
    type Err = ProxyPathTemplateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_new(s)
    }
}

rama_utils::macros::serde_str::impl_serde_str!(as_str ProxyPathTemplate);
