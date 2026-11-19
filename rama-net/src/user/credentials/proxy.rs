use core::{
    fmt::{self, Write as _},
    str::FromStr,
};

use base64::{Engine as _, display::Base64Display, engine::general_purpose::STANDARD};
use rama_core::{
    error::{BoxError, BoxErrorExt as _, ErrorContext as _, ErrorExt as _},
    extensions::Extension,
};
use rama_utils::{
    macros::{match_ignore_ascii_case_str, serde_str::impl_serde_str},
    str::smol_str::SmolStr,
};

use super::{Basic, Bearer};
use crate::std::string::String;

#[derive(Debug, Clone, Extension)]
#[extension(tags(net, proxy))]
/// Extension wrapper that can be used by
/// Deep Protocol Inspection (DPI) services which
/// processed an exchanged [`ProxyCredential`].
pub struct DpiProxyCredential(pub ProxyCredential);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
/// Proxy credentials.
///
/// Written as the value of a `Proxy-Authorization` header: `Basic <base64(user:pass)>`
/// or `Bearer <token>`. Parsing also takes `Basic user:pass` and a bare `user:pass`.
pub enum ProxyCredential {
    /// [`Basic`]` credentials.
    Basic(Basic),
    /// [`Bearer`] credentials.
    Bearer(Bearer),
}

impl From<Basic> for ProxyCredential {
    fn from(basic: Basic) -> Self {
        Self::Basic(basic)
    }
}

impl From<Bearer> for ProxyCredential {
    fn from(bearer: Bearer) -> Self {
        Self::Bearer(bearer)
    }
}

impl fmt::Display for ProxyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic(basic) => {
                let mut user_pass = String::new();
                write!(user_pass, "{basic}")?;
                write!(
                    f,
                    "Basic {}",
                    Base64Display::new(user_pass.as_bytes(), &STANDARD)
                )
            }
            Self::Bearer(bearer) => write!(f, "Bearer {bearer}"),
        }
    }
}

impl FromStr for ProxyCredential {
    type Err = BoxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // A scheme never contains ':', so a space after one belongs to the password.
        let Some((scheme, value)) = s
            .split_once(' ')
            .filter(|(scheme, _)| !scheme.contains(':'))
        else {
            return basic_user_pass(s).context("parse bare basic credential");
        };
        match_ignore_ascii_case_str! {
            match(scheme) {
                "basic" => if value.contains(':') {
                    // base64 never contains ':', so such a value is still plaintext
                    basic_user_pass(value)
                } else {
                    let bytes = STANDARD.decode(value).map_err(|err| {
                        BoxError::from_static_str("basic credential is not base64")
                            .context_debug_field("error", err)
                    })?;
                    let user_pass =
                        core::str::from_utf8(&bytes).context("basic credential as utf-8")?;
                    Ok(Self::Basic(user_pass.parse()?))
                },
                "bearer" => Ok(Self::Bearer(value.parse()?)),
                _ => Err(BoxError::from_static_str("unknown proxy credential scheme")
                    .context_str_field("scheme", SmolStr::new(scheme))),
            }
        }
    }
}

fn basic_user_pass(s: &str) -> Result<ProxyCredential, BoxError> {
    if !s.contains(':') {
        return Err(BoxError::from_static_str(
            "a basic proxy credential is written as user:pass",
        ));
    }
    Ok(ProxyCredential::Basic(s.parse()?))
}

impl_serde_str!(display ProxyCredential);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::credentials::basic;

    #[test]
    fn a_proxy_credential_round_trips_as_a_header_value() {
        for (credential, text) in [
            (
                ProxyCredential::from(basic!("john", "secret")),
                "Basic am9objpzZWNyZXQ=",
            ),
            (
                ProxyCredential::from(Bearer::try_from("abc123").unwrap()),
                "Bearer abc123",
            ),
        ] {
            assert_eq!(credential.to_string(), text);
            assert_eq!(text.parse::<ProxyCredential>().unwrap(), credential);
        }
    }

    #[test]
    fn a_bare_user_pass_is_basic() {
        assert_eq!(
            "john:secret".parse::<ProxyCredential>().unwrap(),
            ProxyCredential::from(basic!("john", "secret")),
        );
        assert_eq!(
            "john:my secret".parse::<ProxyCredential>().unwrap(),
            ProxyCredential::from(basic!("john", "my secret")),
        );
    }

    #[test]
    fn a_basic_value_with_a_colon_is_plaintext() {
        for text in [
            "basic john:secret",
            "Basic john:secret",
            "BASIC john:secret",
        ] {
            assert_eq!(
                text.parse::<ProxyCredential>().unwrap(),
                ProxyCredential::from(basic!("john", "secret")),
                "{text}"
            );
        }
    }

    #[test]
    fn a_credential_scheme_is_case_insensitive() {
        assert_eq!(
            "bearer abc123".parse::<ProxyCredential>().unwrap(),
            ProxyCredential::from(Bearer::try_from("abc123").unwrap()),
        );
        assert_eq!(
            "bASIC am9objpzZWNyZXQ=".parse::<ProxyCredential>().unwrap(),
            ProxyCredential::from(basic!("john", "secret")),
        );
    }

    #[test]
    fn invalid_proxy_credentials_are_refused() {
        for text in [
            "",
            "Basic !!!",
            "Digest abc",
            "Bearer ",
            // an old bearer token: never guessed to be a basic username
            "abc123",
        ] {
            assert!(text.parse::<ProxyCredential>().is_err(), "{text}");
        }
    }
}
