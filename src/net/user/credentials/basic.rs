use std::borrow::Cow;

use crate::error::{ErrorContext, OpaqueError};
use crate::http;
use crate::http::headers::authorization;
use base64::engine::general_purpose::STANDARD as ENGINE;
use base64::Engine;

#[derive(Debug, Clone)]
/// Basic credentials.
pub struct Basic {
    data: BasicData,
}

#[derive(Debug, Clone)]
enum BasicData {
    Username(Cow<'static, str>),
    Pair {
        username: Cow<'static, str>,
        password: Cow<'static, str>,
    },
    Decoded {
        decoded: String,
        colon_pos: usize,
    },
}

impl Basic {
    /// Creates a new [`Basic`] credential.
    pub fn new(
        username: impl Into<Cow<'static, str>>,
        password: impl Into<Cow<'static, str>>,
    ) -> Self {
        let data = BasicData::Pair {
            username: username.into(),
            password: password.into(),
        };
        Basic { data }
    }

    /// Try to create a [`Basic`] credential from a header string,
    /// encoded as 'Basic <base64(username:{password}?)>'.
    pub fn try_from_header_str(s: impl AsRef<str>) -> Result<Self, OpaqueError> {
        let value = s.as_ref();

        if value.as_bytes().len() <= BASIC_SCHEME.len() + 1 {
            return Err(OpaqueError::from_display(
                "invalid scheme length in basic str",
            ));
        }
        if !value.as_bytes()[..BASIC_SCHEME.len()].eq_ignore_ascii_case(BASIC_SCHEME.as_bytes()) {
            return Err(OpaqueError::from_display("invalid scheme in basic str"));
        }

        let bytes = &value.as_bytes()[BASIC_SCHEME.len() + 1..];
        let non_space_pos = bytes
            .iter()
            .position(|b| *b != b' ')
            .ok_or_else(|| OpaqueError::from_display("missing space separator in basic str"))?;
        let bytes = &bytes[non_space_pos..];

        let bytes = ENGINE
            .decode(bytes)
            .context("failed to decode base64 basic str")?;

        let decoded = String::from_utf8(bytes).context("base64 decoded basic str is not utf-8")?;

        Self::try_from_clear_str(decoded)
    }

    /// Try to create a [`Basic`] credential from a clear string,
    /// encoded as 'username:{password}?'.
    pub fn try_from_clear_str(s: String) -> Result<Self, OpaqueError> {
        let colon_pos = s
            .find(':')
            .ok_or_else(|| OpaqueError::from_display("missing colon separator in clear str"))?;
        if colon_pos == 0 {
            return Err(OpaqueError::from_display(
                "missing username in basic credential",
            ));
        }
        let data = BasicData::Decoded {
            decoded: s,
            colon_pos,
        };
        Ok(Basic { data })
    }

    /// Serialize this [`Basic`] credential as a header string.
    pub fn as_header_string(&self) -> String {
        let mut encoded = format!("{BASIC_SCHEME} ");

        match &self.data {
            BasicData::Username(username) => {
                let decoded = format!("{username}:");
                ENGINE.encode_string(&decoded, &mut encoded);
            }
            BasicData::Pair { username, password } => {
                let decoded = format!("{username}:{password}");
                ENGINE.encode_string(&decoded, &mut encoded);
            }
            BasicData::Decoded { decoded, .. } => {
                ENGINE.encode_string(decoded, &mut encoded);
            }
        }

        encoded
    }

    /// View this [`Basic`] as a [`HeaderValue`][http::HeaderValue].
    pub fn as_header_value(&self) -> http::HeaderValue {
        let encoded = self.as_header_string();
        // we validate the inner value upon creation
        http::HeaderValue::from_str(&encoded).expect("inner value should always be valid")
    }

    /// Serialize this [`Basic`] credential as a clear (not encoded) string.
    pub fn as_clear_string(&self) -> String {
        match &self.data {
            BasicData::Username(username) => {
                format!("{username}:")
            }
            BasicData::Pair { username, password } => {
                format!("{username}:{password}")
            }
            BasicData::Decoded { decoded, .. } => decoded.clone(),
        }
    }

    /// Creates a new [`Basic`] credential with only a username.
    pub fn unprotected(username: impl Into<Cow<'static, str>>) -> Self {
        let data: BasicData = BasicData::Username(username.into());
        Basic { data }
    }

    /// View the decoded username.
    pub fn username(&self) -> &str {
        match &self.data {
            BasicData::Username(username) => username,
            BasicData::Pair { username, .. } => username,
            BasicData::Decoded { decoded, colon_pos } => &decoded[..*colon_pos],
        }
    }

    /// View the decoded password.
    pub fn password(&self) -> &str {
        match &self.data {
            BasicData::Username(_) => "",
            BasicData::Pair { password, .. } => password,
            BasicData::Decoded { decoded, colon_pos } => &decoded[*colon_pos + 1..],
        }
    }
}

impl PartialEq<Basic> for Basic {
    fn eq(&self, other: &Basic) -> bool {
        self.username() == other.username() && self.password() == other.password()
    }
}

impl Eq for Basic {}

const BASIC_SCHEME: &str = "Basic";

impl authorization::Credentials for Basic {
    const SCHEME: &'static str = BASIC_SCHEME;

    fn decode(value: &http::HeaderValue) -> Option<Self> {
        let value = value.to_str().ok()?;
        Self::try_from_header_str(value).ok()
    }

    fn encode(&self) -> http::HeaderValue {
        self.as_header_value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authorization::Credentials;

    #[test]
    fn basic_parse_empty() {
        let value = Basic::try_from_header_str("");
        assert!(value.is_err());
    }

    #[test]
    fn basic_clear_text_empty() {
        let value = Basic::try_from_clear_str("".to_owned());
        assert!(value.is_err());
    }

    #[test]
    fn basic_missing_username() {
        let value = Basic::try_from_clear_str(":".to_owned());
        assert!(value.is_err());
    }

    #[test]
    fn basic_encode() {
        let auth = Basic::new("Aladdin", "open sesame");
        let value = auth.encode();

        assert_eq!(value, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",);
    }

    #[test]
    fn basic_encode_no_password() {
        let auth = Basic::unprotected("Aladdin");
        let value = auth.encode();

        assert_eq!(value, "Basic QWxhZGRpbjo=",);
    }

    #[test]
    fn basic_decode() {
        let auth = Basic::decode(&http::HeaderValue::from_static(
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
    }

    #[test]
    fn basic_decode_case_insensitive() {
        let auth = Basic::decode(&http::HeaderValue::from_static(
            "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
    }

    #[test]
    fn basic_decode_extra_whitespaces() {
        let auth = Basic::decode(&http::HeaderValue::from_static(
            "Basic  QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
    }

    #[test]
    fn basic_decode_no_password() {
        let auth = Basic::decode(&http::HeaderValue::from_static("Basic QWxhZGRpbjo=")).unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "");
    }

    #[test]
    fn basic_header() {
        let auth = Basic::try_from_header_str("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==").unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
        assert_eq!(
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
            auth.as_header_string()
        );
    }

    #[test]
    fn basic_header_no_password() {
        let auth = Basic::try_from_header_str("Basic QWxhZGRpbjo=").unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "");
        assert_eq!("Basic QWxhZGRpbjo=", auth.as_header_string());
    }

    #[test]
    fn basic_clear() {
        let auth = Basic::try_from_clear_str("Aladdin:open sesame".to_owned()).unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
        assert_eq!("Aladdin:open sesame", auth.as_clear_string());
    }

    #[test]
    fn basic_clear_no_password() {
        let auth = Basic::try_from_clear_str("Aladdin:".to_owned()).unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "");
        assert_eq!("Aladdin:", auth.as_clear_string());
    }
}
