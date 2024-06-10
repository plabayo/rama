use std::borrow::Cow;

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

impl authorization::Credentials for Basic {
    const SCHEME: &'static str = "Basic";

    fn decode(value: &http::HeaderValue) -> Option<Self> {
        debug_assert!(
            value.as_bytes()[..Self::SCHEME.len()].eq_ignore_ascii_case(Self::SCHEME.as_bytes()),
            "HeaderValue to decode should start with \"Basic ..\", received = {:?}",
            value,
        );

        let bytes = &value.as_bytes()["Basic ".len()..];
        let non_space_pos = bytes.iter().position(|b| *b != b' ')?;
        let bytes = &bytes[non_space_pos..];

        let bytes = ENGINE.decode(bytes).ok()?;

        let decoded = String::from_utf8(bytes).ok()?;

        let colon_pos = decoded.find(':')?;

        let data = BasicData::Decoded { decoded, colon_pos };
        Some(Basic { data })
    }

    fn encode(&self) -> http::HeaderValue {
        let mut encoded = String::from("Basic ");

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

        let bytes = bytes::Bytes::from(encoded);
        http::HeaderValue::from_maybe_shared(bytes)
            .expect("base64 encoding is always a valid HeaderValue")
    }
}

#[cfg(test)]
mod tests {
    use ::http::HeaderValue;
    use headers::authorization::Credentials;

    use super::*;

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
        let auth = Basic::decode(&HeaderValue::from_static(
            "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
    }

    #[test]
    fn basic_decode_case_insensitive() {
        let auth = Basic::decode(&HeaderValue::from_static(
            "basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
    }

    #[test]
    fn basic_decode_extra_whitespaces() {
        let auth = Basic::decode(&HeaderValue::from_static(
            "Basic  QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        ))
        .unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "open sesame");
    }

    #[test]
    fn basic_decode_no_password() {
        let auth = Basic::decode(&HeaderValue::from_static("Basic QWxhZGRpbjo=")).unwrap();
        assert_eq!(auth.username(), "Aladdin");
        assert_eq!(auth.password(), "");
    }
}
