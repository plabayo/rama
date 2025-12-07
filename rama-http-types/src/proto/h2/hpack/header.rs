use super::{DecoderError, NeedMore};
use crate::proto::h2::ext::Protocol;
use crate::{HeaderName, HeaderValue, Method, StatusCode};

use rama_core::bytes::Bytes;
use std::fmt;

/// HTTP/2 Header
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Header<T = HeaderName> {
    Field { name: T, value: HeaderValue },
    // TODO: Change these types to `http::uri` types.
    Authority(BytesStr),
    Method(Method),
    Scheme(BytesStr),
    Path(BytesStr),
    Protocol(Protocol),
    Status(StatusCode),
}

/// The header field name
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Name<'a> {
    Field(&'a HeaderName),
    Authority,
    Method,
    Scheme,
    Path,
    Protocol,
    Status,
}

#[doc(hidden)]
#[derive(Clone, Eq, PartialEq, Default)]
pub struct BytesStr(Bytes);

fn len(name: &HeaderName, value: &HeaderValue) -> usize {
    let n: &str = name.as_ref();
    32 + n.len() + value.len()
}

impl Header<Option<HeaderName>> {
    pub fn reify(self) -> Result<Header, HeaderValue> {
        Ok(match self {
            Self::Field {
                name: Some(n),
                value,
            } => Header::Field { name: n, value },
            Self::Field { name: None, value } => return Err(value),
            Self::Authority(v) => Header::Authority(v),
            Self::Method(v) => Header::Method(v),
            Self::Scheme(v) => Header::Scheme(v),
            Self::Path(v) => Header::Path(v),
            Self::Protocol(v) => Header::Protocol(v),
            Self::Status(v) => Header::Status(v),
        })
    }
}

impl Header {
    pub fn try_new(name: &Bytes, value: Bytes) -> Result<Self, DecoderError> {
        if name.is_empty() {
            return Err(DecoderError::NeedMore(NeedMore::UnexpectedEndOfStream));
        }
        if name[0] == b':' {
            match &name[1..] {
                b"authority" => {
                    let value = BytesStr::try_from(value)?;
                    Ok(Self::Authority(value))
                }
                b"method" => {
                    let method = Method::from_bytes(&value)?;
                    Ok(Self::Method(method))
                }
                b"scheme" => {
                    let value = BytesStr::try_from(value)?;
                    Ok(Self::Scheme(value))
                }
                b"path" => {
                    let value = BytesStr::try_from(value)?;
                    Ok(Self::Path(value))
                }
                b"protocol" => {
                    let value = Protocol::try_from(value)?;
                    Ok(Self::Protocol(value))
                }
                b"status" => {
                    let status = StatusCode::from_bytes(&value)?;
                    Ok(Self::Status(status))
                }
                _ => Err(DecoderError::InvalidPseudoheader),
            }
        } else {
            // HTTP/2 requires lower case header names
            let name = HeaderName::from_lowercase(name)?;
            let value = HeaderValue::from_bytes(&value)?;

            Ok(Self::Field { name, value })
        }
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match *self {
            Self::Field {
                ref name,
                ref value,
            } => len(name, value),
            Self::Authority(ref v) => 32 + 10 + v.len(),
            Self::Method(ref v) => 32 + 7 + v.as_ref().len(),
            Self::Scheme(ref v) => 32 + 7 + v.len(),
            Self::Path(ref v) => 32 + 5 + v.len(),
            Self::Protocol(ref v) => 32 + 9 + v.as_str().len(),
            Self::Status(_) => 32 + 7 + 3,
        }
    }

    /// Returns the header name
    pub fn name(&self) -> Name<'_> {
        match *self {
            Self::Field { ref name, .. } => Name::Field(name),
            Self::Authority(..) => Name::Authority,
            Self::Method(..) => Name::Method,
            Self::Scheme(..) => Name::Scheme,
            Self::Path(..) => Name::Path,
            Self::Protocol(..) => Name::Protocol,
            Self::Status(..) => Name::Status,
        }
    }

    pub fn value_slice(&self) -> &[u8] {
        match *self {
            Self::Field { ref value, .. } => value.as_ref(),
            Self::Authority(ref v) | Self::Scheme(ref v) | Self::Path(ref v) => v.as_ref(),
            Self::Method(ref v) => v.as_ref().as_ref(),
            Self::Protocol(ref v) => v.as_ref(),
            Self::Status(ref v) => v.as_str().as_ref(),
        }
    }

    pub fn value_eq(&self, other: &Self) -> bool {
        match *self {
            Self::Field { ref value, .. } => {
                let a = value;
                match *other {
                    Self::Field { ref value, .. } => a == value,
                    _ => false,
                }
            }
            Self::Authority(ref a) => match *other {
                Self::Authority(ref b) => a == b,
                _ => false,
            },
            Self::Method(ref a) => match *other {
                Self::Method(ref b) => a == b,
                _ => false,
            },
            Self::Scheme(ref a) => match *other {
                Self::Scheme(ref b) => a == b,
                _ => false,
            },
            Self::Path(ref a) => match *other {
                Self::Path(ref b) => a == b,
                _ => false,
            },
            Self::Protocol(ref a) => match *other {
                Self::Protocol(ref b) => a == b,
                _ => false,
            },
            Self::Status(ref a) => match *other {
                Self::Status(ref b) => a == b,
                _ => false,
            },
        }
    }

    pub fn is_sensitive(&self) -> bool {
        match *self {
            Self::Field { ref value, .. } => value.is_sensitive(),
            // TODO: Technically these other header values can be sensitive too.
            _ => false,
        }
    }

    pub fn skip_value_index(&self) -> bool {
        use crate::header;

        match *self {
            Self::Field { ref name, .. } => matches!(
                *name,
                header::AGE
                    | header::AUTHORIZATION
                    | header::CONTENT_LENGTH
                    | header::ETAG
                    | header::IF_MODIFIED_SINCE
                    | header::IF_NONE_MATCH
                    | header::LOCATION
                    | header::COOKIE
                    | header::SET_COOKIE
            ),
            Self::Path(..) => true,
            _ => false,
        }
    }
}

// Mostly for tests
impl From<Header> for Header<Option<HeaderName>> {
    fn from(src: Header) -> Self {
        match src {
            Header::Field { name, value } => Self::Field {
                name: Some(name),
                value,
            },
            Header::Authority(v) => Self::Authority(v),
            Header::Method(v) => Self::Method(v),
            Header::Scheme(v) => Self::Scheme(v),
            Header::Path(v) => Self::Path(v),
            Header::Protocol(v) => Self::Protocol(v),
            Header::Status(v) => Self::Status(v),
        }
    }
}

impl Name<'_> {
    pub fn into_entry(self, value: Bytes) -> Result<Header, DecoderError> {
        match self {
            Name::Field(name) => Ok(Header::Field {
                name: name.clone(),
                value: HeaderValue::from_bytes(&value)?,
            }),
            Name::Authority => Ok(Header::Authority(BytesStr::try_from(value)?)),
            Name::Method => Ok(Header::Method(Method::from_bytes(&value)?)),
            Name::Scheme => Ok(Header::Scheme(BytesStr::try_from(value)?)),
            Name::Path => Ok(Header::Path(BytesStr::try_from(value)?)),
            Name::Protocol => Ok(Header::Protocol(Protocol::try_from(value)?)),
            Name::Status => {
                match StatusCode::from_bytes(&value) {
                    Ok(status) => Ok(Header::Status(status)),
                    // TODO: better error handling
                    Err(_) => Err(DecoderError::InvalidStatusCode),
                }
            }
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match *self {
            Name::Field(ref name) => name.as_ref(),
            Name::Authority => b":authority",
            Name::Method => b":method",
            Name::Scheme => b":scheme",
            Name::Path => b":path",
            Name::Protocol => b":protocol",
            Name::Status => b":status",
        }
    }
}

// ===== impl BytesStr =====

impl BytesStr {
    pub(crate) const fn from_static(value: &'static str) -> Self {
        Self(Bytes::from_static(value.as_bytes()))
    }

    pub(crate) fn from(value: &str) -> Self {
        Self(Bytes::copy_from_slice(value.as_bytes()))
    }

    #[doc(hidden)]
    pub fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        std::str::from_utf8(bytes.as_ref())?;
        Ok(Self(bytes))
    }

    pub(crate) fn as_str(&self) -> &str {
        // Safety: check valid utf-8 in constructor
        unsafe { std::str::from_utf8_unchecked(self.0.as_ref()) }
    }
}

impl std::ops::Deref for BytesStr {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for BytesStr {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for BytesStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
