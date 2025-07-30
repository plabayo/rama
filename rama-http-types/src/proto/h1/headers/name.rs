use rama_core::bytes::Bytes;
use serde::{Deserialize, Serialize, de::Error};
use std::{fmt, str::FromStr};

use crate::{HeaderName, header::InvalidHeaderName};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Http1HeaderName {
    name: HeaderName,
    raw: Option<Bytes>,
}

impl From<HeaderName> for Http1HeaderName {
    #[inline]
    fn from(value: HeaderName) -> Self {
        value.into_http1_header_name()
    }
}

impl From<Http1HeaderName> for HeaderName {
    fn from(value: Http1HeaderName) -> Self {
        value.name
    }
}

impl FromStr for Http1HeaderName {
    type Err = InvalidHeaderName;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_copy_from_str(s)
    }
}

impl Serialize for Http1HeaderName {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Http1HeaderName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::try_copy_from_str(&s).map_err(D::Error::custom)
    }
}

impl fmt::Display for Http1HeaderName {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Http1HeaderName {
    #[inline]
    pub fn try_copy_from_slice(b: &[u8]) -> Result<Self, InvalidHeaderName> {
        let bytes = Bytes::copy_from_slice(b);
        bytes.try_into_http1_header_name()
    }

    #[inline]
    pub fn try_copy_from_str(s: &str) -> Result<Self, InvalidHeaderName> {
        let bytes = Bytes::copy_from_slice(s.as_bytes());
        bytes.try_into_http1_header_name()
    }

    pub fn as_bytes(&self) -> &[u8] {
        if let Some(ref raw) = self.raw {
            return raw.as_ref();
        }
        self.name.as_ref()
    }

    pub fn as_str(&self) -> &str {
        self.raw
            .as_deref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or_else(|| self.name.as_str())
    }

    pub fn header_name(&self) -> &HeaderName {
        &self.name
    }
}

pub trait TryIntoHttp1HeaderName: try_into::Sealed {}

impl<T: try_into::Sealed> TryIntoHttp1HeaderName for T {}

mod try_into {
    use super::*;

    pub trait Sealed {
        #[doc(hidden)]
        fn try_into_http1_header_name(self) -> Result<Http1HeaderName, InvalidHeaderName>;
    }

    impl<T: into::Sealed> Sealed for T {
        fn try_into_http1_header_name(self) -> Result<Http1HeaderName, InvalidHeaderName> {
            Ok(self.into_http1_header_name())
        }
    }

    impl Sealed for Bytes {
        fn try_into_http1_header_name(self) -> Result<Http1HeaderName, InvalidHeaderName> {
            let b: &[u8] = self.as_ref();
            let name = b.try_into()?;
            Ok(Http1HeaderName {
                name,
                raw: Some(self),
            })
        }
    }

    macro_rules! from_owned_into_bytes {
        ($($t:ty),+ $(,)?) => {
            $(
                impl Sealed for $t {
                    #[inline]
                    fn try_into_http1_header_name(self) -> Result<Http1HeaderName, InvalidHeaderName> {
                        let bytes = Bytes::from(self);
                        bytes.try_into_http1_header_name()
                    }
                }
            )+
        };
    }

    from_owned_into_bytes! {
        &'static [u8],
        &'static str,
        String,
        Vec<u8>,
    }
}

#[allow(unused)]
pub(crate) use try_into::Sealed as TryIntoSealed;

pub trait IntoHttp1HeaderName: into::Sealed {}

impl<T: into::Sealed> IntoHttp1HeaderName for T {}

mod into {
    use super::*;

    pub trait Sealed {
        #[doc(hidden)]
        fn into_http1_header_name(self) -> Http1HeaderName;
    }

    impl Sealed for Http1HeaderName {
        fn into_http1_header_name(self) -> Http1HeaderName {
            self
        }
    }

    impl Sealed for HeaderName {
        fn into_http1_header_name(self) -> Http1HeaderName {
            Http1HeaderName {
                name: self,
                raw: None,
            }
        }
    }
}

#[allow(unused)]
pub(crate) use into::Sealed as IntoSealed;
