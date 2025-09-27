use rama_http_types::HeaderValue;

use crate::Error;

//pub use self::charset::Charset;
//pub use self::encoding::Encoding;
pub(crate) use self::entity::{EntityTag, EntityTagRange};
pub(crate) use self::flat_csv::{FlatCsv, SemiColon};
pub(crate) use self::fmt::fmt;
pub use self::http_date::HttpDate;
pub(crate) use self::iter::IterExt;
//pub use language_tags::LanguageTag;
//pub use self::quality_value::{Quality, QualityValue};
pub use self::seconds::Seconds;

//mod charset;
pub mod csv;
//mod encoding;
mod entity;
mod flat_csv;
mod fmt;
mod http_date;
mod iter;
//mod quality_value;
mod seconds;
mod value_string;

pub use value_string::HeaderValueString;

macro_rules! derive_header {
    ($type:ident(_), name: $name:ident) => {
        impl crate::TypedHeader for $type {
            fn name() -> &'static ::rama_http_types::header::HeaderName {
                &::rama_http_types::header::$name
            }
        }

        impl crate::HeaderDecode for $type {
            fn decode<'i, I>(values: &mut I) -> Result<Self, crate::Error>
            where
                I: Iterator<Item = &'i ::rama_http_types::header::HeaderValue>,
            {
                crate::util::TryFromValues::try_from_values(values).map($type)
            }
        }

        impl crate::HeaderEncode for $type {
            fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
                values.extend(::std::iter::once((&self.0).into()));
            }
        }
    };
}

/// A helper trait for use when deriving `Header`.
pub(crate) trait TryFromValues: Sized {
    /// Try to convert from the values into an instance of `Self`.
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>;
}

impl TryFromValues for HeaderValue {
    fn try_from_values<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        I: Iterator<Item = &'i Self>,
    {
        values.next().cloned().ok_or_else(Error::invalid)
    }
}
