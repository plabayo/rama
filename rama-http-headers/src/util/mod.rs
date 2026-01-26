use rama_http_types::HeaderValue;

use crate::Error;

//pub use self::charset::Charset;
//pub use self::encoding::Encoding;
pub(crate) use self::entity::{EntityTag, EntityTagRange};
pub(crate) use self::flat_csv::{
    FlatCsvSeparator, try_decode_flat_csv_header_values_as_non_empty_smallvec,
    try_decode_flat_csv_header_values_as_non_empty_vec,
    try_encode_non_empty_smallvec_as_flat_csv_header_value,
    try_encode_non_empty_vec_as_flat_csv_header_value,
    try_encode_non_empty_vec_of_bytes_as_flat_csv_header_value,
};
pub(crate) use self::fmt::fmt;
pub use self::http_date::HttpDate;
pub(crate) use self::iter::IterExt;
//pub use language_tags::LanguageTag;
//pub use self::quality_value::{Quality, QualityValue};
pub use self::flat_csv::ValuesOrAny;
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

macro_rules! derive_non_empty_flat_csv_header {
    (
        #[header(name = $name:ident, sep = $sep:ident)]
        $(#[$m:meta])*
        pub struct $type:ident(pub NonEmptyVec<$t:ty>);
    ) => {
        $(#[$m])*
        pub struct $type(pub ::rama_utils::collections::NonEmptyVec<$t>);

        impl $type {
            pub fn new(value: $t) -> Self {
                Self(::rama_utils::collections::NonEmptyVec::new(value))
            }
        }

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
                crate::util::try_decode_flat_csv_header_values_as_non_empty_vec(
                   values,
                   crate::util::FlatCsvSeparator::$sep,
                ).map($type).map_err(|err| {
                    rama_core::telemetry::tracing::debug!(
                      "failed to decode header value(s) as flat csv typed header: {err}"
                    );
                    crate::Error::invalid()
                })
            }
        }

        impl crate::HeaderEncode for $type {
            fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
                match crate::util::try_encode_non_empty_vec_as_flat_csv_header_value(
                   &self.0,
                   crate::util::FlatCsvSeparator::$sep,
                ) {
                    Ok(value) => values.extend(::std::iter::once(value)),
                    Err(err) => {
                        rama_core::telemetry::tracing::debug!(
                          "failed to encode header value(s) as flat csv header: {err}"
                        );
                    }
                }
            }
        }
    };

    (
        #[header(name = $name:ident, sep = $sep:ident)]
        $(#[$m:meta])*
        pub struct $type:ident(pub NonEmptySmallVec<$N:literal, $t:ty>);
    ) => {
        $(#[$m])*
        pub struct $type(pub ::rama_utils::collections::NonEmptySmallVec<$N, $t>);

        impl $type {
            pub fn new(value: $t) -> Self {
                Self(::rama_utils::collections::NonEmptySmallVec::new(value))
            }
        }

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
                crate::util::try_decode_flat_csv_header_values_as_non_empty_smallvec(
                   values,
                   crate::util::FlatCsvSeparator::$sep,
                ).map($type).map_err(|err| {
                    rama_core::telemetry::tracing::debug!(
                      "failed to decode header value(s) as flat csv typed header: {err}"
                    );
                    crate::Error::invalid()
                })
            }
        }

        impl crate::HeaderEncode for $type {
            fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
                match crate::util::try_encode_non_empty_smallvec_as_flat_csv_header_value(
                   &self.0,
                   crate::util::FlatCsvSeparator::$sep,
                ) {
                    Ok(value) => values.extend(::std::iter::once(value)),
                    Err(err) => {
                        rama_core::telemetry::tracing::debug!(
                          "failed to encode header value(s) as flat csv header: {err}"
                        );
                    }
                }
            }
        }
    };
}

macro_rules! derive_values_or_any_header {
    (
        #[header(name = $name:ident, sep = $sep:ident)]
        $(#[$m:meta])*
        pub struct $type:ident(pub ValuesOrAny<$t:ty>);
    ) => {
        $(#[$m])*
        pub struct $type(pub $crate::util::ValuesOrAny<$t>);

        impl $type {
            #[must_use]
            pub fn new(value: $t) -> Self {
                Self($crate::util::ValuesOrAny::Values(
                    ::rama_utils::collections::NonEmptyVec::new(value),
                ))
            }

            #[must_use]
            pub fn new_values(values: ::rama_utils::collections::NonEmptyVec<$t>) -> Self {
                Self($crate::util::ValuesOrAny::Values(values))
            }

            #[must_use]
            pub fn new_any() -> Self {
                Self($crate::util::ValuesOrAny::Any)
            }

            #[must_use]
            pub fn is_any(&self) -> bool {
                matches!(&self.0, $crate::util::ValuesOrAny::Any)
            }

            #[must_use]
            pub fn as_values(&self) -> Option<&::rama_utils::collections::NonEmptyVec<$t>> {
                match &self.0 {
                    $crate::util::ValuesOrAny::Any => None,
                    $crate::util::ValuesOrAny::Values(values) => Some(values),
                }
            }

            #[must_use]
            pub fn into_values(self) -> Option<::rama_utils::collections::NonEmptyVec<$t>> {
                match self.0 {
                    $crate::util::ValuesOrAny::Any => None,
                    $crate::util::ValuesOrAny::Values(values) => Some(values),
                }
            }
        }

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
                let Some(first_value) = values.next() else {
                    rama_core::telemetry::tracing::debug!(
                      "failed to decode header value(s) as values typed header: no headers provided"
                    );
                    return Err(crate::Error::invalid());
                };

                let second_value = values.next();

                if first_value.as_bytes().trim_ascii() == b"*" && second_value.is_none() {
                    return Ok(Self::new_any());
                }

                let mut values = std::iter::once(first_value).chain(second_value).chain(values);

                crate::util::try_decode_flat_csv_header_values_as_non_empty_vec(
                   &mut values,
                   crate::util::FlatCsvSeparator::$sep,
                ).map(Self::new_values).map_err(|err| {
                    rama_core::telemetry::tracing::debug!(
                      "failed to decode header value(s) as a multi-value typed header: {err}"
                    );
                    crate::Error::invalid()
                })
            }
        }

        impl crate::HeaderEncode for $type {
            fn encode<E: Extend<::rama_http_types::HeaderValue>>(&self, values: &mut E) {
                let $crate::util::ValuesOrAny::Values(ref these_values) = self.0 else {
                    values.extend(::std::iter::once(
                        ::rama_http_types::header::HeaderValue::from_static("*"),
                    ));
                    return;
                };

                match crate::util::try_encode_non_empty_vec_as_flat_csv_header_value(
                these_values,
                crate::util::FlatCsvSeparator::$sep,
                ) {
                    Ok(value) => values.extend(::std::iter::once(value)),
                    Err(err) => {
                        rama_core::telemetry::tracing::debug!(
                            "failed to encode header value(s) as multi-value typed header: {err}"
                        );
                    }
                }
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
