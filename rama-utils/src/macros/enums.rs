#[doc(hidden)]
#[macro_export]
/// A macro which defines an enum type.
///
/// By default an enum keeps any unrecognized value in an `Unknown` variant,
/// and converting into it never fails. With `#[strict]` (after the `@U8`,
/// `@U16`, `@U64`, `@Bytes` or `@String` kind) the enum has no `Unknown`
/// variant: conversions become `TryFrom` (and a fallible `FromStr`) that fail
/// with [`UnknownEnumValue`](crate::macros::enums::UnknownEnumValue), and
/// deserializing an unrecognized value fails. Use it when an unknown value is
/// never meaningful. `#[display_unknown = f]` only applies to the default mode.
///
/// `@U8`, `@U16` and `@U64` enums order variants primarily by numeric protocol value.
/// Distinct variants sharing a value use a deterministic variant tie-break.
/// They also expose `variant_name`, the bare mnemonic that `Display` and
/// `Debug` decorate, for use as a stable label.
//
// Each kind has one body. The mode travels as two bracketed groups: the
// `Unknown` variant ident (plus an optional display hook) when unknown values
// are kept, and the error type when the enum is strict. Every item that only
// exists in one mode sits in a repetition over the metavariable of its group.
macro_rules! __enum_builder {
    (
        $(#[$m:meta])*
        @U8
        $($rest:tt)*
    ) => {
        $crate::macros::enums::enum_builder! { $(#[$m])* @number u8 $($rest)* }
    };
    (
        $(#[$m:meta])*
        @U16
        $($rest:tt)*
    ) => {
        $crate::macros::enums::enum_builder! { $(#[$m])* @number u16 $($rest)* }
    };
    (
        $(#[$m:meta])*
        @U64
        $($rest:tt)*
    ) => {
        $crate::macros::enums::enum_builder! { $(#[$m])* @number u64 $($rest)* }
    };
    (
        $(#[$m:meta])*
        @number $number:ident
        #[strict]
        $enum_vis:vis enum $enum_name:ident { $($body:tt)* }
    ) => {
        $crate::macros::enums::enum_builder! {
            $(#[$m])*
            @__number $number [] [$crate::macros::enums::UnknownEnumValue]
            $enum_vis enum $enum_name { $($body)* }
        }
    };
    (
        $(#[$m:meta])*
        @number $number:ident
        $(#[display_unknown = $display_unknown_fn:ident])?
        $enum_vis:vis enum $enum_name:ident { $($body:tt)* }
    ) => {
        $crate::macros::enums::enum_builder! {
            $(#[$m])*
            @__number $number [Unknown $(, $display_unknown_fn)?] []
            $enum_vis enum $enum_name { $($body)* }
        }
    };
    (
        $(#[$m:meta])*
        @Bytes
        #[strict]
        $enum_vis:vis enum $enum_name:ident { $($body:tt)* }
    ) => {
        $crate::macros::enums::enum_builder! {
            $(#[$m])*
            @__bytes [] [$crate::macros::enums::UnknownEnumValue]
            $enum_vis enum $enum_name { $($body)* }
        }
    };
    (
        $(#[$m:meta])*
        @Bytes
        $(#[display_unknown = $display_unknown_fn:ident])?
        $enum_vis:vis enum $enum_name:ident { $($body:tt)* }
    ) => {
        $crate::macros::enums::enum_builder! {
            $(#[$m])*
            @__bytes [Unknown $(, $display_unknown_fn)?] []
            $enum_vis enum $enum_name { $($body)* }
        }
    };
    (
        $(#[$m:meta])*
        @String
        #[strict]
        $enum_vis:vis enum $enum_name:ident { $($body:tt)* }
    ) => {
        $crate::macros::enums::enum_builder! {
            $(#[$m])*
            @__string [] [$crate::macros::enums::UnknownEnumValue]
            $enum_vis enum $enum_name { $($body)* }
        }
    };
    (
        $(#[$m:meta])*
        @String
        $enum_vis:vis enum $enum_name:ident { $($body:tt)* }
    ) => {
        $crate::macros::enums::enum_builder! {
            $(#[$m])*
            @__string [Unknown] []
            $enum_vis enum $enum_name { $($body)* }
        }
    };
    (
        $(#[$m:meta])*
        @__number $number:ident
        [$($unknown:ident $(, $display_unknown_fn:ident)?)?]
        [$($strict_err:path)?]
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var,
            )*
            $(
                /// Retains an unrecognized numeric value.
                $unknown($number),
            )?
        }

        impl ::core::cmp::PartialOrd for $enum_name {
            fn partial_cmp(&self, other: &Self) -> Option<::core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::core::cmp::Ord for $enum_name {
            /// Compare by numeric value, then distinguish colliding variants.
            fn cmp(&self, other: &Self) -> ::core::cmp::Ordering {
                match $number::from(*self).cmp(&$number::from(*other)) {
                    ::core::cmp::Ordering::Equal if self != other => {
                        $(
                            if let Self::$unknown(_) = self {
                                return ::core::cmp::Ordering::Greater;
                            }
                            if let Self::$unknown(_) = other {
                                return ::core::cmp::Ordering::Less;
                            }
                        )?
                        self.known_variant_name().cmp(&other.known_variant_name())
                    }
                    ordering => ordering,
                }
            }
        }

        impl $enum_name {
            /// Return this value's variant name, or its decimal number when the
            /// value is unknown.
            ///
            /// Known values borrow their `'static` mnemonic, and unknown
            /// values render their numeric value. Unlike `Display` and
            /// `Debug` the result is a bare, stable label, suitable for log
            /// fields, metrics, and telemetry.
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            #[must_use]
            $enum_vis fn variant_name(&self) -> $crate::macros::enums::__Cow<'static, str> {
                $(
                    if let Self::$unknown(value) = self {
                        return $crate::macros::enums::__Cow::Owned(
                            $crate::macros::enums::__ToString::to_string(value),
                        );
                    }
                )?
                $crate::macros::enums::__Cow::Borrowed(self.known_variant_name())
            }

            /// Return a known value's variant name, and `""` for an unknown
            /// value, which every caller handles before this.
            fn known_variant_name(&self) -> &'static str {
                match self {
                    $(Self::$enum_var => stringify!($enum_var),)*
                    $(Self::$unknown(_) => "",)?
                }
            }

            /// The variant `value` is known as, if any.
            fn from_known_value(value: $number) -> Option<Self> {
                match value {
                    $($enum_val => Some($enum_name::$enum_var),)*
                    _ => None,
                }
            }
        }

        $(
            impl From<$number> for $enum_name {
                fn from(x: $number) -> Self {
                    Self::from_known_value(x).unwrap_or(Self::$unknown(x))
                }
            }
        )?

        $(
            impl ::core::convert::TryFrom<$number> for $enum_name {
                type Error = $strict_err;

                fn try_from(x: $number) -> Result<Self, Self::Error> {
                    Self::from_known_value(x).ok_or(<$strict_err>::__new(stringify!($enum_name)))
                }
            }
        )?

        impl From<$enum_name> for $number {
            fn from(value: $enum_name) -> Self {
                match value {
                    $($enum_name::$enum_var => $enum_val,)*
                    $($enum_name::$unknown(x) => x,)?
                }
            }
        }

        impl ::core::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => write!(f, concat!(stringify!($enum_var), " ({:#06x})"), $number::from(*self)), )*
                    $(
                        $enum_name::$unknown(x) => {
                            $(
                              if let Some(result) = $display_unknown_fn(f, *x) {
                                  return result;
                              }
                            )?
                            write!(f, "Unknown ({x:#06x})")
                        }
                    )?
                }
            }
        }

        impl ::core::fmt::LowerHex for $enum_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::LowerHex::fmt(&$number::from(*self), f)
            }
        }

        impl ::core::fmt::UpperHex for $enum_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::UpperHex::fmt(&$number::from(*self), f)
            }
        }

        impl $crate::macros::enums::__SerdeSerialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::macros::enums::__SerdeSerializer,
            {
                $number::from(*self).serialize(serializer)
            }
        }

        impl<'de> $crate::macros::enums::__SerdeDeserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::macros::enums::__SerdeDeserializer<'de>,
            {
                let n = $number::deserialize(deserializer)?;
                <Self as ::core::convert::TryFrom<$number>>::try_from(n)
                    .map_err(<D::Error as $crate::macros::enums::__SerdeDeError>::custom)
            }
        }
    };
    (
        $(#[$m:meta])*
        @__bytes
        [$($unknown:ident $(, $display_unknown_fn:ident)?)?]
        [$($strict_err:path)?]
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var,
            )*
            $(
                /// Retains an unrecognized byte sequence.
                $unknown($crate::macros::enums::__Vec<u8>),
            )?
        }

        impl $enum_name {
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_bytes(&self) -> &[u8] {
                match self {
                    $($enum_name::$enum_var => $enum_val,)*
                    $($enum_name::$unknown(v) => &v[..],)?
                }
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn try_as_str(&self) -> Option<&str> {
                ::core::str::from_utf8(self.as_bytes()).ok()
            }

            /// The variant `bytes` are known as, if any.
            fn from_known_bytes(bytes: &[u8]) -> Option<Self> {
                match bytes {
                    $($enum_val => Some($enum_name::$enum_var),)*
                    _ => None,
                }
            }
        }

        $(
            impl<'a> From<&'a [u8]> for $enum_name {
                fn from(b: &'a [u8]) -> Self {
                    Self::from_known_bytes(b).unwrap_or_else(|| Self::$unknown(b.to_vec()))
                }
            }

            impl<'a, const N: usize> From<&'a [u8; N]> for $enum_name {
                fn from(b: &'a [u8; N]) -> Self {
                    Self::from(&b[..])
                }
            }

            impl<'a> From<&'a str> for $enum_name {
                fn from(s: &'a str) -> Self {
                    Self::from(s.as_bytes())
                }
            }

            impl ::core::str::FromStr for $enum_name {
                type Err = ::core::convert::Infallible;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    Ok(Self::from_known_bytes(s.as_bytes())
                        .unwrap_or_else(|| Self::$unknown(s.as_bytes().to_vec())))
                }
            }

            impl From<$crate::macros::enums::__String> for $enum_name {
                fn from(s: $crate::macros::enums::__String) -> Self {
                    s.into_bytes().into()
                }
            }

            impl From<$crate::macros::enums::__Vec<u8>> for $enum_name {
                fn from(b: $crate::macros::enums::__Vec<u8>) -> Self {
                    match Self::from_known_bytes(&b) {
                        Some(known) => known,
                        None => $enum_name::$unknown(b),
                    }
                }
            }
        )?

        $(
            impl<'a> ::core::convert::TryFrom<&'a [u8]> for $enum_name {
                type Error = $strict_err;

                fn try_from(b: &'a [u8]) -> Result<Self, Self::Error> {
                    Self::from_known_bytes(b).ok_or(<$strict_err>::__new(stringify!($enum_name)))
                }
            }

            impl<'a> ::core::convert::TryFrom<&'a str> for $enum_name {
                type Error = $strict_err;

                fn try_from(s: &'a str) -> Result<Self, Self::Error> {
                    Self::try_from(s.as_bytes())
                }
            }

            impl ::core::str::FromStr for $enum_name {
                type Err = $strict_err;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    Self::try_from(s.as_bytes())
                }
            }
        )?

        impl From<$enum_name> for $crate::macros::enums::__Vec<u8> {
            fn from(e: $enum_name) -> Self {
                match e {
                    $($enum_name::$enum_var => $enum_val.to_vec(),)*
                    $($enum_name::$unknown(v) => v,)?
                }
            }
        }

        impl From<&$enum_name> for $crate::macros::enums::__Vec<u8> {
            fn from(e: &$enum_name) -> Self {
                e.as_bytes().to_vec()
            }
        }

        impl ::core::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => match ::core::str::from_utf8($enum_val) {
                        Ok(x) => write!(f, "{x}"),
                        Err(_) => write!(f, concat!(stringify!($enum_var), " (0x{:x?})"), $enum_val),
                    }, )*
                    $(
                        $enum_name::$unknown(x) => {
                            $(
                              if let Some(result) = $display_unknown_fn(f, x.as_slice()) {
                                  return result;
                              }
                            )?

                            match ::core::str::from_utf8(x) {
                                Ok(x) => write!(f, "Unknown ({x})"),
                                Err(_) => {
                                    write!(f, "Unknown ({:#x})", $crate::fmt::hex(x))
                                },
                            }
                        },
                    )?
                }
            }
        }

        impl $crate::macros::enums::__SerdeSerialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::macros::enums::__SerdeSerializer,
            {
                match self {
                    $( $enum_name::$enum_var => {
                        $enum_val.serialize(serializer)
                    }, )*
                    $( $enum_name::$unknown(x) => {
                        x.serialize(serializer)
                    }, )?
                }
            }
        }

        impl<'de> $crate::macros::enums::__SerdeDeserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::macros::enums::__SerdeDeserializer<'de>,
            {
                let b = <$crate::macros::enums::__Cow<'de, [u8]>>::deserialize(deserializer)?;
                <Self as ::core::convert::TryFrom<&[u8]>>::try_from(b.as_ref())
                    .map_err(<D::Error as $crate::macros::enums::__SerdeDeError>::custom)
            }
        }
    };
    (
        $(#[$m:meta])*
        @__string
        [$($unknown:ident)?]
        [$($strict_err:path)?]
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var:ident => $enum_val:literal $(| $enum_val_alt:literal)* ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var,
            )*
            $(
                /// Retains an unrecognized value.
                $unknown(Box<str>),
            )?
        }

        impl $enum_name {
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_str(&self) -> &str {
                match self {
                    $($enum_name::$enum_var => $enum_val,)*
                    $($enum_name::$unknown(v) => v,)?
                }
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_static_str(&self) -> $crate::macros::enums::__Cow<'static, str> {
                match self {
                    $($enum_name::$enum_var => $crate::macros::enums::__Cow::Borrowed($enum_val),)*
                    $(
                        $enum_name::$unknown(v) => $crate::macros::enums::__Cow::Owned(
                            $crate::macros::enums::__ToString::to_string(v),
                        ),
                    )?
                }
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_smol_str(&self) -> $crate::macros::enums::__SmolStr {
                match self {
                    $($enum_name::$enum_var => $crate::macros::enums::__SmolStr::new_static($enum_val),)*
                    $($enum_name::$unknown(v) => $crate::macros::enums::__SmolStr::new(v),)?
                }
            }

            /// Parse a known value, ignoring ASCII case, or return `None`.
            pub fn strict_parse(s: &str) -> Option<Self> {
                $crate::macros::match_ignore_ascii_case_str!(match(s) {
                    $($enum_val $(| $enum_val_alt)* => Some($enum_name::$enum_var)),*
                    , _ => None,
                })
            }
        }

        $(
            impl<'a> From<&'a str> for $enum_name {
                fn from(s: &'a str) -> Self {
                    Self::strict_parse(s).unwrap_or_else(|| Self::$unknown(s.into()))
                }
            }

            impl ::core::str::FromStr for $enum_name {
                type Err = ::core::convert::Infallible;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    Ok(Self::strict_parse(s).unwrap_or_else(|| Self::$unknown(s.into())))
                }
            }

            impl From<$crate::macros::enums::__String> for $enum_name {
                fn from(s: $crate::macros::enums::__String) -> Self {
                    Self::strict_parse(&s).unwrap_or_else(|| Self::$unknown(s.into_boxed_str()))
                }
            }
        )?

        $(
            impl<'a> ::core::convert::TryFrom<&'a str> for $enum_name {
                type Error = $strict_err;

                fn try_from(s: &'a str) -> Result<Self, Self::Error> {
                    Self::strict_parse(s).ok_or(<$strict_err>::__new(stringify!($enum_name)))
                }
            }

            impl ::core::str::FromStr for $enum_name {
                type Err = $strict_err;

                fn from_str(s: &str) -> Result<Self, Self::Err> {
                    Self::try_from(s)
                }
            }
        )?

        impl ::core::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl $crate::macros::enums::__SerdeSerialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::macros::enums::__SerdeSerializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> $crate::macros::enums::__SerdeDeserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::macros::enums::__SerdeDeserializer<'de>,
            {
                let s = <$crate::macros::enums::__Cow<'de, str>>::deserialize(deserializer)?;
                <Self as ::core::convert::TryFrom<&str>>::try_from(&s)
                    .map_err(<D::Error as $crate::macros::enums::__SerdeDeError>::custom)
            }
        }
    };
}

#[doc(inline)]
pub use crate::__enum_builder as enum_builder;

/// The error of converting a value no variant of a strict (`#[strict]`)
/// [`enum_builder`] enum matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnknownEnumValue {
    enum_name: &'static str,
}

impl UnknownEnumValue {
    #[doc(hidden)]
    #[must_use]
    pub const fn __new(enum_name: &'static str) -> Self {
        Self { enum_name }
    }

    /// The name of the enum that failed to parse.
    #[must_use]
    pub const fn enum_name(&self) -> &'static str {
        self.enum_name
    }
}

impl core::fmt::Display for UnknownEnumValue {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "unknown {} value", self.enum_name)
    }
}

impl core::error::Error for UnknownEnumValue {}

#[doc(hidden)]
pub use serde::{
    Deserialize as __SerdeDeserialize, Deserializer as __SerdeDeserializer,
    Serialize as __SerdeSerialize, Serializer as __SerdeSerializer, de::Error as __SerdeDeError,
};

#[doc(hidden)]
pub use ::smol_str::SmolStr as __SmolStr;

#[doc(hidden)]
pub use crate::std::string::ToString as __ToString;

#[doc(hidden)]
pub use crate::std::{Cow as __Cow, String as __String, Vec as __Vec};

#[cfg(test)]
// NOTE(expect) the generated helpers carry `#[allow(dead_code)]` for callers
// that never use them. Expanding the macro inside its own crate is the one
// place where that is not an external macro, so the lint sees it here.
#[expect(clippy::allow_attributes)]
mod tests {
    use std::assert_matches;
    use std::borrow::Cow;

    use super::enum_builder;

    enum_builder! {
        @U8
        enum TestU8 {
            Maximum => 255,
            One => 1,
        }
    }

    enum_builder! {
        @U16
        enum TestU16 {
            Maximum => 65535,
            One => 1,
        }
    }

    enum_builder! {
        @U64
        enum TestU64 {
            Above32Bits => 0x17f7586d2cb571,
            One => 1,
        }
    }

    #[test]
    fn wide_numeric_enum_round_trips_known_and_unknown_wire_values() {
        for value in [1, 0x17f7586d2cb571, 0, (1u64 << 62) - 1, u64::MAX] {
            let decoded: TestU64 = serde_json::from_str(&value.to_string()).unwrap();
            assert_eq!(u64::from(decoded), value);
            assert_eq!(serde_json::to_string(&decoded).unwrap(), value.to_string());
            assert_eq!(format!("{decoded:x}"), format!("{value:x}"));
        }
        assert_matches!(TestU64::from(0x17f7586d2cb571), TestU64::Above32Bits);
        assert_matches!(TestU64::from(u64::MAX), TestU64::Unknown(u64::MAX));
        assert_matches!(TestU64::Above32Bits.variant_name(), Cow::Borrowed(_));
        assert!(TestU64::One < TestU64::Above32Bits);
        assert!(TestU64::Above32Bits < TestU64::Unknown(u64::MAX));
    }

    #[test]
    fn numeric_enum_order_follows_values_and_remains_eq_consistent() {
        assert!(TestU8::One < TestU8::Unknown(2));
        assert!(TestU8::Unknown(2) < TestU8::Maximum);
        assert_ne!(TestU8::One, TestU8::Unknown(1));
        assert_ne!(
            TestU8::One.cmp(&TestU8::Unknown(1)),
            core::cmp::Ordering::Equal
        );

        assert!(TestU16::One < TestU16::Unknown(2));
        assert!(TestU16::Unknown(2) < TestU16::Maximum);
        assert_ne!(TestU16::One, TestU16::Unknown(1));
        assert_ne!(
            TestU16::One.cmp(&TestU16::Unknown(1)),
            core::cmp::Ordering::Equal
        );
    }

    #[test]
    fn numeric_enum_variant_names_borrow_known_mnemonics_and_number_the_rest() {
        assert_eq!(TestU8::One.variant_name(), Cow::Borrowed("One"));
        assert_eq!(TestU8::Maximum.variant_name(), Cow::Borrowed("Maximum"));
        assert_matches!(TestU8::One.variant_name(), Cow::Borrowed(_));

        assert_eq!(TestU8::Unknown(0).variant_name(), "0");
        assert_eq!(TestU8::Unknown(u8::MAX).variant_name(), "255");
        assert_matches!(TestU8::Unknown(1).variant_name(), Cow::Owned(_));
        // The number, not the variant sharing its value.
        assert_ne!(
            TestU8::Unknown(1).variant_name(),
            TestU8::One.variant_name()
        );

        assert_eq!(TestU16::One.variant_name(), Cow::Borrowed("One"));
        assert_eq!(TestU16::Maximum.variant_name(), Cow::Borrowed("Maximum"));
        assert_eq!(TestU16::Unknown(0).variant_name(), "0");
        assert_eq!(TestU16::Unknown(u16::MAX).variant_name(), "65535");
        assert_matches!(TestU16::Unknown(1).variant_name(), Cow::Owned(_));
    }
}
