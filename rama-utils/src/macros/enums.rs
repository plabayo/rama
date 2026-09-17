#[doc(hidden)]
#[macro_export]
/// A macro which defines an enum type.
///
/// `@U8` and `@U16` enums order variants primarily by numeric protocol value.
/// Distinct variants sharing a value use a deterministic variant tie-break.
/// They also expose `variant_name`, the bare mnemonic that `Display` and
/// `Debug` decorate, for use as a stable label.
macro_rules! __enum_builder {
    (
        $(#[$m:meta])*
        @U8
        $(#[display_unknown = $display_unknown_fn:ident])?
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var:ident => $enum_val:expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var,
            )*
            /// Retains an unrecognized numeric value.
            Unknown(u8)
        }

        impl ::std::cmp::PartialOrd for $enum_name {
            fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::std::cmp::Ord for $enum_name {
            /// Compare by numeric value, then distinguish colliding variants.
            fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
                match u8::from(*self).cmp(&u8::from(*other)) {
                    ::std::cmp::Ordering::Equal if self != other => match (self, other) {
                        (Self::Unknown(_), _) => ::std::cmp::Ordering::Greater,
                        (_, Self::Unknown(_)) => ::std::cmp::Ordering::Less,
                        _ => self.known_variant_name().cmp(&other.known_variant_name()),
                    },
                    ordering => ordering,
                }
            }
        }

        impl $enum_name {
            /// Return this value's variant name, or its decimal number when the
            /// value is unknown.
            ///
            /// Known values borrow their `'static` mnemonic, and
            /// [`Self::Unknown`] values render their numeric value. Unlike
            /// `Display` and `Debug` the result is a bare, stable label,
            /// suitable for log fields, metrics, and telemetry.
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            #[must_use]
            $enum_vis fn variant_name(&self) -> ::std::borrow::Cow<'static, str> {
                match self {
                    Self::Unknown(value) => ::std::borrow::Cow::Owned(value.to_string()),
                    known => ::std::borrow::Cow::Borrowed(known.known_variant_name()),
                }
            }

            /// Return a known value's variant name, and `""` for
            /// [`Self::Unknown`], which every caller handles before this.
            fn known_variant_name(&self) -> &'static str {
                match self {
                    $(Self::$enum_var => stringify!($enum_var),)*
                    Self::Unknown(_) => "",
                }
            }
        }

        impl From<u8> for $enum_name {
            fn from(x: u8) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for u8 {
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => write!(f, concat!(stringify!($enum_var), " ({:#06x})"), $enum_val)),*
                    ,$enum_name::Unknown(x) => {
                        $(
                          if let Some(result) = $display_unknown_fn(f, *x) {
                              return result;
                          }
                        )?
                        write!(f, "Unknown ({x:#06x})")
                    },
                }
            }
        }

        impl ::std::fmt::LowerHex for $enum_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::LowerHex::fmt(&u8::from(*self), f)
            }
        }

        impl ::std::fmt::UpperHex for $enum_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::UpperHex::fmt(&u8::from(*self), f)
            }
        }

        impl $crate::macros::enums::__SerdeSerialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::macros::enums::__SerdeSerializer,
            {
                u8::from(*self).serialize(serializer)
            }
        }

        impl<'de> $crate::macros::enums::__SerdeDeserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::macros::enums::__SerdeDeserializer<'de>,
            {
                let n = u8::deserialize(deserializer)?;
                Ok(n.into())
            }
        }
    };
    (
        $(#[$m:meta])*
        @U16
        $(#[display_unknown = $display_unknown_fn:ident])?
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
            /// Retains an unrecognized numeric value.
            Unknown(u16)
        }

        impl ::std::cmp::PartialOrd for $enum_name {
            fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl ::std::cmp::Ord for $enum_name {
            /// Compare by numeric value, then distinguish colliding variants.
            fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
                match u16::from(*self).cmp(&u16::from(*other)) {
                    ::std::cmp::Ordering::Equal if self != other => match (self, other) {
                        (Self::Unknown(_), _) => ::std::cmp::Ordering::Greater,
                        (_, Self::Unknown(_)) => ::std::cmp::Ordering::Less,
                        _ => self.known_variant_name().cmp(&other.known_variant_name()),
                    },
                    ordering => ordering,
                }
            }
        }

        impl $enum_name {
            /// Return this value's variant name, or its decimal number when the
            /// value is unknown.
            ///
            /// Known values borrow their `'static` mnemonic, and
            /// [`Self::Unknown`] values render their numeric value. Unlike
            /// `Display` and `Debug` the result is a bare, stable label,
            /// suitable for log fields, metrics, and telemetry.
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            #[must_use]
            $enum_vis fn variant_name(&self) -> ::std::borrow::Cow<'static, str> {
                match self {
                    Self::Unknown(value) => ::std::borrow::Cow::Owned(value.to_string()),
                    known => ::std::borrow::Cow::Borrowed(known.known_variant_name()),
                }
            }

            /// Return a known value's variant name, and `""` for
            /// [`Self::Unknown`], which every caller handles before this.
            fn known_variant_name(&self) -> &'static str {
                match self {
                    $(Self::$enum_var => stringify!($enum_var),)*
                    Self::Unknown(_) => "",
                }
            }
        }

        impl From<u16> for $enum_name {
            fn from(x: u16) -> Self {
                match x {
                    $($enum_val => $enum_name::$enum_var),*
                    , x => $enum_name::Unknown(x),
                }
            }
        }

        impl From<$enum_name> for u16 {
            fn from(value: $enum_name) -> Self {
                match value {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(x) => x
                }
            }
        }

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => write!(f, concat!(stringify!($enum_var), " ({:#06x})"), $enum_val)),*
                    ,$enum_name::Unknown(x) => {
                        $(
                          if let Some(result) = $display_unknown_fn(f, *x) {
                              return result;
                          }
                        )?
                        write!(f, "Unknown ({x:#06x})")
                    }
                }
            }
        }

        impl ::std::fmt::LowerHex for $enum_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::LowerHex::fmt(&u16::from(*self), f)
            }
        }

        impl ::std::fmt::UpperHex for $enum_name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::UpperHex::fmt(&u16::from(*self), f)
            }
        }

        impl $crate::macros::enums::__SerdeSerialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::macros::enums::__SerdeSerializer,
            {
                u16::from(*self).serialize(serializer)
            }
        }

        impl<'de> $crate::macros::enums::__SerdeDeserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::macros::enums::__SerdeDeserializer<'de>,
            {
                let n = u16::deserialize(deserializer)?;
                Ok(n.into())
            }
        }
    };
    (
        $(#[$m:meta])*
        @Bytes
        $(#[display_unknown = $display_unknown_fn:ident])?
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
            /// Retains an unrecognized byte sequence.
            Unknown($crate::macros::enums::__Vec<u8>)
        }

        impl $enum_name {
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_bytes(&self) -> &[u8] {
                match self {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(v) => &v[..],
                }
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn try_as_str(&self) -> Option<&str> {
                ::core::str::from_utf8(match self {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(b) => b,
                }).ok()
            }
        }

        impl<'a> From<&'a [u8]> for $enum_name {
            fn from(b: &'a [u8]) -> Self {
                match b {
                    $($enum_val => $enum_name::$enum_var),*
                    , b => $enum_name::Unknown(b.to_vec()),
                }
            }
        }

        impl<'a, const N: usize> From<&'a [u8; N]> for $enum_name {
            fn from(b: &'a [u8; N]) -> Self {
                match &b[..] {
                    $($enum_val => $enum_name::$enum_var),*
                    , b => $enum_name::Unknown(b.to_vec()),
                }
            }
        }

        impl<'a> From<&'a str> for $enum_name {
            fn from(s: &'a str) -> Self {
                match s.as_bytes() {
                    $($enum_val => $enum_name::$enum_var),*
                    , b => $enum_name::Unknown(b.to_vec()),
                }
            }
        }

        impl ::core::str::FromStr for $enum_name {
            type Err = ::core::convert::Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(s.into())
            }
        }

        impl From<$crate::macros::enums::__String> for $enum_name {
            fn from(s: $crate::macros::enums::__String) -> Self {
                let b = s.into_bytes();
                b.into()
            }
        }

        impl From<$crate::macros::enums::__Vec<u8>> for $enum_name {
            fn from(b: $crate::macros::enums::__Vec<u8>) -> Self {
                match &b[..] {
                    $($enum_val => $enum_name::$enum_var),*
                    , _ => $enum_name::Unknown(b),
                }
            }
        }

        impl From<$enum_name> for $crate::macros::enums::__Vec<u8> {
            fn from(e: $enum_name) -> Self {
                match e {
                    $($enum_name::$enum_var => $enum_val.to_vec()),*
                    , $enum_name::Unknown(v) => v,
                }
            }
        }

        impl From<&$enum_name> for $crate::macros::enums::__Vec<u8> {
            fn from(e: &$enum_name) -> Self {
                match e {
                    $($enum_name::$enum_var => $enum_val.to_vec()),*
                    , $enum_name::Unknown(v) => v.clone(),
                }
            }
        }

        impl ::core::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => match ::core::str::from_utf8($enum_val) {
                        Ok(x) => write!(f, "{x}"),
                        Err(_) => write!(f, concat!(stringify!($enum_var), " (0x{:x?})"), $enum_val),
                    }),*
                    ,$enum_name::Unknown(x) => {
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
                    }),*
                    ,$enum_name::Unknown(x) => {
                        x.serialize(serializer)
                    }
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
                Ok(b.as_ref().into())
            }
        }
    };
    (
        $(#[$m:meta])*
        @String
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var:ident => $enum_val:literal $(| $enum_val_alt:literal)* ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,Unknown(Box<str>)
        }

        impl $enum_name {
            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_str(&self) -> &str {
                match self {
                    $( $enum_name::$enum_var => $enum_val),*
                    ,$enum_name::Unknown(v) => &v,
                }
            }

            #[allow(dead_code)]
            $enum_vis fn as_static_str(&self) -> ::std::borrow::Cow<'static, str> {
                match self {
                    $( $enum_name::$enum_var => ::std::borrow::Cow::Borrowed($enum_val)),*
                    ,$enum_name::Unknown(v) => ::std::borrow::Cow::Owned(v.to_string()),
                }
            }

            // NOTE(allow) generated irrespective if there are callers
            #[allow(dead_code)]
            $enum_vis fn as_smol_str(&self) -> $crate::macros::enums::__SmolStr {
                match self {
                    $( $enum_name::$enum_var => $crate::macros::enums::__SmolStr::new_static($enum_val)),*
                    ,$enum_name::Unknown(v) => $crate::macros::enums::__SmolStr::new(&v),
                }
            }
        }

        impl<'a> From<&'a str> for $enum_name {
            fn from(s: &'a str) -> Self {
                $crate::macros::match_ignore_ascii_case_str!(match(s) {
                    $($enum_val $(| $enum_val_alt)* => $enum_name::$enum_var),*
                    , _ => $enum_name::Unknown(s.into()),
                })
            }
        }

        impl ::std::str::FromStr for $enum_name {
            type Err = ::std::convert::Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(s.into())
            }
        }

        impl $enum_name {
            /// Same as `FromStr` or `From<&str>` but returning
            /// `None` for unknown values
            pub fn strict_parse(s: &str) -> Option<Self> {
                $crate::macros::match_ignore_ascii_case_str!(match(s) {
                    $($enum_val $(| $enum_val_alt)* => Some($enum_name::$enum_var)),*
                    , _ => None,
                })
            }
        }

        impl From<String> for $enum_name {
            fn from(s: String) -> Self {
                match s.as_str() {
                    $($enum_val $(| $enum_val_alt)* => $enum_name::$enum_var),*
                    , _ => $enum_name::Unknown(s.into_boxed_str()),
                }
            }
        }

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => write!(f, "{}", $enum_val)),*
                    ,$enum_name::Unknown(x) => write!(f, "{x}"),
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
                    }),*
                    ,$enum_name::Unknown(x) => {
                        x.serialize(serializer)
                    }
                }
            }
        }

        impl<'de> $crate::macros::enums::__SerdeDeserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::macros::enums::__SerdeDeserializer<'de>,
            {
                let s = <::std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Ok(s.as_ref().into())
            }
        }
    };
}

#[doc(inline)]
pub use crate::__enum_builder as enum_builder;

#[doc(hidden)]
pub use serde::{
    Deserialize as __SerdeDeserialize, Deserializer as __SerdeDeserializer,
    Serialize as __SerdeSerialize, Serializer as __SerdeSerializer,
};

#[doc(hidden)]
pub use ::smol_str::SmolStr as __SmolStr;

#[doc(hidden)]
pub use crate::std::{Cow as __Cow, String as __String, Vec as __Vec};

#[cfg(test)]
// NOTE(expect) the generated helpers carry `#[allow(dead_code)]` for callers
// that never use them. Expanding the macro inside its own crate is the one
// place where that is not an external macro, so the lint sees it here.
#[expect(clippy::allow_attributes)]
mod tests {
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
        assert!(matches!(TestU8::One.variant_name(), Cow::Borrowed(_)));

        assert_eq!(TestU8::Unknown(0).variant_name(), "0");
        assert_eq!(TestU8::Unknown(u8::MAX).variant_name(), "255");
        assert!(matches!(TestU8::Unknown(1).variant_name(), Cow::Owned(_)));
        // The number, not the variant sharing its value.
        assert_ne!(
            TestU8::Unknown(1).variant_name(),
            TestU8::One.variant_name()
        );

        assert_eq!(TestU16::One.variant_name(), Cow::Borrowed("One"));
        assert_eq!(TestU16::Maximum.variant_name(), Cow::Borrowed("Maximum"));
        assert_eq!(TestU16::Unknown(0).variant_name(), "0");
        assert_eq!(TestU16::Unknown(u16::MAX).variant_name(), "65535");
        assert!(matches!(TestU16::Unknown(1).variant_name(), Cow::Owned(_)));
    }
}
