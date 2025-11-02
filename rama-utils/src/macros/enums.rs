#[doc(hidden)]
#[macro_export]
/// A macro which defines an enum type.
macro_rules! __enum_builder {
    (
        $(#[$m:meta])*
        @U8
        $(#[display_unknown = $display_unknown_fn:ident])?
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var:ident => $enum_val:expr ),* $(,)? }
    ) => {
        $(#[$m])*
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,Unknown(u8)
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
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,Unknown(u16)
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
                $enum_var
            ),*
            ,Unknown(Vec<u8>)
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
                ::std::str::from_utf8(match self {
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

        impl ::std::str::FromStr for $enum_name {
            type Err = ::std::convert::Infallible;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(s.into())
            }
        }

        impl From<String> for $enum_name {
            fn from(s: String) -> Self {
                let b = s.into_bytes();
                b.into()
            }
        }

        impl From<Vec<u8>> for $enum_name {
            fn from(b: Vec<u8>) -> Self {
                match &b[..] {
                    $($enum_val => $enum_name::$enum_var),*
                    , _ => $enum_name::Unknown(b),
                }
            }
        }

        impl From<$enum_name> for Vec<u8> {
            fn from(e: $enum_name) -> Self {
                match e {
                    $($enum_name::$enum_var => $enum_val.to_vec()),*
                    , $enum_name::Unknown(v) => v,
                }
            }
        }

        impl From<&$enum_name> for Vec<u8> {
            fn from(e: &$enum_name) -> Self {
                match e {
                    $($enum_name::$enum_var => $enum_val.to_vec()),*
                    , $enum_name::Unknown(v) => v.clone(),
                }
            }
        }

        impl ::std::fmt::Display for $enum_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( $enum_name::$enum_var => match ::std::str::from_utf8($enum_val) {
                        Ok(x) => write!(f, "{x}"),
                        Err(_) => write!(f, concat!(stringify!($enum_var), " (0x{:x?})"), $enum_val),
                    }),*
                    ,$enum_name::Unknown(x) => {
                        $(
                          if let Some(result) = $display_unknown_fn(f, x.as_slice()) {
                              return result;
                          }
                        )?

                        match ::std::str::from_utf8(x) {
                            Ok(x) => write!(f, "Unknown ({x})"),
                            Err(_) => write!(f, "Unknown (0x{})", hex::encode(x)),
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
                let b = <::std::borrow::Cow<'de, [u8]>>::deserialize(deserializer)?;
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
            ,Unknown(String)
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
                    , _ => $enum_name::Unknown(s.to_owned()),
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
                    , _ => $enum_name::Unknown(s),
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
