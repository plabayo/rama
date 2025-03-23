#[doc(hidden)]
#[macro_export]
/// A macro which defines an enum type.
macro_rules! __enum_builder {
    (
        $(#[$comment:meta])*
        @U8
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$comment])*
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
                    ,$enum_name::Unknown(x) => write!(f, "Unknown ({x:#06x})"),
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

        impl ::serde::Serialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                u8::from(*self).serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let n = u8::deserialize(deserializer)?;
                Ok(n.into())
            }
        }
    };
    (
        $(#[$comment:meta])*
        @U16
        $enum_vis:vis enum $enum_name:ident
        { $( $(#[$enum_meta:meta])* $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$comment])*
        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
        $enum_vis enum $enum_name {
            $(
                $(#[$enum_meta])*
                $enum_var
            ),*
            ,Unknown(u16)
        }

        impl $enum_name {
            /// returns true if this id is a grease object
            $enum_vis fn is_grease(&self) -> bool {
                match self {
                    $enum_name::Unknown(x) if x & 0x0f0f == 0x0a0a => true,
                    _ => false,
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
                    ,$enum_name::Unknown(x) => if x & 0x0f0f == 0x0a0a {
                        write!(f, "GREASE ({x:#06x})")
                        } else {
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

        impl ::serde::Serialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                u16::from(*self).serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let n = u16::deserialize(deserializer)?;
                Ok(n.into())
            }
        }
    };
    (
        $(#[$comment:meta])*
        @Bytes
        $enum_vis:vis enum $enum_name:ident
        { $( $enum_var: ident => $enum_val: expr ),* $(,)? }
    ) => {
        $(#[$comment])*
        #[derive(Debug, PartialEq, Eq, Clone, Hash)]
        $enum_vis enum $enum_name {
            $( $enum_var),*
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
                    ,$enum_name::Unknown(x) =>
                        if x.len() == 2 && x[0] & 0x0f == 0x0a && x[1] & 0x0f == 0x0a {
                            write!(f, "GREASE (0x{})", hex::encode(x))
                        } else {
                            match ::std::str::from_utf8(x) {
                                Ok(x) => write!(f, "Unknown ({x})"),
                                Err(_) => write!(f, "Unknown (0x{})", hex::encode(x)),
                            }
                        }
                }
            }
        }

        impl ::serde::Serialize for $enum_name {
            #[inline]
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
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

        impl<'de> ::serde::Deserialize<'de> for $enum_name {
            #[inline]
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: ::serde::Deserializer<'de>,
            {
                let b = <::std::borrow::Cow<'de, [u8]>>::deserialize(deserializer)?;
                Ok(b.as_ref().into())
            }
        }
    };
}

#[doc(inline)]
pub use crate::__enum_builder as enum_builder;
