//! Shared `serde` glue for string-like types.

/// Implement [`serde::Serialize`] + [`serde::Deserialize`] for a type whose
/// canonical wire form is a single string.
///
/// Both arms deserialize by parsing a borrowed-or-owned string through the
/// type's [`FromStr`](std::str::FromStr) impl. They differ only in how the
/// value is serialized:
///
/// - `display $t` serializes via [`Display`](std::fmt::Display)
///   (`serializer.collect_str`) — use when the canonical string is the
///   `Display` output.
/// - `as_str $t` serializes the borrowed `self.as_str()` slice directly — use
///   when the type already holds its canonical string.
///
/// The macro relies on `serde` being importable as `serde::` at the call site.
///
/// # Example
///
/// ```
/// # use rama_utils::macros::serde_str::impl_serde_str;
/// struct Tag(String);
///
/// impl std::fmt::Display for Tag {
///     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///         f.write_str(&self.0)
///     }
/// }
///
/// impl std::str::FromStr for Tag {
///     type Err = std::convert::Infallible;
///     fn from_str(s: &str) -> Result<Self, Self::Err> {
///         Ok(Self(s.to_owned()))
///     }
/// }
///
/// impl_serde_str!(display Tag);
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! __impl_serde_str {
    (display $t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }
        $crate::__impl_serde_str!(@de $t);
    };
    (as_str $t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.as_str().serialize(serializer)
            }
        }
        $crate::__impl_serde_str!(@de $t);
    };
    (@de $t:ty) => {
        impl<'de> serde::Deserialize<'de> for $t {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

#[doc(inline)]
pub use crate::__impl_serde_str as impl_serde_str;
