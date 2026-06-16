//! Internal helper macros shared across `rama-net` modules.

/// Implement `serde::Serialize` + `serde::Deserialize` for a string-like type.
///
/// Both arms deserialize by parsing a borrowed-or-owned string through the
/// type's [`FromStr`](std::str::FromStr) impl. They differ only in how the
/// value is serialized:
///
/// - `display $t` serializes via [`Display`](std::fmt::Display)
///   (`serializer.collect_str`) — use when the canonical wire form is the
///   `Display` output.
/// - `as_str $t` serializes the borrowed `self.as_str()` slice directly — use
///   when the type already holds its canonical string.
macro_rules! impl_serde_str {
    (display $t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }
        $crate::macros::impl_serde_str!(@de $t);
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
        $crate::macros::impl_serde_str!(@de $t);
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

pub(crate) use impl_serde_str;
