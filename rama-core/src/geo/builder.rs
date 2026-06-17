//! The [`geo_enum!`] macro used to define the closed code-keyed enums in this
//! module (continent, country, language, script).
//!
//! Each invocation generates two types: an owned form whose `Unknown` variant
//! holds a `Box<str>`, and a borrowing, [`Copy`] `*Ref` form whose `Unknown`
//! holds a `&str`. Both expose `code()` / `name()` / `from_code()`, round-trip
//! through their canonical code via `Display` + serde, and convert between each
//! other (`to_owned`). The owned form also exposes a `Self::ALL` slice of every
//! known value.
//!
//! An optional `meta <Struct> { field: Option<T>, .. }` prelude adds per-value
//! metadata accessors (one method per field, returning the field's `Option<T>`,
//! `None` for `Unknown`) on both the owned and borrowing forms — used for e.g.
//! a country's ISO alpha-3 / numeric codes.

/// Define an owned + borrowing pair of closed, code-keyed enums.
///
/// Syntax (without metadata):
/// ```ignore
/// geo_enum! {
///     /// docs for the owned type
///     pub enum Continent / ContinentRef {
///         Africa => "AF", "Africa",
///         Europe => "EU", "Europe",
///     }
/// }
/// ```
///
/// Syntax (with metadata accessors — every field must be `Option<_>`):
/// ```ignore
/// geo_enum! {
///     meta CountryMeta {
///         alpha3: Option<&'static str>,
///         numeric: Option<u16>,
///     }
///     /// docs for the owned type
///     pub enum Country / CountryRef {
///         Belgium => "BE", "Belgium", { alpha3: Some("BEL"), numeric: Some(56) },
///     }
/// }
/// ```
macro_rules! geo_enum {
    // ===== shared body: enum defs + code/name/from_code/ALL + serde =====
    (@common
        $(#[$meta:meta])*
        $vis:vis enum $name:ident / $name_ref:ident {
            $( $(#[$vmeta:meta])* $var:ident => $code:literal, $label:literal ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        $vis enum $name {
            $( $(#[$vmeta])* $var, )*
            /// A code not recognised by this version of rama, preserved verbatim.
            Unknown(Box<str>),
        }

        #[doc = concat!("Borrowing, [`Copy`] counterpart of [`", stringify!($name), "`].")]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name_ref<'a> {
            $( $(#[$vmeta])* $var, )*
            /// A code not recognised by this version of rama, borrowed verbatim.
            Unknown(&'a str),
        }

        impl $name {
            /// Every known value, in canonical-code order (excludes `Unknown`).
            pub const ALL: &'static [Self] = &[ $( Self::$var ),* ];

            /// The canonical code for this value (e.g. `"BE"`).
            #[must_use]
            pub fn code(&self) -> &str {
                match self {
                    $( Self::$var => $code, )*
                    Self::Unknown(s) => s,
                }
            }

            /// The English display name, or `None` for an unknown code.
            #[must_use]
            pub fn name(&self) -> Option<&'static str> {
                match self {
                    $( Self::$var => Some($label), )*
                    Self::Unknown(_) => None,
                }
            }

            /// Parse from a canonical code (case-sensitive). Unknown codes are
            /// preserved in the `Unknown` variant rather than rejected.
            #[must_use]
            pub fn from_code(code: &str) -> Self {
                match code {
                    $( $code => Self::$var, )*
                    other => Self::Unknown(other.into()),
                }
            }

            /// Whether this is a known (non-`Unknown`) value.
            #[must_use]
            pub fn is_known(&self) -> bool {
                !matches!(self, Self::Unknown(_))
            }

            /// Borrow as the [`Copy`] reference form.
            #[must_use]
            pub fn as_view(&self) -> $name_ref<'_> {
                match self {
                    $( Self::$var => $name_ref::$var, )*
                    Self::Unknown(s) => $name_ref::Unknown(s),
                }
            }
        }

        impl<'a> $name_ref<'a> {
            /// The canonical code for this value (e.g. `"BE"`).
            #[must_use]
            pub fn code(self) -> &'a str {
                match self {
                    $( Self::$var => $code, )*
                    Self::Unknown(s) => s,
                }
            }

            /// The English display name, or `None` for an unknown code.
            #[must_use]
            pub fn name(self) -> Option<&'static str> {
                match self {
                    $( Self::$var => Some($label), )*
                    Self::Unknown(_) => None,
                }
            }

            /// Parse from a canonical code (case-sensitive), borrowing `code`
            /// for any unknown value.
            #[must_use]
            pub fn from_code(code: &'a str) -> Self {
                match code {
                    $( $code => Self::$var, )*
                    other => Self::Unknown(other),
                }
            }

            /// Whether this is a known (non-`Unknown`) value.
            #[must_use]
            pub fn is_known(self) -> bool {
                !matches!(self, Self::Unknown(_))
            }

            /// Convert into the owned form (allocates only for `Unknown`).
            #[must_use]
            pub fn to_owned(self) -> $name {
                match self {
                    $( Self::$var => $name::$var, )*
                    Self::Unknown(s) => $name::Unknown(s.into()),
                }
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.code())
            }
        }

        impl ::std::fmt::Display for $name_ref<'_> {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(self.code())
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = ::std::convert::Infallible;
            fn from_str(s: &str) -> ::std::result::Result<Self, Self::Err> {
                Ok(Self::from_code(s))
            }
        }

        impl From<&str> for $name {
            fn from(s: &str) -> Self {
                Self::from_code(s)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                match s.as_str() {
                    $( $code => Self::$var, )*
                    _ => Self::Unknown(s.into_boxed_str()),
                }
            }
        }

        impl ::serde::Serialize for $name {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.code())
            }
        }

        impl ::serde::Serialize for $name_ref<'_> {
            fn serialize<S: ::serde::Serializer>(
                &self,
                serializer: S,
            ) -> ::std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(self.code())
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $name {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> ::std::result::Result<Self, D::Error> {
                let s = <::std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
                Ok(Self::from_code(&s))
            }
        }
    };

    // ===== with per-value metadata accessors =====
    (
        meta $meta_struct:ident { $( $field:ident : $fty:ty ),+ $(,)? }
        $(#[$meta:meta])*
        $vis:vis enum $name:ident / $name_ref:ident {
            $( $(#[$vmeta:meta])* $var:ident => $code:literal, $label:literal, { $($init:tt)* } ),* $(,)?
        }
    ) => {
        geo_enum! { @common
            $(#[$meta])*
            $vis enum $name / $name_ref {
                $( $(#[$vmeta])* $var => $code, $label ),*
            }
        }

        /// Static per-value metadata; every field is `Option<_>` so it can be
        /// flattened against the absence of a value for `Unknown`.
        #[derive(Clone, Copy)]
        struct $meta_struct { $( $field : $fty ),+ }

        impl $name {
            fn meta(&self) -> Option<$meta_struct> {
                Some(match self {
                    $( Self::$var => $meta_struct { $($init)* }, )*
                    Self::Unknown(_) => return None,
                })
            }

            $(
                #[doc = concat!("The `", stringify!($field), "` metadata for this value, or `None` if unknown.")]
                #[must_use]
                pub fn $field(&self) -> $fty {
                    self.meta().and_then(|m| m.$field)
                }
            )+
        }

        impl $name_ref<'_> {
            fn meta(self) -> Option<$meta_struct> {
                Some(match self {
                    $( Self::$var => $meta_struct { $($init)* }, )*
                    Self::Unknown(_) => return None,
                })
            }

            $(
                #[doc = concat!("The `", stringify!($field), "` metadata for this value, or `None` if unknown.")]
                #[must_use]
                pub fn $field(self) -> $fty {
                    self.meta().and_then(|m| m.$field)
                }
            )+
        }
    };

    // ===== plain (no metadata) =====
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident / $name_ref:ident {
            $( $(#[$vmeta:meta])* $var:ident => $code:literal, $label:literal ),* $(,)?
        }
    ) => {
        geo_enum! { @common
            $(#[$meta])*
            $vis enum $name / $name_ref {
                $( $(#[$vmeta])* $var => $code, $label ),*
            }
        }
    };
}

pub(crate) use geo_enum;
