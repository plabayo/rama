//! Serialize byte fields as hex strings, with one adapter for vectors and arrays.
//!
//! The default is lowercase without a prefix. Use [`upper`], [`prefixed`], or
//! [`upper_prefixed`] for common alternatives, or [`colon`] / [`upper_colon`]
//! for colon-separated bytes. Deserialization accepts either
//! digit case and requires the selected prefix and separators exactly.
//!
//! ```
//! #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
//! struct Digest {
//!     #[serde(with = "rama_utils::bytes::serde_hex::upper_prefixed")]
//!     bytes: [u8; 2],
//! }
//! let digest = Digest { bytes: [0, 0xab] };
//! let json = serde_json::to_string(&digest)?;
//! assert_eq!(json, r#"{"bytes":"0x00AB"}"#);
//! assert_eq!(serde_json::from_str::<Digest>(&json)?, digest);
//! # Ok::<(), serde_json::Error>(())
//! ```
//!
//! For custom formats, use [`crate::hex::serde_with!`]. Serialization uses
//! [`Serializer::collect_str`]; whether it allocates depends on the serializer.
//! Deserializing an array needs no intermediate vector.

use core::{fmt, marker::PhantomData};

use serde::{
    Deserializer, Serializer,
    de::{Error, Visitor},
};

use crate::hex::{Format, FromHex, Hex};

/// Serialize byte-like input as lowercase, unprefixed hex.
pub fn serialize<S: Serializer, B: AsRef<[u8]> + ?Sized>(
    bytes: &B,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    Format::new().serialize(bytes, serializer)
}

/// Deserialize compact, mixed-case hex into a vector, array, or [`FromHex`] type.
pub fn deserialize<'de, D: Deserializer<'de>, T: FromHex>(deserializer: D) -> Result<T, D::Error> {
    Format::new().deserialize(deserializer)
}

impl serde::Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl Format<'_> {
    /// Serialize byte-like input with this format, without an intermediate hex
    /// string unless the serializer itself needs one.
    pub fn serialize<S: Serializer, B: AsRef<[u8]> + ?Sized>(
        &self,
        bytes: &B,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&crate::fmt::hex(bytes).with_format(*self))
    }

    /// Deserialize into a [`FromHex`] destination using this format.
    pub fn deserialize<'de, D: Deserializer<'de>, T: FromHex>(
        &self,
        deserializer: D,
    ) -> Result<T, D::Error> {
        struct HexVisitor<'a, T>(Format<'a>, PhantomData<T>);
        impl<'de, T: FromHex> Visitor<'de> for HexVisitor<'_, T> {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hex string matching the configured format")
            }

            fn visit_str<E: Error>(self, value: &str) -> Result<T, E> {
                self.0.decode(value).map_err(E::custom)
            }
        }
        deserializer.deserialize_str(HexVisitor(*self, PhantomData))
    }
}

// Public only so the exported macro works with a renamed Serde dependency.
#[doc(hidden)]
pub use serde as __serde;

/// Generate a module for `#[serde(with = "module_name")]` with a custom format.
///
/// The expression must produce a constant [`Format<'static>`]. Names in the
/// expression are available through an import of the enclosing module. Explicit
/// relative paths are interpreted inside the generated module (for example,
/// `super::CUSTOM`). Invoke this macro at module scope. An optional visibility
/// can expose the adapter for reuse elsewhere.
///
/// ```
/// use rama_utils::hex::{self, Format};
/// const CUSTOM: Format<'static> = Format::new()
///     .with_upper_case().with_prefix("sha256:");
/// hex::serde_with!(custom_hex, CUSTOM);
/// #[derive(serde::Serialize, serde::Deserialize)]
/// struct Payload(#[serde(with = "custom_hex")] [u8; 2]);
/// # fn main() -> Result<(), serde_json::Error> {
/// assert_eq!(serde_json::to_string(&Payload([0, 0xab]))?, "\"sha256:00AB\"");
/// # Ok(())
/// # }
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! __hex_serde_with {
    ($(#[$attr:meta])* $vis:vis $name:ident, $format:expr $(,)?) => {
        $(#[$attr])*
        #[expect(clippy::allow_attributes, reason = "these lints depend on the macro invocation scope and expression")]
        #[allow(unused_imports, unreachable_pub)]
        $vis mod $name {
            // Make enclosing names available to the configuration expression.
            use super::*;

            pub fn serialize<S, B: ::core::convert::AsRef<[u8]> + ?Sized>(
                bytes: &B,
                serializer: S,
            ) -> ::core::result::Result<S::Ok, S::Error>
            where
                S: $crate::bytes::serde_hex::__serde::Serializer,
            {
                let format: $crate::hex::Format<'static> = const { $format };
                format.serialize(bytes, serializer)
            }

            pub fn deserialize<'de, D, T: $crate::hex::FromHex>(
                deserializer: D,
            ) -> ::core::result::Result<T, D::Error>
            where
                D: $crate::bytes::serde_hex::__serde::Deserializer<'de>,
            {
                let format: $crate::hex::Format<'static> = const { $format };
                format.deserialize(deserializer)
            }
        }
    };
}

crate::__hex_serde_with!(
    /// Uppercase hex without a prefix.
    pub upper, Format::new().with_upper_case()
);
crate::__hex_serde_with!(
    /// Lowercase hex with a required `0x` prefix.
    pub prefixed, Format::new().with_prefix("0x")
);
crate::__hex_serde_with!(
    /// Uppercase hex with a required lowercase `0x` prefix.
    pub upper_prefixed,
    Format::new().with_upper_case().with_prefix("0x")
);

crate::__hex_serde_with!(
    /// Lowercase colon-separated bytes, without a prefix.
    pub colon, Format::new().with_separator(":")
);
crate::__hex_serde_with!(
    /// Uppercase colon-separated bytes, without a prefix.
    pub upper_colon, Format::new().with_upper_case().with_separator(":")
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::std::Vec;
    use serde_test::{Token, assert_ser_tokens};

    const FORMAT: Format<'static> = Format::new().with_upper_case().with_prefix("🔑:");
    crate::hex::serde_with!(custom, FORMAT);
    crate::hex::serde_with!(relative, super::FORMAT);

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Payload {
        #[serde(with = "super")]
        plain: Vec<u8>,
        #[serde(with = "upper")]
        upper: [u8; 2],
        #[serde(with = "prefixed")]
        prefixed: Vec<u8>,
        #[serde(with = "upper_prefixed")]
        upper_prefixed: [u8; 2],
        #[serde(with = "custom")]
        custom: [u8; 2],
    }

    const SEPARATED: Format<'static> = Format::new().with_prefix("hash:").with_separator("→");
    crate::hex::serde_with!(separated, SEPARATED);

    #[test]
    fn separated_adapters_round_trip_and_reject_malformed_framing() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Separated {
            #[serde(with = "colon")]
            lower: Vec<u8>,
            #[serde(with = "upper_colon")]
            upper: [u8; 3],
            #[serde(with = "separated")]
            custom: [u8; 3],
        }
        let payload = Separated {
            lower: Vec::from([0, 0xab, 255]),
            upper: [0, 0xab, 255],
            custom: [0, 0xab, 255],
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            json,
            r#"{"lower":"00:ab:ff","upper":"00:AB:FF","custom":"hash:00→ab→ff"}"#
        );
        assert_eq!(serde_json::from_str::<Separated>(&json).unwrap(), payload);
        for (valid, invalid) in [
            ("00:ab:ff", "00abff"),
            ("00:AB:FF", "00:AB:FF:"),
            ("hash:00→ab→ff", "hash:00:ab:ff"),
        ] {
            serde_json::from_str::<Separated>(&json.replace(valid, invalid)).unwrap_err();
        }
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Empty(#[serde(with = "separated")] [u8; 0]);
        assert_eq!(serde_json::to_string(&Empty([])).unwrap(), "\"hash:\"");
        assert_eq!(
            serde_json::from_str::<Empty>("\"hash:\"").unwrap(),
            Empty([])
        );
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Large(#[serde(with = "upper_colon")] [u8; 65]);
        let value = Large([0xab; 65]);
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<Large>(&json).unwrap(), value);
    }

    #[test]
    fn common_and_custom_adapters_round_trip() {
        let payload = Payload {
            plain: Vec::from([0, 0xab]),
            upper: [0, 0xab],
            prefixed: Vec::from([0, 0xab]),
            upper_prefixed: [0, 0xab],
            custom: [0, 0xab],
        };
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Relative(#[serde(with = "relative")] [u8; 2]);
        let json = serde_json::to_string(&Relative([0, 0xab])).unwrap();
        assert_eq!(json, "\"🔑:00AB\"");
        assert_eq!(
            serde_json::from_str::<Relative>(&json).unwrap(),
            Relative([0, 0xab])
        );
        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            json,
            r#"{"plain":"00ab","upper":"00AB","prefixed":"0x00ab","upper_prefixed":"0x00AB","custom":"🔑:00AB"}"#
        );
        assert_eq!(serde_json::from_str::<Payload>(&json).unwrap(), payload);
        assert_eq!(
            serde_json::from_str::<Payload>(&json.replace("AB", "aB")).unwrap(),
            payload
        );
    }

    #[test]
    fn empty_arrays_and_escaped_strings() {
        #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        struct Empty(#[serde(with = "upper_prefixed")] [u8; 0]);
        assert_eq!(serde_json::to_string(&Empty([])).unwrap(), "\"0x\"");
        assert_eq!(serde_json::from_str::<Empty>("\"0x\"").unwrap(), Empty([]));
        #[derive(Debug, PartialEq, serde::Deserialize)]
        struct One(#[serde(with = "super")] [u8; 1]);
        assert_eq!(
            serde_json::from_str::<One>(r#""\u0030f""#).unwrap(),
            One([15])
        );
    }

    #[test]
    fn malformed_and_wrong_sized_fields_are_errors() {
        #[derive(Debug, serde::Deserialize)]
        struct Pair(#[serde(with = "upper_prefixed")] [u8; 2]);
        for input in [
            r#""0x""#,
            r#""0x00""#,
            r#""0x000102""#,
            r#""0x000""#,
            r#""0x00gg""#,
            r#""0000""#,
            r#""0X0000""#,
        ] {
            assert!(serde_json::from_str::<Pair>(input).is_err(), "{input}");
        }
        let pair = serde_json::from_str::<Pair>(r#""0x00ff""#).unwrap();
        assert_eq!(pair.0, [0, 255]);
        let error = serde_json::from_str::<Pair>("17").unwrap_err().to_string();
        assert!(
            error.contains("expected a hex string matching the configured format"),
            "{error}"
        );
    }

    #[test]
    fn views_and_borrowed_slices_serialize_as_strings() {
        let view = crate::fmt::hex(&[0, 0xab]).with_format(FORMAT);
        assert_ser_tokens(&view, &[Token::Str("🔑:00AB")]);
        #[derive(serde::Serialize)]
        struct Borrowed<'a>(#[serde(with = "upper")] &'a [u8]);
        assert_eq!(
            serde_json::to_string(&Borrowed(&[0, 0xab])).unwrap(),
            "\"00AB\""
        );

        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("broken"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(serde_json::to_writer(Broken, &view).unwrap_err().is_io());
    }
}
