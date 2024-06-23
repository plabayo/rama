use crate::error::{ErrorContext, OpaqueError};
use std::{borrow::Cow, fmt};

macro_rules! create_obf_type {
    ($name:ident, $val_fn:expr, $fix_lossy:expr) => {
        #[doc = concat!(stringify!($name), "used by Forwarded extension")]
        #[doc = ""]
        #[doc = "See <https://datatracker.ietf.org/doc/html/rfc7239#section-6>."]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(Cow<'static, str>);

        impl $name {
            #[doc = concat!("Creates a [`", stringify!($name), "`] at compile time.")]
            #[doc = ""]
            #[doc = concat!("This function requires the static string to be a valid [`", stringify!($name), "`]")]
            ///
            /// # Panics
            ///
            /// This function panics at **compile time** when the static string is not a valid.
            pub const fn from_static(s: &'static str) -> Self {
                if !$val_fn(s.as_bytes()) {
                    panic!(concat!("static str is an invalid ", stringify!($name)));
                }
                Self(Cow::Borrowed(s))
            }

            #[doc = concat!("Try to convert a vector of bytes to a [`", stringify!($name), "`].")]
            pub fn try_from_bytes(vec: Vec<u8>) -> Result<Self, OpaqueError> {
                vec.try_into()
            }

            #[doc = concat!("Try to convert a string slice to a [`", stringify!($name), "`].")]
            pub fn try_from_str(s: &str) -> Result<Self, OpaqueError> {
                s.to_owned().try_into()
            }

            #[doc = concat!("Converts a vector of bytes to a [`", stringify!($name), "`], converting invalid characters to underscore.")]
            pub fn from_bytes_lossy(mut vec: Vec<u8>) -> Self {
                vec = $fix_lossy(vec);

                if vec.len() > OBF_MAX_LEN {
                    vec = vec.into_iter().take(OBF_MAX_LEN).collect();
                }

                for b in vec.iter_mut() {
                    if OBF_CHARS[*b as usize] == 0 {
                        *b = b'_'
                    }
                }

                vec.try_into().expect("sanitized bytes vec should always be correct")
            }

            #[doc = concat!("Converts a string slice to a [`", stringify!($name), "`], converting invalid characters to underscore.")]
            pub fn from_str_lossy(s: &str) -> Self {
                let vec = s.to_owned().into_bytes();
                Self::from_bytes_lossy(vec)
            }

            #[doc = concat!("Gets the [`", stringify!($name), "`] as reference.")]
            pub fn as_str(&self) -> &str {
                self.as_ref()
            }

            #[allow(dead_code)]
            /// easier creation for other locs in this codebase where we are certain that data is pre-validated
            pub(super) fn from_inner(inner: Cow<'static, str>) -> Self {
                debug_assert!($val_fn(inner.as_bytes()));
                Self(inner)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.0.as_ref()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl std::str::FromStr for $name {
            type Err = OpaqueError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                $name::try_from(s.to_owned())
            }
        }

        impl TryFrom<String> for $name {
            type Error = OpaqueError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                if $val_fn(s.as_bytes()) {
                    Ok(Self(Cow::Owned(s)))
                } else {
                    Err(OpaqueError::from_display(concat!("invalid ", stringify!($name))))
                }
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = OpaqueError;

            fn try_from(s: Vec<u8>) -> Result<Self, Self::Error> {
                if $val_fn(s.as_slice()) {
                    Ok(Self(Cow::Owned(
                        String::from_utf8(s).context(concat!("convert ", stringify!($name), "bytes to utf-8 string"))?,
                    )))
                } else {
                    Err(OpaqueError::from_display(concat!("invalid ", stringify!($name))))
                }
            }
        }

        impl PartialEq<str> for $name {
            fn eq(&self, other: &str) -> bool {
                self.0 == other
            }
        }

        impl PartialEq<&str> for $name {
            fn eq(&self, other: &&str) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for str {
            fn eq(&self, other: &$name) -> bool {
                other == self
            }
        }

        impl PartialEq<$name> for &str {
            fn eq(&self, other: &$name) -> bool {
                other == *self
            }
        }

        impl PartialEq<String> for $name {
            fn eq(&self, other: &String) -> bool {
                self.as_str() == other
            }
        }

        impl PartialEq<$name> for String {
            fn eq(&self, other: &$name) -> bool {
                other == self
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                s.try_into().map_err(serde::de::Error::custom)
            }
        }
    };
}

create_obf_type!(ObfNode, is_valid_obf_node, fix_obf_node);
create_obf_type!(ObfPort, is_valid_obf_port, fix_obf_port);

const fn is_valid_obf_port(s: &[u8]) -> bool {
    is_valid_obf_node(s) && s[0] == b'_'
}

fn fix_obf_port(mut vec: Vec<u8>) -> Vec<u8> {
    if vec.is_empty() {
        vec![b'_']
    } else if vec[0] != b'_' {
        vec.insert(0, b'_');
        vec
    } else {
        vec
    }
}

const fn is_valid_obf_node(s: &[u8]) -> bool {
    if s.is_empty() || s.len() > OBF_MAX_LEN {
        false
    } else {
        let mut i = 0;
        while i < s.len() {
            if OBF_CHARS[s[i] as usize] == 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

fn fix_obf_node(vec: Vec<u8>) -> Vec<u8> {
    if vec.is_empty() {
        vec![b'_']
    } else {
        vec
    }
}

/// The maximum length of an obf string.
///
/// Not defined by spec, but might as well put a limit on it
const OBF_MAX_LEN: usize = 256;

// obfnode = 1*( ALPHA / DIGIT / "." / "_" / "-")
// obfport = "_" 1*(ALPHA / DIGIT / "." / "_" / "-")
//
// https://datatracker.ietf.org/doc/html/rfc7239#section-6
#[rustfmt::skip]
const OBF_CHARS: [u8; 256] = [
    //  0      1      2      3      4      5      6      7      8      9
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //   x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  1x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  2x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  3x
        0,     0,     0,     0,     0,  b'-',  b'.',     0,  b'0',  b'1', //  4x
     b'2',  b'3',  b'4',  b'5',  b'6',  b'7',  b'8',  b'9',     0,     0, //  5x
        0,     0,     0,     0,     0,  b'A',  b'B',  b'C',  b'D',  b'E', //  6x
     b'F',  b'G',  b'H',  b'I',  b'J',  b'K',  b'L',  b'M',  b'N',  b'O', //  7x
     b'P',  b'Q',  b'R',  b'S',  b'T',  b'U',  b'V',  b'W',  b'X',  b'Y', //  8x
     b'Z',     0,     0,     0,     0,  b'_',     0,  b'a',  b'b',  b'c', //  9x
     b'd',  b'e',  b'f',  b'g',  b'h',  b'i',  b'j',  b'k',  b'l',  b'm', // 10x
     b'n',  b'o',  b'p',  b'q',  b'r',  b's',  b't',  b'u',  b'v',  b'w', // 11x
     b'x',  b'y',  b'z',     0,     0,     0,     0,     0,     0,     0, // 12x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 13x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 14x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 15x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 16x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 17x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 18x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 19x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 20x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 21x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 22x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 23x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, // 24x
        0,     0,     0,     0,     0,     0                              // 25x
];

#[cfg(test)]
#[allow(clippy::expect_fun_call)]
mod tests {
    use super::*;

    #[test]
    fn test_obf_node_parse_valid() {
        for str in [
            "_gazonk",
            "foo",
            "_foo-bar.baz",
            "-",
            "_",
            ".",
            "1",
            "a",
            "A",
            "-FoA-F-sdada_321A---",
        ] {
            let msg = format!("to parse: {}", str);
            assert_eq!(ObfNode::try_from(str.to_owned()).expect(msg.as_str()), str);
            assert_eq!(
                ObfNode::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                str
            );
        }
    }

    #[test]
    fn test_obf_node_parse_lossy() {
        for (str, expected) in [
            ("_gazonk", "_gazonk"),
            ("foo", "foo"),
            ("", "_"),
            ("@", "_"),
            ("wh@t", "wh_t"),
            ("😀", "____"),
            ("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv"),
        ] {
            assert_eq!(ObfNode::from_str_lossy(str), expected);
            assert_eq!(
                ObfNode::from_bytes_lossy(str.as_bytes().to_vec()),
                expected
            );
        }
    }

    #[test]
    fn test_obf_node_parse_invalid() {
        for str in [
            "",
            "@",
            "😀",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(ObfNode::try_from(str.to_owned()).is_err());
            assert!(ObfNode::try_from(str.as_bytes().to_vec()).is_err());
        }
    }

    #[test]
    fn test_obf_port_parse_valid() {
        for str in [
            "_gazonk",
            "_83",
            "_foo-bar.baz",
            "_-",
            "_",
            "_.",
            "_1",
            "_a",
            "_A",
            "_-FoA-F-sdada_321A---",
        ] {
            let msg = format!("to parse: {}", str);
            assert_eq!(ObfPort::try_from(str.to_owned()).expect(msg.as_str()), str);
            assert_eq!(
                ObfPort::try_from(str.as_bytes().to_vec()).expect(msg.as_str()),
                str
            );
        }
    }

    #[test]
    fn test_obf_port_parse_lossy() {
        for (str, expected) in [
            ("_gazonk", "_gazonk"),
            ("_83", "_83"),
            ("83", "_83"),
            ("-", "_-"),
            ("", "_"),
            ("@", "__"),
            ("wh@t", "_wh_t"),
            ("😀", "_____"),
            ("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz", "_abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstu"),
        ] {
            assert_eq!(ObfPort::from_str_lossy(str), expected);
            assert_eq!(
                ObfPort::from_bytes_lossy(str.as_bytes().to_vec()),
                expected
            );
        }
    }

    #[test]
    fn test_obf_port_parse_invalid() {
        for str in [
            "",
            "-",
            "a",
            "1",
            "@",
            "😀",
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(ObfPort::try_from(str.to_owned()).is_err());
            assert!(ObfPort::try_from(str.as_bytes().to_vec()).is_err());
        }
    }
}
