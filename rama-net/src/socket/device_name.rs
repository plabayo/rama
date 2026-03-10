use std::{fmt, str::FromStr};

use rama_core::error::{BoxError, ErrorContext as _};
use rama_utils::str::smol_str::SmolStr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Name of a (network) interface device name, e.g. `eth0`.
pub struct DeviceName(SmolStr);

impl DeviceName {
    /// Create a new [`DeviceName`].
    #[must_use]
    pub const fn new(name: &'static str) -> Self {
        if !is_valid(name.as_bytes()) {
            panic!("static str is not a valid (interface) device name");
        }
        Self(SmolStr::new_static(name))
    }

    /// Return a reference to `self` as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Return a reference to `self` as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Display for DeviceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for DeviceName {
    type Err = BoxError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<String> for DeviceName {
    type Error = BoxError;

    #[inline]
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

impl TryFrom<&String> for DeviceName {
    type Error = BoxError;

    #[inline]
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for DeviceName {
    type Error = BoxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        use rama_core::error::ErrorExt as _;

        if is_valid(s.as_bytes()) {
            return Ok(Self(SmolStr::from(s)));
        }

        Err(BoxError::from("invalid (interface) device name").context_str_field("str", s))
    }
}

impl TryFrom<Vec<u8>> for DeviceName {
    type Error = BoxError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for DeviceName {
    type Error = BoxError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let s = std::str::from_utf8(bytes).context("parse (interface) device name from bytes")?;
        s.try_into()
    }
}

impl serde::Serialize for DeviceName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let name = self.as_str();
        name.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DeviceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

pub(super) const fn is_valid(s: &[u8]) -> bool {
    if s.is_empty() || s.len() > DEVICE_MAX_LEN {
        false
    } else {
        let mut i = 0;
        if DEVICE_FIRST_CHARS[s[0] as usize] == 0 {
            return false;
        }
        while i < s.len() {
            if DEVICE_CHARS[s[i] as usize] == 0 {
                return false;
            }
            i += 1;
        }
        true
    }
}

/// The maximum length of a device name.
const DEVICE_MAX_LEN: usize = 15;

#[rustfmt::skip]
/// Valid byte values for a device name.
const DEVICE_CHARS: [u8; 256] = [
    //  0      1      2      3      4      5      6      7      8      9
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //   x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  1x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  2x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0, //  3x
        0,     0,     0,     0,     0,  b'-',  b'.',     0,  b'0',  b'1', //  4x
        b'2',  b'3',  b'4',  b'5',  b'6',  b'7',  b'8',  b'9',  b':',     0, //  5x
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

#[rustfmt::skip]
const DEVICE_FIRST_CHARS: [u8; 256] = [
    //  0      1      2      3      4      5      6      7      8      9
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //   x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  1x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  2x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  3x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  4x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    //  5x
        0,     0,     0,     0,     0,     b'A',  b'B',  b'C',  b'D',  b'E', //  6x
        b'F',  b'G',  b'H',  b'I',  b'J',  b'K',  b'L',  b'M',  b'N',  b'O', //  7x
        b'P',  b'Q',  b'R',  b'S',  b'T',  b'U',  b'V',  b'W',  b'X',  b'Y', //  8x
        b'Z',     0,     0,     0,     0,     0,     0,  b'a',  b'b',  b'c', //  9x
        b'd',  b'e',  b'f',  b'g',  b'h',  b'i',  b'j',  b'k',  b'l',  b'm', // 10x
        b'n',  b'o',  b'p',  b'q',  b'r',  b's',  b't',  b'u',  b'v',  b'w', // 11x
        b'x',  b'y',  b'z',     0,     0,     0,     0,     0,     0,  0,    // 12x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 13x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 14x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 15x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 16x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 17x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 18x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 19x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 20x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 21x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 22x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 23x
        0,     0,     0,     0,     0,     0,     0,     0,     0,     0,    // 24x
        0,     0,     0,     0,     0,     0                                 // 25x
];

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn test_parse_valid_device_name() {
        for s in [
            "eth0",
            "eth0.100",
            "br-lan",
            "ens192",
            "veth_abcd1234",
            "lo",
        ] {
            let msg = format!("parsing '{s}'");

            assert_eq!(s, s.parse::<DeviceName>().expect(&msg).as_str());
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn test_parse_display_device_name() {
        for s in [
            "eth0",
            "eth0.100",
            "br-lan",
            "ens192",
            "veth_abcd1234",
            "lo",
        ] {
            let msg = format!("parsing '{s}'");
            let name: DeviceName = s.parse().expect(&msg);
            assert_eq!(name.to_string(), s, "{msg}");
        }
    }
}
