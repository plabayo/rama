//! X-Clacks-Overhead header implementation
//!
//! A non-standardised HTTP header based upon the fictional work of the late, great,
//! Sir Terry Pratchett. The header commemorates influential figures in computing
//! and technology by cycling through a predefined list of names.
//!
//! # Credits
//!
//! Original implementation inspired by work from Xe.
//! See: <https://xclacksoverhead.org/home/about>
//!
//! # Examples
//!
//! ```
//! use rama_http_headers::XClacksOverhead;
//!
//! // Time-based rotation through commemorated names
//! let header = XClacksOverhead::new();
//!
//! // Parse from a string
//! let header: XClacksOverhead = "GNU Terry Pratchett".parse().unwrap();
//!
//! // Compile-time constant
//! let header = XClacksOverhead::from_static("GNU Dennis Ritchie");
//! ```
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::HeaderValueString;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct XClacksOverhead(HeaderValueString);

derive_header! {
    XClacksOverhead(_),
    name: X_CLACKS_OVERHEAD
}

const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

const NAMES: [&str; 17] = [
    "Ashlynn",
    "Terry Davis",
    "Dennis Ritchie",
    "Steven Hawking",
    "John Conway",
    "Ruth Bader Ginsburg",
    "Bram Moolenaar",
    "Grant Imahara",
    "David Bowie",
    "Sir Terry Pratchett",
    "Satoru Iwata",
    "Kris Nóva",
    "Joe Armstrong",
    "Paul Allen",
    "Kevin Mitnick",
    "Sir Clive Sinclair",
    "Matt Trout",
];

impl XClacksOverhead {
    /// Construct a new `XClacksOverhead` header with a name selected based on current epoch time.
    ///
    /// The name changes once per day (UTC).
    #[must_use]
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let index = (now / SECONDS_PER_DAY) as usize % NAMES.len();
        Self(
            HeaderValueString::from_string(format!("GNU {}", NAMES[index]))
                .expect("Valid header value"),
        )
    }

    /// Construct an `XClacksOverhead` from a static string.
    ///
    /// # Panic
    ///
    /// Panics if the static string is not a legal header value.
    #[must_use]
    pub const fn from_static(s: &'static str) -> Self {
        Self(HeaderValueString::from_static(s))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "invalid X-Clacks-Overhead header value"]
    pub struct InvalidXClacksOverhead;
}

impl FromStr for XClacksOverhead {
    type Err = InvalidXClacksOverhead;

    fn from_str(src: &str) -> Result<Self, Self::Err> {
        HeaderValueString::from_str(src)
            .map(XClacksOverhead)
            .map_err(|_| InvalidXClacksOverhead)
    }
}

impl Default for XClacksOverhead {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for XClacksOverhead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_header_format() {
        let header = XClacksOverhead::new();
        let value = header.as_str();
        assert!(value.starts_with("GNU "));

        let name = value.strip_prefix("GNU ").unwrap();
        assert!(NAMES.contains(&name));
    }

    #[test]
    fn test_from_str() {
        let header = "GNU Terry Pratchett".parse::<XClacksOverhead>().unwrap();
        assert_eq!(header.as_str(), "GNU Terry Pratchett");
    }

    #[test]
    fn test_from_static() {
        let header = XClacksOverhead::from_static("GNU Dennis Ritchie");
        assert_eq!(header.as_str(), "GNU Dennis Ritchie");
    }

    #[test]
    fn test_all_names_are_valid() {
        for name in NAMES.iter() {
            let name = format!("GNU {name}");
            let header = name.parse::<XClacksOverhead>().unwrap();
            assert_eq!(header.as_str(), name);
        }
    }

    #[test]
    fn test_default() {
        let header = XClacksOverhead::default();
        assert!(header.as_str().starts_with("GNU "));
    }
}
