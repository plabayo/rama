//! module for [`XClacksOverhead`]

use std::fmt;
use std::str::FromStr;

use rama_utils::time::now_unix_ms;

use crate::util::HeaderValueString;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// X-Clacks-Overhead header implementation
///
/// A non-standardised HTTP header based upon the fictional work of the late, great,
/// Sir Terry Pratchett. The header commemorates influential figures in computing
/// and technology by cycling through a predefined list of names.
///
/// Use the [`XClacksOverhead::new`] constructor when using it with a response header
/// adder layer or something similar. This way you get each response a different header.
///
/// # Credits
///
/// Original implementation inspired by work from Xe.
/// See: <https://xclacksoverhead.org/home/about>
///
/// # Examples
///
/// ```
/// use rama_http_headers::exotic::XClacksOverhead;
///
/// // Time-based rotation through commemorated names
/// let header = XClacksOverhead::new();
///
/// // Parse from a string
/// let header: XClacksOverhead = "GNU Terry Pratchett".parse().unwrap();
///
/// // Compile-time constant
/// let header = XClacksOverhead::from_static("GNU Dennis Ritchie");
/// ```
pub struct XClacksOverhead(HeaderValueString);

derive_header! {
    XClacksOverhead(_),
    name: X_CLACKS_OVERHEAD
}

macro_rules! name_list {
    ($($name:literal),+ $(,)?) => {
        const NAMES: &[&str] = &[
            $(
                concat!("GNU ", $name),
            )+
        ];
    };
}

name_list![
    "Karen Sparck Jones",
    "Grant Imahara",
    "Douglas Adams",
    "Ian Murdock",
    "Sir Terry Pratchett",
    "Kevin Mitnick",
    "Radia Perlman",
    "Sophie Wilson",
    "Grace Hopper",
    "Terry Davis",
    "Paul Allen",
    "Edsger Dijkstra",
    "Joe Armstrong",
    "David Bowie",
    "Barbara Liskov",
    "Kris Nova",
    "Alan Turing",
    "Sir Clive Sinclair",
    "Ada Lovelace",
    "John Conway",
    "Satoru Iwata",
    "Dennis Ritchie",
    "Ruth Bader Ginsburg",
    "Matt Trout",
    "Bram Moolenaar",
    "Aaron Swartz",
    "Steven Hawking",
];

impl XClacksOverhead {
    /// Construct a new `XClacksOverhead` header with a name selected based on current epoch time.
    ///
    /// The name changes once per day (UTC).
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_index(now_unix_ms().wrapping_abs() as usize)
    }

    #[inline(always)]
    fn new_with_index(n: usize) -> Self {
        let index = n % NAMES.len();
        Self(HeaderValueString::from_static(NAMES[index]))
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
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for XClacksOverhead {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HeaderEncode;

    use ahash::{HashSet, HashSetExt as _};

    fn test_value(value: &XClacksOverhead) -> String {
        let _ = value.encode_to_value();

        let s = value.to_string();
        let _ = XClacksOverhead::from_str(&s).unwrap();

        s
    }

    #[test]
    fn test_new() {
        let value = XClacksOverhead::new();
        let _ = test_value(&value);
    }

    #[test]
    fn test_default() {
        let value = XClacksOverhead::default();
        let _ = test_value(&value);
    }

    #[test]
    fn test_random_values() {
        let mut unique_values = HashSet::new();
        for index in 0..NAMES.len() * 2 {
            let value = XClacksOverhead::new_with_index(index);
            let s = test_value(&value);
            unique_values.insert(s);
        }
        assert_eq!(NAMES.len(), unique_values.len());
    }
}
