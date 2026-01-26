use rama_core::telemetry::tracing;
use rama_utils::collections::smallvec::SmallVec;
use serde::{Deserialize, Serialize, de::Error};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash)]
#[repr(u8)]
/// Defined in function of being able to communicate the used or desired
/// order in which the pseudo headers are in the h2 request.
///
/// Used mainly in [`PseudoHeaderOrder`].
pub enum PseudoHeader {
    Method = 0b1000_0000,
    Scheme = 0b0100_0000,
    Authority = 0b0010_0000,
    Path = 0b0001_0000,
    Protocol = 0b0000_1000,
    Status = 0b0000_0100,
}

impl PseudoHeader {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Method => ":method",
            Self::Scheme => ":scheme",
            Self::Authority => ":authority",
            Self::Path => ":path",
            Self::Protocol => ":protocol",
            Self::Status => ":status",
        }
    }
}

impl fmt::Display for PseudoHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

rama_utils::macros::error::static_str_error! {
    #[doc = "pseudo header string is invalid"]
    pub struct InvalidPseudoHeaderStr;
}

impl FromStr for PseudoHeader {
    type Err = InvalidPseudoHeaderStr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s.strip_prefix(':').unwrap_or(s);

        if s.eq_ignore_ascii_case("method") {
            Ok(Self::Method)
        } else if s.eq_ignore_ascii_case("scheme") {
            Ok(Self::Scheme)
        } else if s.eq_ignore_ascii_case("authority") {
            Ok(Self::Authority)
        } else if s.eq_ignore_ascii_case("path") {
            Ok(Self::Path)
        } else if s.eq_ignore_ascii_case("protocol") {
            Ok(Self::Protocol)
        } else if s.eq_ignore_ascii_case("status") {
            Ok(Self::Status)
        } else {
            Err(InvalidPseudoHeaderStr)
        }
    }
}

impl Serialize for PseudoHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PseudoHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <std::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(D::Error::custom)
    }
}

const PSEUDO_HEADERS_STACK_SIZE: usize = 5;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PseudoHeaderOrder {
    headers: SmallVec<[PseudoHeader; PSEUDO_HEADERS_STACK_SIZE]>,
    mask: u8,
}

impl PseudoHeaderOrder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, header: PseudoHeader) {
        if self.mask & (header as u8) == 0 {
            self.mask |= header as u8;
            self.headers.push(header);
        } else {
            tracing::trace!("ignore duplicate psuedo header: {header:?}")
        }
    }

    pub fn extend(&mut self, iter: impl IntoIterator<Item = PseudoHeader>) {
        for header in iter {
            self.push(header);
        }
    }

    #[must_use]
    pub fn iter(&self) -> PseudoHeaderOrderIter {
        self.clone().into_iter()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }
}

impl IntoIterator for PseudoHeaderOrder {
    type Item = PseudoHeader;
    type IntoIter = PseudoHeaderOrderIter;

    fn into_iter(self) -> Self::IntoIter {
        let Self { mut headers, .. } = self;
        headers.reverse();
        PseudoHeaderOrderIter { headers }
    }
}

impl FromIterator<PseudoHeader> for PseudoHeaderOrder {
    fn from_iter<T: IntoIterator<Item = PseudoHeader>>(iter: T) -> Self {
        let mut this = Self::new();
        for header in iter {
            this.push(header);
        }
        this
    }
}

impl<'a> FromIterator<&'a PseudoHeader> for PseudoHeaderOrder {
    fn from_iter<T: IntoIterator<Item = &'a PseudoHeader>>(iter: T) -> Self {
        let mut this = Self::new();
        for header in iter {
            this.push(*header);
        }
        this
    }
}

#[derive(Debug)]
/// Iterator over a copy of [`PseudoHeaderOrder`].
pub struct PseudoHeaderOrderIter {
    headers: SmallVec<[PseudoHeader; PSEUDO_HEADERS_STACK_SIZE]>,
}

impl Iterator for PseudoHeaderOrderIter {
    type Item = PseudoHeader;

    fn next(&mut self) -> Option<Self::Item> {
        self.headers.pop()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.headers.len()))
    }

    fn count(self) -> usize
    where
        Self: Sized,
    {
        self.headers.len()
    }
}

impl Serialize for PseudoHeaderOrder {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.headers.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PseudoHeaderOrder {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = <Vec<PseudoHeader>>::deserialize(deserializer)?;
        Ok(v.into_iter().collect())
    }
}
