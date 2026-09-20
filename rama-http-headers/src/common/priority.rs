//! Extensible HTTP priorities (RFC 9218). Unknown dictionary members are validated and ignored.

use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader};
use rama_http_types::{HeaderName, HeaderValue};
use sfv::{
    BareItemFromInput, KeyRef, Parser,
    visitor::{
        DictionaryVisitor, EntryVisitor, Ignored, InnerListVisitor, ItemVisitor, ParameterVisitor,
    },
};
use std::convert::Infallible;

/// HTTP urgency and incremental-delivery preference, independent of protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    urgency: u8,
    incremental: bool,
}
impl Default for Priority {
    fn default() -> Self {
        Self {
            urgency: 3,
            incremental: false,
        }
    }
}
impl Priority {
    /// Construct a priority. Urgency must be in the inclusive range 0–7.
    #[must_use]
    pub const fn new(urgency: u8, incremental: bool) -> Option<Self> {
        if urgency > 7 {
            None
        } else {
            Some(Self {
                urgency,
                incremental,
            })
        }
    }
    /// Urgency, with zero being most urgent.
    #[must_use]
    pub const fn urgency(self) -> u8 {
        self.urgency
    }
    /// Whether useful processing can proceed incrementally.
    #[must_use]
    pub const fn incremental(self) -> bool {
        self.incremental
    }
    /// Parse a complete Priority field value, including unknown structured members.
    /// Invalid known parameter types/ranges use their defaults; malformed syntax fails.
    pub fn parse(value: &[u8]) -> Result<Self, Error> {
        let mut priority = Self::default();
        Parser::new(value)
            .parse_dictionary_with_visitor(&mut priority)
            .map_err(|_error| Error::invalid())?;
        Ok(priority)
    }
    /// Canonical field value. All possible combinations use static storage.
    #[must_use]
    pub fn field_value(self) -> HeaderValue {
        const PLAIN: [&str; 8] = ["u=0", "u=1", "u=2", "u=3", "u=4", "u=5", "u=6", "u=7"];
        const INCREMENTAL: [&str; 8] = [
            "u=0, i", "u=1, i", "u=2, i", "u=3, i", "u=4, i", "u=5, i", "u=6, i", "u=7, i",
        ];
        HeaderValue::from_static(if self.incremental {
            INCREMENTAL[self.urgency as usize]
        } else {
            PLAIN[self.urgency as usize]
        })
    }
}

struct Value<'a> {
    priority: &'a mut Priority,
    urgency: bool,
}
impl<'de> DictionaryVisitor<'de> for &mut Priority {
    type Out = ();
    type Error = Infallible;
    fn entry(&mut self, key: &'de KeyRef) -> Result<impl EntryVisitor<'de>, Infallible> {
        // Structured dictionaries use the last occurrence, including invalid typed values.
        Ok(match key.as_str() {
            "u" => {
                self.urgency = 3;
                Some(Value {
                    priority: self,
                    urgency: true,
                })
            }
            "i" => {
                self.incremental = false;
                Some(Value {
                    priority: self,
                    urgency: false,
                })
            }
            _ => None,
        })
    }
    fn finish(self) -> Result<(), Infallible> {
        Ok(())
    }
}
impl<'de> EntryVisitor<'de> for Value<'_> {
    type Error = Infallible;
    fn item(self) -> Result<impl ItemVisitor<'de>, Infallible> {
        Ok(self)
    }
    fn inner_list(self) -> Result<impl InnerListVisitor<'de>, Infallible> {
        Ok(Ignored)
    }
}
impl<'de> ItemVisitor<'de> for Value<'_> {
    type Out = ();
    type Error = Infallible;
    fn bare_item(
        self,
        item: BareItemFromInput<'de>,
    ) -> Result<impl ParameterVisitor<'de, Out = ()>, Infallible> {
        if self.urgency {
            if let Some(value) = item
                .as_integer()
                .and_then(|v| u8::try_from(v).ok())
                .filter(|v| *v <= 7)
            {
                self.priority.urgency = value;
            }
        } else if let Some(value) = item.as_boolean() {
            self.priority.incremental = value;
        }
        Ok(Ignored)
    }
}
impl TypedHeader for Priority {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("priority");
        &NAME
    }
}
impl HeaderDecode for Priority {
    fn decode<'i, I: Iterator<Item = &'i HeaderValue>>(values: &mut I) -> Result<Self, Error> {
        let first = values.next().ok_or_else(Error::invalid)?;
        let Some(second) = values.next() else {
            return Self::parse(first.as_bytes());
        };
        let mut combined = Vec::from(first.as_bytes());
        for value in std::iter::once(second).chain(values) {
            combined.extend_from_slice(b", ");
            combined.extend_from_slice(value.as_bytes());
        }
        Self::parse(&combined)
    }
}
impl HeaderEncode for Priority {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        values.extend(std::iter::once(self.field_value()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structured_priority_syntax_and_last_value() {
        assert_eq!(
            Priority::parse(b"u=1, i").unwrap(),
            Priority::new(1, true).unwrap()
        );
        assert_eq!(
            Priority::parse(b"u=1, u=99, i, i=wrong").unwrap(),
            Priority::default()
        );
        assert_eq!(
            Priority::parse(b"x=(\"a,b\" token);p=?1, u=7, i=?0").unwrap(),
            Priority::new(7, false).unwrap()
        );
        assert_eq!(Priority::parse(b"u=1, u=(2)").unwrap(), Priority::default());
        Priority::parse(b"u=1, x=\"unterminated").unwrap_err();
        for urgency in 0..8 {
            for incremental in [false, true] {
                let priority = Priority::new(urgency, incremental).unwrap();
                assert_eq!(
                    Priority::parse(priority.field_value().as_bytes()).unwrap(),
                    priority
                );
            }
        }
    }
}
