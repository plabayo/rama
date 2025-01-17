mod rule;

mod element;

mod element_iter;

mod valid_date;

// ----------------------------------------------- \\

use crate::headers::Header;
use element::Element;
use element_iter::ElementIter;
use http::{HeaderName, HeaderValue};
use std::fmt::Formatter;
use std::iter::Iterator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XRobotsTag(Vec<Element>);

impl Header for XRobotsTag {
    fn name() -> &'static HeaderName {
        &crate::header::X_ROBOTS_TAG
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        todo!();
        crate::headers::util::csv::from_comma_delimited(values).map(XRobotsTag) // wouldn't really work, need more complex logic
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        use std::fmt;
        struct Format<F>(F);
        impl<F> fmt::Display for Format<F>
        where
            F: Fn(&mut Formatter<'_>) -> fmt::Result,
        {
            fn fmt(&self, f: &mut Formatter) -> fmt::Result {
                self.0(f)
            }
        }
        let s = format!(
            "{}",
            Format(|f: &mut Formatter<'_>| {
                crate::headers::util::csv::fmt_comma_delimited(&mut *f, self.0.iter())
            })
        );
        values.extend(Some(HeaderValue::from_str(&s).unwrap()))
    }
}

impl FromIterator<Element> for XRobotsTag {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = Element>,
    {
        XRobotsTag(iter.into_iter().collect())
    }
}

impl IntoIterator for XRobotsTag {
    type Item = Element;
    type IntoIter = ElementIter;

    fn into_iter(self) -> Self::IntoIter {
        ElementIter::new(self.0.into_iter())
    }
}
