use crate::headers::x_robots_tag_components::robots_tag_components::Parser;
use crate::headers::x_robots_tag_components::RobotsTag;
use crate::headers::Error;
use headers::Header;
use http::{HeaderName, HeaderValue};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XRobotsTag(Vec<RobotsTag>);

impl Header for XRobotsTag {
    fn name() -> &'static HeaderName {
        &crate::header::X_ROBOTS_TAG
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let elements = values.try_fold(Vec::new(), |mut acc, value| {
            acc.extend(Parser::parse_value(value).map_err(|err| {
                tracing::debug!(?err, "x-robots-tag header element decoding failure");
                Error::invalid()
            })?);

            Ok(acc)
        })?;

        Ok(XRobotsTag(elements))
    }

    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        use std::fmt;
        struct Format<F>(F);
        impl<F> fmt::Display for Format<F>
        where
            F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result,
        {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0(f)
            }
        }
        let s = format!(
            "{}",
            Format(|f: &mut fmt::Formatter<'_>| {
                crate::headers::util::csv::fmt_comma_delimited(&mut *f, self.0.iter())
            })
        );
        values.extend(Some(HeaderValue::from_str(&s).unwrap()))
    }
}

impl FromIterator<RobotsTag> for XRobotsTag {
    fn from_iter<T: IntoIterator<Item = RobotsTag>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}
