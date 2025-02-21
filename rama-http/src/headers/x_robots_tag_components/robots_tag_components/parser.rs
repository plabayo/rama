use crate::headers::x_robots_tag_components::robots_tag_components::Builder;
use crate::headers::x_robots_tag_components::RobotsTag;
use http::HeaderValue;
use rama_core::error::OpaqueError;

pub(crate) struct Parser<'a> {
    remaining: Option<&'a str>,
}

impl<'a> Parser<'a> {
    pub(crate) fn new(remaining: &'a str) -> Self {
        let remaining = match remaining.trim() {
            "" => None,
            text => Some(text),
        };

        Self { remaining }
    }
}

impl<'a> Iterator for Parser<'_> {
    type Item = Result<RobotsTag, OpaqueError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut remaining = self.remaining?.trim();
        if remaining.is_empty() {
            return None;
        }

        let mut builder = Self::parse_first(&mut remaining).ok()?;

        while let Some((field, rest)) = remaining.split_once(',') {
            match builder.add_field(field) {
                Ok(_) => {
                    remaining = rest;
                }
                Err(e) if e.is::<headers::Error>() => {
                    self.remaining = Some(remaining.trim());
                    return Some(Ok(builder.build()));
                }
                Err(e) => return Some(Err(e)),
            }
        }

        match builder.add_field(remaining) {
            Ok(_) => {
                self.remaining = None;
                Some(Ok(builder.build()))
            }
            Err(e) if e.is::<headers::Error>() => {
                self.remaining = Some(remaining.trim());
                Some(Ok(builder.build()))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

impl Parser<'_> {
    fn parse_first(remaining: &mut &str) -> Result<Builder<RobotsTag>, OpaqueError> {
        match remaining.find(&[':', ',']) {
            Some(index) if remaining.chars().nth(index) == Some(',') => {
                let builder = RobotsTag::builder().add_field(&remaining[..index])?;
                *remaining = &remaining[index + 1..];
                Ok(builder)
            }
            Some(colon_index) if remaining.chars().nth(colon_index) == Some(':') => {
                let (field, rest) = if let Some((before, after)) = remaining.split_once(',') {
                    (before, after)
                } else {
                    (*remaining, "")
                };

                let builder = match RobotsTag::builder().add_field(field) {
                    Ok(builder) => Ok(builder),
                    Err(e) if e.is::<headers::Error>() => RobotsTag::builder()
                        .bot_name(
                            remaining[..colon_index]
                                .trim()
                                .parse()
                                .map_err(OpaqueError::from_std)?,
                        )
                        .add_field(&field[colon_index + 1..]),
                    Err(e) => Err(e),
                };
                *remaining = rest;
                builder
            }
            _ => {
                let builder = RobotsTag::builder().add_field(&remaining)?;
                *remaining = "";
                Ok(builder)
            }
        }
    }

    pub(crate) fn parse_value(value: &HeaderValue) -> Result<Vec<RobotsTag>, OpaqueError> {
        Parser::new(value.to_str().map_err(OpaqueError::from_std)?).collect::<Result<Vec<_>, _>>()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::{DateTime, Utc};

    macro_rules! test_parse_first {
        ($name:ident, $remaining:literal, $expected:expr) => {
            #[test]
            fn $name() {
                let mut remaining = $remaining;
                assert_eq!(Parser::parse_first(&mut remaining).unwrap(), $expected);
                assert_eq!(remaining, $remaining.split_once(',').unwrap_or(("", "")).1);
            }
        };
    }

    test_parse_first!(one_tag, "nofollow", RobotsTag::builder().no_follow());

    test_parse_first!(
        multiple_tags,
        "nofollow, nosnippet",
        RobotsTag::builder().no_follow()
    );

    test_parse_first!(
        one_tag_composite,
        "google_bot: nofollow",
        RobotsTag::builder()
            .bot_name("google_bot".parse().unwrap())
            .no_follow()
    );

    test_parse_first!(
        multiple_tags_with_composite,
        "google_bot: nofollow, nosnippet",
        RobotsTag::builder()
            .bot_name("google_bot".parse().unwrap())
            .no_follow()
    );

    test_parse_first!(
        unavailable_after,
        "unavailable_after: 2025-02-18T08:25:15Z",
        RobotsTag::builder().unavailable_after(
            DateTime::parse_from_rfc3339("2025-02-18T08:25:15Z")
                .unwrap()
                .with_timezone(&Utc)
        )
    );
}
