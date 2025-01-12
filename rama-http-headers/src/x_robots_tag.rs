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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::x_robots_tag_components::MaxImagePreviewSetting;
    use chrono::{DateTime, Utc};

    macro_rules! test_header {
        ($name: ident, $input: expr, $expected: expr) => {
            #[test]
            fn $name() {
                let decoded = XRobotsTag::decode(
                    &mut $input
                        .into_iter()
                        .map(|s| HeaderValue::from_bytes(s).unwrap())
                        .collect::<Vec<_>>()
                        .iter(),
                )
                .ok();
                assert_eq!(decoded, $expected,);
            }
        };
    }

    test_header!(
        one_rule,
        vec![b"noindex"],
        Some(XRobotsTag(vec![RobotsTag::builder().no_index().build()]))
    );

    test_header!(
        one_composite_rule,
        vec![b"max-snippet: 2025"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .max_snippet(2025)
            .build()]))
    );

    test_header!(
        multiple_rules,
        vec![b"noindex, nofollow, nosnippet"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .no_index()
            .no_follow()
            .no_snippet()
            .build()]))
    );

    test_header!(
        multiple_rules_with_composite,
        vec![b"max-video-preview: -1, noindex, nofollow, max-snippet: 2025, max-image-preview: standard"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .max_video_preview(None)
            .no_index()
            .no_follow()
            .max_snippet(2025)
            .max_image_preview(MaxImagePreviewSetting::Standard)
            .build()]))
    );

    test_header!(
        one_bot_one_rule,
        vec![b"google_bot: noindex"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .bot_name("google_bot".parse().unwrap())
            .no_index()
            .build()]))
    );

    test_header!(
        one_bot_one_composite_rule,
        vec![b"google_bot: max-video-preview: 0"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .bot_name("google_bot".parse().unwrap())
            .max_video_preview(Some(0))
            .build()]))
    );

    test_header!(
        one_bot_multiple_rules,
        vec![b"google_bot: noindex, nosnippet"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .bot_name("google_bot".parse().unwrap())
            .no_index()
            .no_snippet()
            .build()]))
    );

    test_header!(
        one_bot_multiple_rules_with_composite,
        vec![b"google_bot: max-video-preview: -1, noindex, nofollow, max-snippet: 2025, max-image-preview: standard"],
        Some(XRobotsTag(vec![RobotsTag::builder()
            .bot_name("google_bot".parse().unwrap())
            .max_video_preview(None)
            .no_index()
            .no_follow()
            .max_snippet(2025)
            .max_image_preview(MaxImagePreviewSetting::Standard)
            .build()]))
    );

    test_header!(
        multiple_bots_one_rule,
        vec![b"google_bot: noindex, BadBot: nofollow"],
        Some(XRobotsTag(vec![
            RobotsTag::builder()
                .bot_name("google_bot".parse().unwrap())
                .no_index()
                .build(),
            RobotsTag::builder()
                .bot_name("BadBot".parse().unwrap())
                .no_follow()
                .build()
        ]))
    );

    test_header!(
        multiple_bots_one_composite_rule,
        vec![b"google_bot: unavailable_after: 2025-02-18T08:25:15Z, BadBot: max-image-preview: large"],
        Some(XRobotsTag(vec![
            RobotsTag::builder()
                .bot_name("google_bot".parse().unwrap())
                .unavailable_after(DateTime::parse_from_rfc3339("2025-02-18T08:25:15Z")
                    .unwrap()
                    .with_timezone(&Utc))
                .build(),
            RobotsTag::builder()
                .bot_name("BadBot".parse().unwrap())
                .max_image_preview(MaxImagePreviewSetting::Large)
                .build()
        ]))
    );

    test_header!(
        multiple_bots_multiple_rules,
        vec![b"google_bot: none, indexifembedded, BadBot: nofollow, noai, spc"],
        Some(XRobotsTag(vec![
            RobotsTag::builder()
                .bot_name("google_bot".parse().unwrap())
                .none()
                .index_if_embedded()
                .build(),
            RobotsTag::builder()
                .bot_name("BadBot".parse().unwrap())
                .no_follow()
                .no_ai()
                .spc()
                .build()
        ]))
    );

    test_header!(
        multiple_bots_multiple_rules_with_composite,
        vec![
            b"google_bot: max-snippet: 8, notranslate, max-image-preview: none,\
        BadBot: max-video-preview: 2025, noimageindex, max-snippet: 0"
        ],
        Some(XRobotsTag(vec![
            RobotsTag::builder()
                .bot_name("google_bot".parse().unwrap())
                .max_snippet(8)
                .no_translate()
                .max_image_preview(MaxImagePreviewSetting::None)
                .build(),
            RobotsTag::builder()
                .bot_name("BadBot".parse().unwrap())
                .max_video_preview(Some(2025))
                .no_image_index()
                .max_snippet(0)
                .build()
        ]))
    );
}
