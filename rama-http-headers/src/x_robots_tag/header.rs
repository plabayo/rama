use crate::{Error, HeaderDecode, HeaderEncode, TypedHeader, x_robots_tag::robots_tag_parse_iter};

use super::RobotsTag;
use rama_core::{bytes::Bytes, telemetry::tracing};
use rama_http_types::{HeaderName, HeaderValue};
use rama_utils::{collections::NonEmptyVec, macros::generate_set_and_with};
use std::fmt::Write as _;

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct XRobotsTag(pub NonEmptyVec<RobotsTag>);

impl TypedHeader for XRobotsTag {
    fn name() -> &'static HeaderName {
        &rama_http_types::header::X_ROBOTS_TAG
    }
}

impl XRobotsTag {
    #[inline(always)]
    pub fn new(tag: RobotsTag) -> Self {
        Self(NonEmptyVec::new(tag))
    }

    generate_set_and_with! {
        /// Set provided header in the header map
        /// Warning: this function will replace already existing headers
        /// If more control is needed, use `.header_map()` or `.header_map_raw()`
        /// to get access to the underlying header map
        pub fn additional_tag(
            mut self,
            tag: RobotsTag,
        ) -> Self {
            self.0.push(tag);
            self
        }
    }

    #[must_use]
    pub fn into_first_tag(self) -> RobotsTag {
        self.0.head
    }

    #[must_use]
    pub fn first_tag(&self) -> &RobotsTag {
        self.0.first()
    }
}

impl HeaderDecode for XRobotsTag {
    fn decode<'i, I>(values: &mut I) -> Result<Self, Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i HeaderValue>,
    {
        let elements = values.try_fold(None, |mut acc, value| {
            for result in robots_tag_parse_iter(value.as_bytes()) {
                match result {
                    Ok(extra) => match acc {
                        None => acc = Some(NonEmptyVec::new(extra)),
                        Some(ref mut acc) => acc.push(extra),
                    },
                    Err(err) => {
                        tracing::debug!(?err, "x-robots-tag header element decoding failure");
                        return Err(Error::invalid());
                    }
                }
            }
            Ok(acc)
        })?;

        if let Some(elements) = elements {
            Ok(Self(elements))
        } else {
            tracing::debug!("no values founds for x-robots-tag header");
            Err(Error::invalid())
        }
    }
}

impl HeaderEncode for XRobotsTag {
    fn encode<E: Extend<HeaderValue>>(&self, values: &mut E) {
        let mut s = String::new();
        // `to_string` panics on a Display error, so write fallibly instead
        if let Err(err) = write!(
            s,
            "{}",
            rama_utils::fmt::display_fn(|f: &mut std::fmt::Formatter<'_>| {
                // a bot key scopes every directive after it, so unscoped tags go first
                let unscoped = self.0.iter().filter(|tag| tag.bot_name().is_none());
                let scoped = self.0.iter().filter(|tag| tag.bot_name().is_some());
                crate::util::csv::fmt_comma_delimited(&mut *f, unscoped.chain(scoped))
            })
        ) {
            tracing::debug!("failed to format x-robots-tag: {err}");
            return;
        }
        // decoded values may carry obs-text, which `try_from(String)` rejects
        match HeaderValue::from_maybe_shared(Bytes::from(s)) {
            Ok(v) => values.extend(::std::iter::once(v)),
            Err(err) => {
                tracing::debug!("failed to encode x-robots-tag as header value: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rama_utils::collections::non_empty_vec;

    use super::*;
    use crate::{
        util::HeaderValueString,
        x_robots_tag::{DirectiveDateTime, MaxImagePreviewSetting},
    };

    #[test]
    #[::tracing_test::traced_test]
    fn test_to_header_value_string_examples_simple() {
        for (header_value, expected) in [
            (XRobotsTag::new(RobotsTag::new_no_index()), "noindex"),
            (
                XRobotsTag::new(RobotsTag::new_no_image_index().with_unavailable_after(
                    DirectiveDateTime::try_new_ymd_and_hms(2025, 12, 3, 13, 9, 53).unwrap(),
                )),
                "noimageindex, unavailable_after: Wed, 3 Dec 2025 13:09:53 +0000",
            ),
            (
                XRobotsTag::new(
                    RobotsTag::new_no_index_for_bot(HeaderValueString::from_static("BadBot"))
                        .with_no_follow(true),
                )
                .with_additional_tag(RobotsTag::new_no_follow_for_bot(
                    HeaderValueString::from_static("googlebot"),
                )),
                "BadBot: noindex, nofollow, googlebot: nofollow",
            ),
        ] {
            let value = header_value.encode_to_value().unwrap();
            let s = value.to_str().unwrap();
            assert_eq!(expected, s);
        }
    }

    #[test]
    fn test_multi_line_tags_round_trip() {
        let line = HeaderValue::from_str(&vec!["a"; 2049].join(",")).unwrap();
        let header = XRobotsTag::decode(&mut [line.clone(), line].iter()).unwrap();
        let encoded = header.encode_to_value().unwrap();
        XRobotsTag::decode(&mut [encoded].iter()).unwrap();
    }

    #[test]
    fn test_encode_keeps_unscoped_directives_global() {
        let values = [
            HeaderValue::from_static("googlebot: noindex"),
            HeaderValue::from_static("nofollow"),
        ];
        let header = XRobotsTag::decode(&mut values.iter()).unwrap();
        let encoded = header.encode_to_value().unwrap();
        let again = XRobotsTag::decode(&mut [encoded].iter()).unwrap();
        let global = again.0.iter().find(|tag| tag.bot_name().is_none()).unwrap();
        assert!(global.no_follow());
        let googlebot = again.0.iter().find(|tag| tag.bot_name().is_some()).unwrap();
        assert!(googlebot.no_index());
        assert!(!googlebot.no_follow());
    }

    #[test]
    fn test_empty_line_keeps_other_lines() {
        let values = [
            HeaderValue::from_static("noindex"),
            HeaderValue::from_static(","),
        ];
        let header = XRobotsTag::decode(&mut values.iter()).unwrap();
        assert!(header.first_tag().no_index());
    }

    #[test]
    fn test_obs_text_round_trips() {
        let value = HeaderValue::from_bytes("max-image-preview: é, noindex".as_bytes()).unwrap();
        let header = XRobotsTag::decode(&mut [value].iter()).unwrap();
        let encoded = header.encode_to_value().unwrap();
        assert_eq!(XRobotsTag::decode(&mut [encoded].iter()).unwrap(), header);
    }

    #[test]
    fn test_encode_decoded_out_of_rfc2822_range_date_no_panic() {
        let value = HeaderValue::from_static("unavailable_after: 1 Jan 0000 00:00:00 +0100");
        let header = XRobotsTag::decode(&mut [value].iter()).unwrap();
        assert!(header.first_tag().unavailable_after().is_some());
        let encoded = header.encode_to_value().unwrap();
        let reencoded = XRobotsTag::decode(&mut [encoded].iter()).unwrap();
        assert_eq!(
            header.first_tag().unavailable_after().unwrap().date_time(),
            reencoded
                .first_tag()
                .unavailable_after()
                .unwrap()
                .date_time(),
        );
    }

    macro_rules! test_header {
        ($name: ident, $input: expr, $expected: expr) => {
            #[test]
            #[::tracing_test::traced_test]
            fn $name() {
                let decoded = XRobotsTag::decode(
                    &mut $input
                        .into_iter()
                        .map(|s| HeaderValue::from_bytes(s).unwrap())
                        .collect::<Vec<_>>()
                        .iter(),
                )
                .inspect_err(|err| tracing::error!("failed to decode robots tag: {err}"))
                .ok();
                assert_eq!(decoded, $expected);
            }
        };
    }

    test_header!(
        one_rule,
        vec![b"noindex"],
        Some(XRobotsTag::new(RobotsTag::new_no_index()))
    );

    test_header!(
        one_composite_rule,
        vec![b"max-snippet: 2025"],
        Some(XRobotsTag::new(RobotsTag::new_max_snippet(2025)))
    );

    test_header!(
        multiple_rules,
        vec![b"noindex, nofollow, nosnippet"],
        Some(XRobotsTag::new(
            RobotsTag::new_no_index()
                .with_no_follow(true)
                .with_no_snippet(true)
        ))
    );

    test_header!(
            multiple_rules_with_composite,
            vec![b"max-video-preview: -1, noindex, nofollow, max-snippet: 2025, max-image-preview: standard"],
            Some(XRobotsTag::new(RobotsTag::new_max_video_preview(-1)
                .with_no_index(true)
                .with_no_follow(true)
                .with_max_snippet(2025)
                .with_max_image_preview(MaxImagePreviewSetting::Standard)))
        );

    test_header!(
        one_bot_one_rule,
        vec![b"google_bot: noindex"],
        Some(XRobotsTag::new(RobotsTag::new_no_index_for_bot(
            HeaderValueString::from_static("google_bot")
        )))
    );

    test_header!(
        one_bot_one_composite_rule,
        vec![b"google_bot: max-video-preview: 0"],
        Some(XRobotsTag::new(RobotsTag::new_max_video_preview_for_bot(
            0,
            HeaderValueString::from_static("google_bot")
        )))
    );

    test_header!(
        one_bot_multiple_rules,
        vec![b"google_bot: noindex, nosnippet"],
        Some(XRobotsTag::new(
            RobotsTag::new_no_index_for_bot(HeaderValueString::from_static("google_bot"))
                .with_no_snippet(true)
        ))
    );

    test_header!(
            one_bot_multiple_rules_with_composite,
            vec![b"google_bot: max-video-preview: -1, noindex, nofollow, max-snippet: 2025, max-image-preview: standard"],
            Some(XRobotsTag::new(RobotsTag::new_max_video_preview_for_bot(-1, HeaderValueString::from_static("google_bot"))
                .with_no_index(true)
                .with_no_follow(true)
                .with_max_snippet(2025)
                .with_max_image_preview(MaxImagePreviewSetting::Standard)))
        );

    test_header!(
        multiple_bots_one_rule,
        vec![b"google_bot: noindex, BadBot: nofollow"],
        Some(XRobotsTag(non_empty_vec![
            RobotsTag::new_no_index_for_bot(HeaderValueString::from_static("google_bot")),
            RobotsTag::new_no_follow_for_bot(HeaderValueString::from_static("BadBot")),
        ]))
    );

    test_header!(
            multiple_bots_one_composite_rule,
            vec![b"google_bot: unavailable_after: 2025-02-18T08:25:15+00:00, BadBot: max-image-preview: large"],
            Some(XRobotsTag(non_empty_vec![
                RobotsTag::new_unavailable_after_for_bot(DirectiveDateTime::try_new_ymd_and_hms(2025, 2, 18, 8, 25, 15).unwrap().with_format_rfc3339(), HeaderValueString::from_static("google_bot")),
                RobotsTag::new_max_image_preview_for_bot(MaxImagePreviewSetting::Large, HeaderValueString::from_static("BadBot")),
            ]))
        );

    test_header!(
        multiple_bots_multiple_rules,
        vec![b"google_bot: none, indexifembedded, BadBot: nofollow, noai, spc"],
        Some(XRobotsTag(non_empty_vec![
            RobotsTag::new_none_for_bot(HeaderValueString::from_static("google_bot"))
                .with_index_if_embedded(true),
            RobotsTag::new_no_follow_for_bot(HeaderValueString::from_static("BadBot"))
                .with_no_ai(true)
                .with_spc(true),
        ]))
    );

    test_header!(
        multiple_bots_multiple_rules_with_composite,
        vec![
            b"google_bot: max-snippet: 8, notranslate, max-image-preview: none,\
            BadBot: max-video-preview: 2025, noimageindex, max-snippet: 0"
        ],
        Some(XRobotsTag(non_empty_vec![
            RobotsTag::new_max_snippet_for_bot(8, HeaderValueString::from_static("google_bot"))
                .with_no_translate(true)
                .with_max_image_preview(MaxImagePreviewSetting::None),
            RobotsTag::new_max_video_preview_for_bot(
                2025,
                HeaderValueString::from_static("BadBot")
            )
            .with_no_image_index(true)
            .with_max_snippet(0),
        ]))
    );
}
