use super::FragmentMergeMode;
use crate::sse::{
    Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType, parser::is_lf,
};
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};
use smol_str::SmolStr;
use std::borrow::Cow;

/// [`MergeFragments`] merges one or more fragments into the DOM.
///
/// By default, Datastar merges fragments using Idiomorph,
/// which matches top level elements based on their ID.
///
/// See the [Datastar documentation](https://data-star.dev/reference/sse_events#datastar-merge-fragments)
/// for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeFragments {
    /// The HTML fragments to merge into the DOM.
    pub fragments: Cow<'static, str>,
    /// The CSS selector used to insert the fragments.
    ///
    /// If not provided, Datastar will default to using the id attribute of the fragment.
    pub selector: Option<SmolStr>,
    /// The mode to use when merging the fragment into the DOM.
    ///
    /// If not provided the Datastar client side will default to [`FragmentMergeMode::Morph`].
    pub merge_mode: FragmentMergeMode,
    /// Whether to use view transitions.
    ///
    /// If not provided the Datastar client side will default to `false`.
    pub use_view_transition: bool,
}

impl MergeFragments {
    pub const TYPE: EventType = EventType::MergeFragments;

    /// Create a new [`MergeFragments`] data blob.
    pub fn new(fragments: impl Into<Cow<'static, str>>) -> Self {
        Self {
            fragments: fragments.into(),
            selector: None,
            merge_mode: Default::default(),
            use_view_transition: false,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<MergeFragments> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
            .with_retry(super::consts::DEFAULT_DATASTAR_DURATION)
            .with_data(self)
    }

    /// Consume `self` as a [`super::DatastarEvent`].
    pub fn into_datastar_event<T>(self) -> super::DatastarEvent<T> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
            .with_retry(super::consts::DEFAULT_DATASTAR_DURATION)
            .with_data(super::EventData::MergeFragments(self))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the CSS selector used to insert the fragments.
        pub fn selector(mut self, selector: impl Into<SmolStr>) -> Self {
            self.selector = Some(selector.into());
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set mode to use when merging the fragment into the DOM.
        pub fn merge_mode(mut self, mode: FragmentMergeMode) -> Self {
            self.merge_mode = mode;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to use view transitions.
        pub fn use_view_transition(mut self, use_view_transition: bool) -> Self {
            self.use_view_transition = use_view_transition;
            self
        }
    }
}

impl From<MergeFragments> for Event<MergeFragments> {
    fn from(value: MergeFragments) -> Self {
        value.into_sse_event()
    }
}

impl<T> From<MergeFragments> for super::DatastarEvent<T> {
    fn from(value: MergeFragments) -> Self {
        value.into_datastar_event()
    }
}

impl EventDataWrite for MergeFragments {
    #[allow(clippy::write_with_newline)]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        if let Some(selector) = &self.selector {
            write!(w, "selector {}\n", selector).context("MergeFragments: write selector")?;
        }

        if self.merge_mode != FragmentMergeMode::default() {
            write!(w, "mergeMode {}\n", self.merge_mode)
                .context("MergeFragments: write merge mode")?;
        }

        if self.use_view_transition {
            w.write_all(b"useViewTransition true\n")
                .context("MergeFragments: write view transition usage")?;
        }

        let mut fragments = self.fragments.lines();
        let mut next_fragment = fragments
            .next()
            .context("MergeFragments: no fragments specified")?;
        for fragment in fragments {
            write!(w, "fragments {}\n", next_fragment)
                .context("MergeFragments: write fragments")?;
            next_fragment = fragment;
        }
        write!(w, "fragments {}", next_fragment).context("MergeFragments: write last fragments")?;

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`MergeFragments`].
#[derive(Debug)]
pub struct MergeFragmentsReader(Option<MergeFragments>);

impl EventDataRead for MergeFragments {
    type Reader = MergeFragmentsReader;

    fn line_reader() -> Self::Reader {
        MergeFragmentsReader(None)
    }
}

impl EventDataLineReader for MergeFragmentsReader {
    type Data = MergeFragments;

    fn read_line(&mut self, line: &str) -> Result<(), OpaqueError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        };

        let merge_fragments = self
            .0
            .get_or_insert_with(|| MergeFragments::new(Cow::Owned(Default::default())));

        let (keyword, value) = line
            .split_once(' ')
            // in case of empty value
            .unwrap_or((line, ""));

        if keyword.eq_ignore_ascii_case("selector") {
            if value.is_empty() {
                tracing::trace!("ignore selector property with empty value");
            } else {
                merge_fragments.selector = Some(value.into());
            }
        } else if keyword.eq_ignore_ascii_case("mergeMode") {
            if value.is_empty() {
                tracing::trace!("ignore mergeMode property with empty value");
            } else {
                merge_fragments.merge_mode = value.into();
            }
        } else if keyword.eq_ignore_ascii_case("useViewTransition") {
            merge_fragments.use_view_transition = value
                .parse()
                .context("MergeFragmentsReader: parse useViewTransition")?;
        } else if keyword.eq_ignore_ascii_case("fragments") {
            let fragments = merge_fragments.fragments.to_mut();
            fragments.push_str(value);
            fragments.push('\n');
        } else {
            tracing::debug!(
                "MergeFragmentsReader: ignore unknown merge fragment line: keyword = {}; value = {}",
                keyword,
                value,
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        let mut merge_fragments = match self.0.take() {
            Some(fragments) => fragments,
            None => return Ok(None),
        };

        if !event
            .and_then(|e| {
                e.parse::<EventType>()
                    .ok()
                    .map(|t| t == EventType::MergeFragments)
            })
            .unwrap_or_default()
        {
            return Err(OpaqueError::from_display(
                "MergeFragmentsReader: unexpected event type: expected: datastar-merge-fragments",
            ));
        }

        if merge_fragments
            .fragments
            .chars()
            .next_back()
            .map(is_lf)
            .unwrap_or_default()
        {
            merge_fragments.fragments.to_mut().pop();
        }
        if merge_fragments.fragments.is_empty() {
            return Err(OpaqueError::from_display(
                "merge fragments contains no fragments",
            ));
        }

        Ok(Some(merge_fragments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_merge_fragments(input: &str) -> MergeFragments {
        let mut reader = MergeFragments::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some("datastar-merge-fragments"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_deserialize_minimal() {
        let data = read_merge_fragments(r##"fragments <div id="foo">Hello, world!</div>"##);
        assert_eq!(data.fragments, r##"<div id="foo">Hello, world!</div>"##);
        assert_eq!(data.merge_mode, FragmentMergeMode::Morph);
        assert_eq!(data.selector, None);
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let expected_data = MergeFragments::new("<div>\nHello, world!\n</div>")
            .with_selector("#foo")
            .with_merge_mode(FragmentMergeMode::Append)
            .with_use_view_transition(true);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_merge_fragments(&input);

        assert_eq!(expected_data, data);
    }
}
