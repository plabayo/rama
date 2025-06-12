use crate::sse::{Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType};
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};
use smol_str::SmolStr;

/// [`RemoveFragments`] sends a selector to the browser to remove HTML fragments from the DOM.
///
/// See the [Datastar documentation](https://data-star.dev/reference/sse_events#datastar-remove-fragments) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemoveFragments {
    /// `selector` is a CSS selector that represents the fragments to be removed from the DOM.
    ///
    /// The selector must be a valid CSS selector.
    /// The Datastar client side will use this selector to remove the fragment from the DOM.
    pub selector: SmolStr,
    /// Whether to use view transitions,
    ///
    /// if not provided the Datastar client side will default to `false`.
    pub use_view_transition: bool,
}

impl RemoveFragments {
    pub const TYPE: EventType = EventType::RemoveFragments;

    /// Create a new [`MergeFragments`] data blob.
    pub fn new(selector: impl Into<SmolStr>) -> Self {
        Self {
            selector: selector.into(),
            use_view_transition: false,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<RemoveFragments> {
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
            .with_data(super::EventData::RemoveFragments(self))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to use view transitions.
        pub fn use_view_transition(mut self, use_view_transition: bool) -> Self {
            self.use_view_transition = use_view_transition;
            self
        }
    }
}

impl From<RemoveFragments> for Event<RemoveFragments> {
    fn from(value: RemoveFragments) -> Self {
        value.into_sse_event()
    }
}

impl<T> From<RemoveFragments> for super::DatastarEvent<T> {
    fn from(value: RemoveFragments) -> Self {
        value.into_datastar_event()
    }
}

impl EventDataWrite for RemoveFragments {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        write!(w, "selector {}", self.selector).context("RemoveFragments: write selector")?;

        if self.use_view_transition {
            w.write_all(b"\nuseViewTransition true")
                .context("RemoveFragments: write view transition usage")?;
        }

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`RemoveFragments`].
#[derive(Debug)]
pub struct RemoveFragmentsReader(Option<RemoveFragments>);

impl EventDataRead for RemoveFragments {
    type Reader = RemoveFragmentsReader;

    fn line_reader() -> Self::Reader {
        RemoveFragmentsReader(None)
    }
}

impl EventDataLineReader for RemoveFragmentsReader {
    type Data = RemoveFragments;

    fn read_line(&mut self, line: &str) -> Result<(), OpaqueError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        };

        let remove_fragments = self
            .0
            .get_or_insert_with(|| RemoveFragments::new(SmolStr::default()));

        let (keyword, value) = line
            .split_once(' ')
            // in case of empty value
            .unwrap_or((line, ""));

        if keyword.eq_ignore_ascii_case("selector") {
            if value.is_empty() {
                tracing::trace!("ignore selector property with empty value");
            } else {
                remove_fragments.selector = value.into();
            }
        } else if keyword.eq_ignore_ascii_case("useViewTransition") {
            remove_fragments.use_view_transition = value
                .parse()
                .context("RemoveFragmentsReader: parse useViewTransition")?;
        } else {
            tracing::debug!(
                %keyword,
                %value,
                "RemoveFragmentsReader: ignore unknown remove fragment line",
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        let remove_fragments = match self.0.take() {
            Some(fragments) => fragments,
            None => return Ok(None),
        };

        if !event
            .and_then(|e| {
                e.parse::<EventType>()
                    .ok()
                    .map(|t| t == EventType::RemoveFragments)
            })
            .unwrap_or_default()
        {
            return Err(OpaqueError::from_display(
                "RemoveFragmentsReader: unexpected event type: expected: datastar-remove-fragments",
            ));
        }

        if remove_fragments.selector.is_empty() {
            return Err(OpaqueError::from_display(
                "remove fragments contains no selector",
            ));
        }

        Ok(Some(remove_fragments))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_remove_fragments(input: &str) -> RemoveFragments {
        let mut reader = RemoveFragments::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some("datastar-remove-fragments"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_deserialize_minimal() {
        let data = read_remove_fragments(r##"selector #foo"##);
        assert_eq!(data.selector, r##"#foo"##);
        assert!(!data.use_view_transition);
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let expected_data = RemoveFragments::new("body > main > header > .foo#bar::first")
            .with_use_view_transition(true);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_remove_fragments(&input);

        assert_eq!(expected_data, data);
    }
}
