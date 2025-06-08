use crate::sse::{Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType};
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
            .try_with_event(EventType::RemoveFragments.as_str())
            .unwrap()
            .with_data(self)
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to use view transitions.
        pub fn use_view_transition(mut self, use_view_transition: bool) -> Self {
            self.use_view_transition = use_view_transition;
            self
        }
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
        let remove_fragments = self
            .0
            .get_or_insert_with(|| RemoveFragments::new(SmolStr::default()));

        let (keyword, value) = line
            .trim()
            .split_once(' ')
            .context("invalid remove fragment line: missing keyword separator")?;

        if keyword.eq_ignore_ascii_case("selector") {
            remove_fragments.selector = value.into();
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

        if event
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
