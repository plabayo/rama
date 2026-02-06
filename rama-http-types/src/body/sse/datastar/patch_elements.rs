use super::ElementPatchMode;
use crate::sse::{
    Event, EventBuildError, EventDataLineReader, EventDataRead, EventDataWrite,
    datastar::EventType, parser::is_lf,
};
use rama_core::error::{BoxError, ErrorContext};
use rama_core::telemetry::tracing;
use rama_utils::str::{NonEmptyStr, arcstr::ArcStr};

/// [`PatchElements`] patches HTML elements into the DOM.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PatchElements {
    /// The elements to be patched into the DOM.
    pub elements: Option<NonEmptyStr>,
    /// The CSS selector used to patch the elements.
    pub selector: Option<NonEmptyStr>,
    /// The mode in which elements are patched into the DOM.
    ///
    /// If not provided the Datastar client side will default to [`ElementPatchMode::Outer`].
    pub mode: ElementPatchMode,
    /// Whether to use view transitions.
    ///
    /// If not provided the Datastar client side will default to `false`.
    pub use_view_transition: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash)]
struct PatchElementsBuilder {
    elements: Option<String>,
    selector: Option<NonEmptyStr>,
    mode: ElementPatchMode,
    use_view_transition: bool,
}

impl PatchElements {
    pub const TYPE: EventType = EventType::PatchElements;

    /// Create a new [`PatchElements`] data blob.
    #[must_use]
    pub const fn new(elements: NonEmptyStr) -> Self {
        Self {
            elements: Some(elements),
            selector: None,
            mode: ElementPatchMode::Outer,
            use_view_transition: false,
        }
    }

    /// Create a new [`PatchElements`] data blob for removal
    #[must_use]
    pub const fn new_remove(selector: NonEmptyStr) -> Self {
        Self {
            elements: None,
            selector: Some(selector),
            mode: ElementPatchMode::Remove,
            use_view_transition: false,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn try_into_sse_event(self) -> Result<Event<Self>, EventBuildError> {
        Ok(Event::new()
            .try_with_event(Self::TYPE.as_smol_str())?
            .with_data(self))
    }

    /// Consume `self` as a [`super::DatastarEvent`].
    pub fn try_into_datastar_event<T>(self) -> Result<super::DatastarEvent<T>, EventBuildError> {
        Ok(Event::new()
            .try_with_event(Self::TYPE.as_smol_str())?
            .with_data(super::EventData::PatchElements(self)))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the CSS selector used to patch the elements.
        pub fn selector(mut self, selector: NonEmptyStr) -> Self {
            self.selector = Some(selector);
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set mode in which elements are patched into the DOM.
        pub fn mode(mut self, mode: ElementPatchMode) -> Self {
            self.mode = mode;
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

impl TryFrom<PatchElements> for Event<PatchElements> {
    type Error = EventBuildError;

    #[inline(always)]
    fn try_from(value: PatchElements) -> Result<Self, Self::Error> {
        value.try_into_sse_event()
    }
}

impl<T> TryFrom<PatchElements> for super::DatastarEvent<T> {
    type Error = EventBuildError;

    #[inline(always)]
    fn try_from(value: PatchElements) -> Result<Self, Self::Error> {
        value.try_into_datastar_event()
    }
}

impl EventDataWrite for PatchElements {
    #[allow(clippy::write_with_newline)]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), BoxError> {
        let mut sep = "";

        if let Some(selector) = &self.selector {
            write!(w, "selector {selector}").context("PatchElements: write selector")?;
            sep = "\n";
        }

        if self.mode != ElementPatchMode::default() {
            write!(w, "{sep}mode {}", self.mode).context("PatchElements: write mode")?;
            sep = "\n";
        }

        if self.use_view_transition {
            write!(w, "{sep}useViewTransition true")
                .context("PatchElements: write view transition usage")?;
            sep = "\n";
        }

        if let Some(mut elements) = self.elements.as_deref() {
            if elements.chars().last().map(is_lf).unwrap_or_default() {
                elements = &elements[..elements.len() - 1];
            }

            let mut elements = elements.lines();
            let mut next_element = elements
                .next()
                .context("PatchElements: no elements specified")?;
            for element in elements {
                write!(w, "{sep}elements {next_element}")
                    .context("PatchElements: write elements")?;
                next_element = element;
                sep = "\n"
            }
            write!(w, "{sep}elements {next_element}")
                .context("PatchElements: write last elements")?;
        }

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`PatchElements`].
#[derive(Debug)]
pub struct PatchElementsReader(Option<PatchElementsBuilder>);

impl EventDataRead for PatchElements {
    type Reader = PatchElementsReader;

    fn line_reader() -> Self::Reader {
        PatchElementsReader(None)
    }
}

impl EventDataLineReader for PatchElementsReader {
    type Data = PatchElements;

    fn read_line(&mut self, line: &str) -> Result<(), BoxError> {
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        };

        let patch_elements = self.0.get_or_insert_default();

        let (keyword, value) = line
            .split_once(' ')
            // in case of empty value
            .unwrap_or((line, ""));

        if keyword.eq_ignore_ascii_case("selector") {
            if value.is_empty() {
                tracing::trace!("ignore selector property with empty value");
            } else {
                // SAFETY: we check above if it is empty :)
                patch_elements.selector =
                    Some(unsafe { NonEmptyStr::new_unchecked(ArcStr::from(value)) });
            }
        } else if keyword.eq_ignore_ascii_case("mode") {
            if value.is_empty() {
                tracing::trace!("ignore mode property with empty value");
            } else {
                patch_elements.mode = value.into();
            }
        } else if keyword.eq_ignore_ascii_case("useViewTransition") {
            patch_elements.use_view_transition = value
                .parse()
                .context("PatchElementsReader: parse useViewTransition")?;
        } else if keyword.eq_ignore_ascii_case("elements") {
            let elements = patch_elements.elements.get_or_insert_default();
            elements.push_str(value);
            elements.push('\n');
        } else {
            tracing::debug!(
                "PatchElementsReader: ignore unknown line: keyword = {}; value = {}",
                keyword,
                value,
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, BoxError> {
        let Some(PatchElementsBuilder {
            elements,
            selector,
            mode,
            use_view_transition,
        }) = self.0.take()
        else {
            return Ok(None);
        };

        if !event
            .and_then(|e| {
                e.parse::<EventType>()
                    .ok()
                    .map(|t| t == EventType::PatchElements)
            })
            .unwrap_or_default()
        {
            return Err(BoxError::from(
                "PatchElementsReader: unexpected event type: expected: datastar-patch-elements",
            ));
        }

        Ok(Some(PatchElements {
            elements: elements
                .map(|mut s| {
                    if s.chars().last().map(is_lf).unwrap_or_default() {
                        let _ = s.pop();
                    }
                    s.try_into()
                })
                .transpose()
                .context("PatchElementsReader: unexpected empty Some(String)")?,
            selector,
            mode,
            use_view_transition,
        }))
    }
}

#[cfg(test)]
mod tests {
    use rama_utils::str::non_empty_str;

    use super::*;

    fn read_patch_elements(input: &str) -> PatchElements {
        let mut reader = PatchElements::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some("datastar-patch-elements"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_deserialize_minimal() {
        let data = read_patch_elements(r##"elements <div id="foo">Hello, world!</div>"##);
        assert_eq!(
            data.elements.as_deref(),
            Some(r##"<div id="foo">Hello, world!</div>"##)
        );
        assert_eq!(data.mode, ElementPatchMode::Outer);
        assert_eq!(data.selector, None);
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let expected_data = PatchElements::new(non_empty_str!("<div>\nHello, world!\n</div>"))
            .with_selector(non_empty_str!("#foo"))
            .with_mode(ElementPatchMode::Append)
            .with_use_view_transition(true);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_patch_elements(&input);

        assert_eq!(expected_data, data);
    }
}
