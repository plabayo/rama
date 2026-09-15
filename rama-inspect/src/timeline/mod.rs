//! Format-independent view model for a recorded capture.
//!
//! A decoder turns one capture file (HAR, qlog, ...) into a [`Timeline`]: file
//! [`Timeline::summary`] metadata, the [`Connection`]s the capture observed, and
//! time-ordered [`Entry`] items carrying their own detail [`Section`]s. A viewer
//! renders that shape without knowing which format produced it.
//!
//! [`View`] adds the interaction state a viewer needs — connection scope, text
//! filter, selection and a visible time window — so navigation behaviour is
//! shared and testable outside any user interface.

use std::{fmt, sync::Arc, time::Duration};

use jiff::Timestamp;
use rama_core::error::BoxError;
use rama_utils::str::arcstr::ArcStr;

use crate::search::matches_display;

#[cfg(test)]
mod tests;

/// A named value in a [`Section`], a [`Connection`] or a file summary.
#[derive(Debug, Clone)]
pub struct Field {
    /// Name of the value, e.g. `content-type`.
    pub name: ArcStr,
    /// Rendered value; use [`Section::UNAVAILABLE`] when a capture omitted it.
    pub value: ArcStr,
}

impl Field {
    /// Create a field from anything that can become shared text.
    pub fn new(name: impl Into<ArcStr>, value: impl Into<ArcStr>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// One detail block of an [`Entry`], rendered as a titled group.
#[derive(Debug, Clone)]
pub struct Section {
    /// Group title, e.g. `request headers`.
    pub title: ArcStr,
    /// Group content.
    pub body: SectionBody,
}

impl Section {
    /// Placeholder for a value the capture did not record.
    pub const UNAVAILABLE: &'static str = "—";

    /// Create a section listing named values.
    pub fn fields(title: impl Into<ArcStr>, fields: Vec<Field>) -> Self {
        Self {
            title: title.into(),
            body: SectionBody::Fields(fields),
        }
    }

    /// Create a section holding a (possibly truncated) text preview.
    pub fn text(title: impl Into<ArcStr>, text: impl Into<ArcStr>) -> Self {
        Self {
            title: title.into(),
            body: SectionBody::Text(text.into()),
        }
    }

    /// Create a section that states why its content is missing.
    pub fn unavailable(title: impl Into<ArcStr>, reason: impl Into<ArcStr>) -> Self {
        Self {
            title: title.into(),
            body: SectionBody::Unavailable(reason.into()),
        }
    }

    /// Whether this section carries nothing worth rendering.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match &self.body {
            SectionBody::Fields(fields) => fields.is_empty(),
            SectionBody::Text(text) => text.is_empty(),
            SectionBody::Unavailable(_) => false,
        }
    }
}

/// Content of a [`Section`].
#[derive(Debug, Clone)]
pub enum SectionBody {
    /// Named values, in capture order.
    Fields(Vec<Field>),
    /// Free-form text, already bounded and made display-safe by the decoder.
    Text(ArcStr),
    /// Nothing was captured; the value explains why.
    Unavailable(ArcStr),
}

/// How prominently an [`Entry`] should be rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Level {
    /// Neutral, e.g. a plain protocol event.
    #[default]
    Info,
    /// Completed as expected, e.g. a 2xx response.
    Success,
    /// Noteworthy but not a failure, e.g. a 4xx response or a packet loss event.
    Warning,
    /// Failed, e.g. a 5xx response or a connection error.
    Failure,
}

/// A connection (or trace / stream group) the capture observed.
#[derive(Debug, Clone)]
pub struct Connection {
    /// Stable identifier from the capture, e.g. a qlog `group_id`.
    pub id: ArcStr,
    /// Short label for selection UI.
    pub label: ArcStr,
    /// Connection-level metadata.
    pub fields: Vec<Field>,
}

/// One item on the timeline: an HTTP exchange, a protocol event, a message, ...
#[derive(Debug, Clone)]
pub struct Entry {
    /// Index into [`Timeline::connections`], when the capture attributes it.
    pub connection: Option<usize>,
    /// Offset from the timeline origin.
    pub start: Duration,
    /// Elapsed time; zero for an instantaneous event.
    pub duration: Duration,
    /// Rendering hint.
    pub level: Level,
    /// Short prefix, e.g. an HTTP method or an event category.
    pub badge: Option<ArcStr>,
    /// Primary text, e.g. a URL or an event name.
    pub label: ArcStr,
    /// Trailing summary, e.g. a status line or a size.
    pub detail: Option<ArcStr>,
    /// Detail blocks shown when the entry is selected.
    pub sections: Vec<Section>,
    /// Ready-to-paste representations of this entry, e.g. a curl command.
    pub copy: Vec<CopyItem>,
}

impl Entry {
    /// Create an entry at `start` with `label`, without detail.
    pub fn new(start: Duration, label: impl Into<ArcStr>) -> Self {
        Self {
            connection: None,
            start,
            duration: Duration::ZERO,
            level: Level::default(),
            badge: None,
            label: label.into(),
            detail: None,
            sections: Vec::new(),
            copy: Vec::new(),
        }
    }

    /// Offset at which this entry ends.
    #[must_use]
    pub fn end(&self) -> Duration {
        self.start.saturating_add(self.duration)
    }

    /// Whether the entry's text contains `needle`, case-insensitively.
    ///
    /// Everything the viewer can display is searched, detail sections included.
    /// Section text is already bounded by the decoder's preview limits.
    #[must_use]
    pub fn matches(&self, needle: &str) -> bool {
        needle.is_empty() || matches_display(&EntryText(self), needle)
    }
}

/// Streams every searchable fragment of an entry without allocating.
struct EntryText<'a>(&'a Entry);

impl fmt::Display for EntryText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let entry = self.0;
        if let Some(badge) = &entry.badge {
            write!(f, "{badge} ")?;
        }
        write!(f, "{}", entry.label)?;
        if let Some(detail) = &entry.detail {
            write!(f, " {detail}")?;
        }
        for section in &entry.sections {
            write!(f, " {}", section.title)?;
            match &section.body {
                SectionBody::Fields(fields) => {
                    for field in fields {
                        write!(f, " {} {}", field.name, field.value)?;
                    }
                }
                SectionBody::Text(text) => write!(f, " {text}")?,
                SectionBody::Unavailable(reason) => write!(f, " {reason}")?,
            }
        }
        Ok(())
    }
}

/// Text a viewer can copy out of an [`Entry`].
///
/// The text is produced on demand: a decoder can offer an expensive rendering,
/// such as a curl command carrying a request body, for every entry of a large
/// capture without building it until someone asks for that one entry.
#[derive(Clone)]
pub struct CopyItem {
    /// What the text is, e.g. `curl`.
    pub label: ArcStr,
    render: Arc<dyn Fn() -> Result<ArcStr, BoxError> + Send + Sync>,
}

impl CopyItem {
    /// Create an item whose text is already known.
    pub fn new(label: impl Into<ArcStr>, text: impl Into<ArcStr>) -> Self {
        let text = text.into();
        Self::lazy(label, move || Ok(text.clone()))
    }

    /// Create an item whose text is rendered when it is asked for.
    pub fn lazy(
        label: impl Into<ArcStr>,
        render: impl Fn() -> Result<ArcStr, BoxError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            label: label.into(),
            render: Arc::new(render),
        }
    }

    /// Render the text, reporting why it could not be produced.
    pub fn text(&self) -> Result<ArcStr, BoxError> {
        (self.render)()
    }
}

impl fmt::Debug for CopyItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CopyItem")
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

/// One decoded capture file.
///
/// Entry offsets are relative to the timeline origin. [`Timeline::epoch`] gives
/// that origin's wall-clock time when the capture records one; a capture with a
/// monotonic-only reference (a qlog trace, typically) leaves it unset rather
/// than inventing an absolute time.
#[derive(Debug, Clone)]
pub struct Timeline {
    /// Human-readable format label, e.g. `HAR 1.2`.
    pub format: ArcStr,
    /// Where the capture came from, e.g. a file name.
    pub source: ArcStr,
    /// Wall-clock time of offset zero, when the capture records it.
    pub epoch: Option<Timestamp>,
    /// File-level metadata.
    pub summary: Vec<Field>,
    /// Connections referenced by [`Entry::connection`].
    pub connections: Vec<Connection>,
    entries: Vec<Entry>,
}

impl Timeline {
    /// Create an empty timeline for a given format and source.
    pub fn new(format: impl Into<ArcStr>, source: impl Into<ArcStr>) -> Self {
        Self {
            format: format.into(),
            source: source.into(),
            epoch: None,
            summary: Vec::new(),
            connections: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Replace the entries, ordering them by start offset.
    pub fn set_entries(&mut self, mut entries: Vec<Entry>) {
        entries.sort_by_key(|entry| entry.start);
        self.entries = entries;
    }

    /// Entries in time order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Offset at which the last entry ends.
    #[must_use]
    pub fn span(&self) -> Duration {
        self.entries
            .iter()
            .map(Entry::end)
            .max()
            .unwrap_or(Duration::ZERO)
    }

    /// Wall-clock time of `offset`, when [`Timeline::epoch`] is known.
    #[must_use]
    pub fn timestamp_at(&self, offset: Duration) -> Option<Timestamp> {
        let offset = jiff::SignedDuration::try_from(offset).ok()?;
        self.epoch?.checked_add(offset).ok()
    }
}

/// Interaction state over a [`Timeline`]: scope, filter, selection and window.
#[derive(Debug, Clone)]
pub struct View {
    timeline: Timeline,
    connection: Option<usize>,
    filter: String,
    matches: Vec<usize>,
    cursor: usize,
    window: (Duration, Duration),
}

impl View {
    /// Show `timeline` in full, with the first entry selected.
    pub fn new(timeline: Timeline) -> Self {
        let mut view = Self {
            window: (Duration::ZERO, timeline.span()),
            timeline,
            connection: None,
            filter: String::new(),
            matches: Vec::new(),
            cursor: 0,
        };
        view.refresh();
        view
    }

    /// The timeline being viewed.
    #[must_use]
    pub fn timeline(&self) -> &Timeline {
        &self.timeline
    }

    /// Active text filter.
    #[must_use]
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Restrict to entries matching `filter`, keeping the selection when possible.
    pub fn set_filter(&mut self, filter: impl Into<String>) {
        self.filter = filter.into();
        self.refresh();
    }

    /// Connection scope, or `None` for all connections.
    #[must_use]
    pub fn connection(&self) -> Option<usize> {
        self.connection
    }

    /// Restrict to one connection, or to all when `None`.
    pub fn select_connection(&mut self, connection: Option<usize>) {
        self.connection = connection.filter(|index| *index < self.timeline.connections.len());
        self.refresh();
    }

    /// Cycle through "all connections" and each individual connection.
    pub fn cycle_connection(&mut self) {
        let count = self.timeline.connections.len();
        let next = match self.connection {
            _ if count == 0 => None,
            None => Some(0),
            Some(index) if index + 1 < count => Some(index + 1),
            Some(_) => None,
        };
        self.select_connection(next);
    }

    /// Indices, into [`Timeline::entries`], of the entries currently shown.
    #[must_use]
    pub fn matches(&self) -> &[usize] {
        &self.matches
    }

    /// Entries currently shown, in time order.
    pub fn visible(&self) -> impl ExactSizeIterator<Item = &Entry> {
        self.matches
            .iter()
            .map(|index| &self.timeline.entries[*index])
    }

    /// Number of entries currently shown.
    #[must_use]
    pub fn len(&self) -> usize {
        self.matches.len()
    }

    /// Whether the filter and scope hide every entry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Position of the selection within [`View::visible`].
    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// The selected entry, if any entry is shown.
    #[must_use]
    pub fn selected(&self) -> Option<&Entry> {
        let index = *self.matches.get(self.cursor)?;
        self.timeline.entries.get(index)
    }

    /// Move the selection down, stopping at the last shown entry.
    pub fn select_next(&mut self) {
        self.select(self.cursor.saturating_add(1));
    }

    /// Move the selection up, stopping at the first shown entry.
    pub fn select_prev(&mut self) {
        self.select(self.cursor.saturating_sub(1));
    }

    /// Select the first shown entry.
    pub fn select_first(&mut self) {
        self.select(0);
    }

    /// Select the last shown entry.
    pub fn select_last(&mut self) {
        self.select(self.matches.len().saturating_sub(1));
    }

    /// Select by position within [`View::visible`], clamped to what is shown.
    pub fn select(&mut self, position: usize) {
        self.cursor = position.min(self.matches.len().saturating_sub(1));
    }

    /// Visible time window as `(start, end)` offsets.
    #[must_use]
    pub fn window(&self) -> (Duration, Duration) {
        self.window
    }

    /// Show the whole capture again.
    pub fn reset_window(&mut self) {
        self.window = (Duration::ZERO, self.timeline.span());
    }

    /// Scale the window by `factor` around the selection (`< 1` zooms in).
    ///
    /// The window never shrinks below a millisecond and never grows past the
    /// capture's own span.
    pub fn zoom(&mut self, factor: f64) {
        let span = self.timeline.span();
        let width = self.window_width().as_secs_f64() * factor.max(f64::MIN_POSITIVE);
        let width = Duration::from_secs_f64(width.clamp(0.001, span.as_secs_f64().max(0.001)));
        let focus = self
            .selected()
            .map_or_else(|| self.window_center(), |entry| entry.start);
        let start = focus
            .saturating_sub(width / 2)
            .min(span.saturating_sub(width));
        self.window = (start, start.saturating_add(width));
    }

    /// Slide the window by `fraction` of its width, staying inside the capture.
    pub fn pan(&mut self, fraction: f64) {
        let width = self.window_width();
        let step = width.mul_f64(fraction.abs());
        let (start, _) = self.window;
        let start = if fraction < 0.0 {
            start.saturating_sub(step)
        } else {
            start
                .saturating_add(step)
                .min(self.timeline.span().saturating_sub(width))
        };
        self.window = (start, start.saturating_add(width));
    }

    /// Where `entry` sits in the window, as `(start, end)` fractions in `0..=1`.
    ///
    /// `None` when the entry falls entirely outside the window.
    #[must_use]
    pub fn bar(&self, entry: &Entry) -> Option<(f64, f64)> {
        let (window_start, window_end) = self.window;
        if entry.end() < window_start || entry.start > window_end {
            return None;
        }
        let width = self.window_width().as_secs_f64();
        if width <= 0.0 {
            return Some((0.0, 1.0));
        }
        let offset = |point: Duration| {
            (point.saturating_sub(window_start).as_secs_f64() / width).clamp(0.0, 1.0)
        };
        Some((offset(entry.start), offset(entry.end())))
    }

    fn window_width(&self) -> Duration {
        self.window.1.saturating_sub(self.window.0)
    }

    fn window_center(&self) -> Duration {
        self.window.0.saturating_add(self.window_width() / 2)
    }

    /// Recompute the shown entries, keeping the previously selected one when it
    /// survives the new filter, and otherwise staying at the same position.
    fn refresh(&mut self) {
        let previous = self.matches.get(self.cursor).copied();
        self.matches = self
            .timeline
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                self.connection
                    .is_none_or(|scope| entry.connection == Some(scope))
                    && entry.matches(&self.filter)
            })
            .map(|(index, _)| index)
            .collect();
        self.cursor = previous
            .and_then(|index| self.matches.iter().position(|shown| *shown == index))
            .unwrap_or(self.cursor)
            .min(self.matches.len().saturating_sub(1));
    }
}
