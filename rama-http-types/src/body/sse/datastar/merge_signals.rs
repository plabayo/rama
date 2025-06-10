use crate::sse::{Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType};
use rama_error::{ErrorContext, OpaqueError};

/// [`MergeSignals`] sends one or more signals to the browser
/// to be merged into the signals.
///
/// See the [Datastar documentation](https://data-star.dev/reference/sse_events#datastar-merge-signals) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MergeSignals<T = String> {
    /// `signals` is a JavaScript object or JSON string that
    /// will be sent to the browser to update signals in the signals.
    ///
    /// The data ***must*** evaluate to a valid JavaScript.
    /// It will be converted to signals by the Datastar client side.
    pub signals: T,
    /// Whether to merge the signal only if it does not already exist.
    ///
    /// If not provided, the Datastar client side will default to false,
    /// which will cause the data to be merged into the signals.
    pub only_if_missing: bool,
}

impl<T> MergeSignals<T> {
    pub const TYPE: EventType = EventType::MergeSignals;

    /// Create a new [`MergeSignals`] data blob.
    pub fn new(signals: T) -> Self {
        Self {
            signals,
            only_if_missing: false,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<MergeSignals<T>> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
            .with_retry(super::consts::DEFAULT_DATASTAR_DURATION)
            .with_data(self)
    }

    /// Consume `self` as a [`super::DatastarEvent`].
    pub fn into_datastar_event(self) -> super::DatastarEvent<T> {
        Event::new()
            .try_with_event(Self::TYPE.as_smol_str())
            .unwrap()
            .with_retry(super::consts::DEFAULT_DATASTAR_DURATION)
            .with_data(super::EventData::MergeSignals(self))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to merge the signal only if it does not already exist.
        pub fn only_if_missing(mut self, only_if_missing: bool) -> Self {
            self.only_if_missing = only_if_missing;
            self
        }
    }
}

impl<T> From<MergeSignals<T>> for Event<MergeSignals<T>> {
    fn from(value: MergeSignals<T>) -> Self {
        value.into_sse_event()
    }
}

impl<T> From<MergeSignals<T>> for super::DatastarEvent<T> {
    fn from(value: MergeSignals<T>) -> Self {
        value.into_datastar_event()
    }
}

impl<T: EventDataWrite> EventDataWrite for MergeSignals<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        w.write_all(b"signals ")
            .context("MergeSignals: write signals keyword")?;
        self.signals
            .write_data(w)
            .context("MergeSignals: write signals value")?;

        if self.only_if_missing {
            w.write_all(b"\nonlyIfMissing true")
                .context("MergeSignals: write onlyIfMissing")?;
        }

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`MergeSignals`].
#[derive(Debug)]
pub struct MergeSignalsReader<R> {
    signals: R,
    only_if_missing: bool,
}

impl<T: EventDataRead> EventDataRead for MergeSignals<T> {
    type Reader = MergeSignalsReader<T::Reader>;

    fn line_reader() -> Self::Reader {
        MergeSignalsReader {
            signals: T::line_reader(),
            only_if_missing: false,
        }
    }
}

impl<R: EventDataLineReader> EventDataLineReader for MergeSignalsReader<R> {
    type Data = MergeSignals<R::Data>;

    fn read_line(&mut self, line: &str) -> Result<(), OpaqueError> {
        let (keyword, value) = line
            .trim()
            .split_once(' ')
            .context("invalid merge signals line: missing keyword separator")?;

        if keyword.eq_ignore_ascii_case("signals") {
            self.signals.read_line(value)?;
        } else if keyword.eq_ignore_ascii_case("onlyIfMissing") {
            self.only_if_missing = value
                .parse()
                .context("MergeSignalsReader: parse onlyIfMissing")?;
        } else {
            tracing::debug!(
                %keyword,
                %value,
                "MergeSignalsReader: ignore unknown merge signals line",
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        let signals = match self.signals.data(None)? {
            Some(signals) => signals,
            None => return Ok(None),
        };

        if event
            .and_then(|e| {
                e.parse::<EventType>()
                    .ok()
                    .map(|t| t == EventType::MergeSignals)
            })
            .unwrap_or_default()
        {
            return Err(OpaqueError::from_display(
                "MergeSignalsReader: unexpected event type: expected: datastar-merge-signals",
            ));
        }

        let only_if_missing = std::mem::take(&mut self.only_if_missing);
        Ok(Some(MergeSignals {
            signals,
            only_if_missing,
        }))
    }
}
