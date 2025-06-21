use crate::sse::{Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType};
use rama_core::telemetry::tracing;
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
        let line = line.trim();
        if line.is_empty() {
            return Ok(());
        };

        let (keyword, value) = line
            .split_once(' ')
            // in case of empty value
            .unwrap_or((line, ""));

        if keyword.eq_ignore_ascii_case("signals") {
            self.signals.read_line(value)?;
        } else if keyword.eq_ignore_ascii_case("onlyIfMissing") {
            self.only_if_missing = value
                .parse()
                .context("MergeSignalsReader: parse onlyIfMissing")?;
        } else {
            tracing::debug!(
                "MergeSignalsReader: ignore unknown merge signals line: keyword = {}; value = {}",
                keyword,
                value,
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        let signals = match self.signals.data(None)? {
            Some(signals) => signals,
            None => return Ok(None),
        };

        if !event
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

#[cfg(test)]
mod tests {
    use super::*;

    fn read_merge_signals<T: EventDataRead>(input: &str) -> MergeSignals<T> {
        let mut reader = MergeSignals::<T>::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some("datastar-merge-signals"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_deserialize_minimal() {
        let data: MergeSignals<String> = read_merge_signals(r##"signals {answer: 42}"##);
        assert_eq!(data.signals, r##"{answer: 42}"##);
        assert!(!data.only_if_missing);
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let expected_data =
            MergeSignals::new(r##"{a:1,b:{"c":2}}"##.to_owned()).with_only_if_missing(true);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_merge_signals(&input);

        assert_eq!(expected_data, data);
    }
}
