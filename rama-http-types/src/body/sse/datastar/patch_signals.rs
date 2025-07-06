use crate::sse::{Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType};
use rama_core::telemetry::tracing;
use rama_error::{ErrorContext, OpaqueError};

/// [`PatchSignals`] patches signals into the signal store
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PatchSignals<T = String> {
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

impl<T> PatchSignals<T> {
    pub const TYPE: EventType = EventType::PatchSignals;

    /// Create a new [`PatchSignals`] data blob.
    pub fn new(signals: T) -> Self {
        Self {
            signals,
            only_if_missing: false,
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<PatchSignals<T>> {
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
            .with_data(super::EventData::PatchSignals(self))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to merge the signal only if it does not already exist.
        pub fn only_if_missing(mut self, only_if_missing: bool) -> Self {
            self.only_if_missing = only_if_missing;
            self
        }
    }
}

impl<T> From<PatchSignals<T>> for Event<PatchSignals<T>> {
    fn from(value: PatchSignals<T>) -> Self {
        value.into_sse_event()
    }
}

impl<T> From<PatchSignals<T>> for super::DatastarEvent<T> {
    fn from(value: PatchSignals<T>) -> Self {
        value.into_datastar_event()
    }
}

impl<T: EventDataWrite> EventDataWrite for PatchSignals<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        w.write_all(b"signals ")
            .context("PatchSignals: write signals keyword")?;
        self.signals
            .write_data(w)
            .context("PatchSignals: write signals value")?;

        if self.only_if_missing {
            w.write_all(b"\nonlyIfMissing true")
                .context("PatchSignals: write onlyIfMissing")?;
        }

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`PatchSignals`].
#[derive(Debug)]
pub struct PatchSignalsReader<R> {
    signals: R,
    only_if_missing: bool,
}

impl<T: EventDataRead> EventDataRead for PatchSignals<T> {
    type Reader = PatchSignalsReader<T::Reader>;

    fn line_reader() -> Self::Reader {
        PatchSignalsReader {
            signals: T::line_reader(),
            only_if_missing: false,
        }
    }
}

impl<R: EventDataLineReader> EventDataLineReader for PatchSignalsReader<R> {
    type Data = PatchSignals<R::Data>;

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
                .context("PatchSignalsReader: parse onlyIfMissing")?;
        } else {
            tracing::debug!(
                "PatchSignalsReader: ignore unknown line: keyword = {}; value = {}",
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
                    .map(|t| t == EventType::PatchSignals)
            })
            .unwrap_or_default()
        {
            return Err(OpaqueError::from_display(
                "PatchSignalsReader: unexpected event type: expected: datastar-patch-signals",
            ));
        }

        let only_if_missing = std::mem::take(&mut self.only_if_missing);
        Ok(Some(PatchSignals {
            signals,
            only_if_missing,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_patch_signals<T: EventDataRead>(input: &str) -> PatchSignals<T> {
        let mut reader = PatchSignals::<T>::line_reader();
        for line in input.lines() {
            reader.read_line(line).unwrap();
        }
        reader
            .data(Some("datastar-patch-signals"))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn test_deserialize_minimal() {
        let data: PatchSignals<String> = read_patch_signals(r##"signals {answer: 42}"##);
        assert_eq!(data.signals, r##"{answer: 42}"##);
        assert!(!data.only_if_missing);
    }

    #[test]
    fn test_serialize_deserialize_reflect() {
        let expected_data =
            PatchSignals::new(r##"{a:1,b:{"c":2}}"##.to_owned()).with_only_if_missing(true);

        let mut buf = Vec::new();
        expected_data.write_data(&mut buf).unwrap();

        let input = String::from_utf8(buf).unwrap();
        let data = read_patch_signals(&input);

        assert_eq!(expected_data, data);
    }
}
