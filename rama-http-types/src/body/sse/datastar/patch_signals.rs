use crate::sse::{
    Event, EventBuildError, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType,
};
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
    pub fn try_into_sse_event(self) -> Result<Event<Self>, EventBuildError> {
        Ok(Event::new()
            .try_with_event(Self::TYPE.as_smol_str())?
            .with_data(self))
    }

    /// Consume `self` as a [`super::DatastarEvent`].
    pub fn try_into_datastar_event(self) -> Result<super::DatastarEvent<T>, EventBuildError> {
        Ok(Event::new()
            .try_with_event(Self::TYPE.as_smol_str())?
            .with_data(super::EventData::PatchSignals(self)))
    }

    rama_utils::macros::generate_set_and_with! {
        /// Sets whether to merge the signal only if it does not already exist.
        pub fn only_if_missing(mut self, only_if_missing: bool) -> Self {
            self.only_if_missing = only_if_missing;
            self
        }
    }
}

impl<T> TryFrom<PatchSignals<T>> for Event<PatchSignals<T>> {
    type Error = EventBuildError;

    #[inline(always)]
    fn try_from(value: PatchSignals<T>) -> Result<Self, Self::Error> {
        value.try_into_sse_event()
    }
}

impl<T> TryFrom<PatchSignals<T>> for super::DatastarEvent<T> {
    type Error = EventBuildError;

    #[inline(always)]
    fn try_from(value: PatchSignals<T>) -> Result<Self, Self::Error> {
        value.try_into_datastar_event()
    }
}

impl<T: EventDataWrite> EventDataWrite for PatchSignals<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        w.write_all(b"signals ")
            .context("PatchSignals: write signals keyword")?;
        self.signals
            .write_data(&mut DataWriteSplitter(w))
            .context("PatchSignals: write signals value")?;

        if self.only_if_missing {
            w.write_all(b"\nonlyIfMissing true")
                .context("PatchSignals: write onlyIfMissing")?;
        }

        Ok(())
    }
}

struct DataWriteSplitter<'a, W: std::io::Write>(&'a mut W);

impl<W: std::io::Write> std::io::Write for DataWriteSplitter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut last_split = 0;
        for delimiter in memchr::memchr2_iter(b'\n', b'\r', buf) {
            self.0.write_all(&buf[last_split..=delimiter])?;
            self.0.write_all(b"signals ")?;
            last_split = delimiter + 1;
        }
        self.0.write_all(&buf[last_split..])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
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
        let Some(signals) = self.signals.data(None)? else {
            return Ok(None);
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
    fn test_serialize_signals_multiline() {
        let mut buf = Vec::default();
        PatchSignals::new(
            r##"{
"foo": 1,
"bar": false,
}"##,
        )
        .write_data(&mut buf)
        .unwrap();
        let output = String::from_utf8(buf).unwrap();
        assert_eq!(
            r##"signals {
signals "foo": 1,
signals "bar": false,
signals }"##,
            output
        );
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
