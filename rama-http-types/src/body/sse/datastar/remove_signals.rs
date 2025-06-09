use crate::sse::{Event, EventDataLineReader, EventDataRead, EventDataWrite, datastar::EventType};
use rama_error::{ErrorContext, OpaqueError};
use smallvec::{SmallVec, smallvec};
use smol_str::SmolStr;

/// [`RemoveSignals`] sends signals to the browser to be removed from the signals.
///
/// See the [Datastar documentation](https://data-star.dev/reference/sse_events#datastar-remove-signals) for more information.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemoveSignals {
    /// `paths` is a list of strings that represent the signal paths to be removed from the signals.
    ///
    /// The paths ***must*** be valid . delimited paths to signals within the signals.
    /// The Datastar client side will use these paths to remove the data from the signals.
    pub paths: SmallVec<[SmolStr; 4]>,
}

impl RemoveSignals {
    /// Create a new [`RemoveSignals`] data blob.
    pub fn new(path: impl Into<SmolStr>) -> Self {
        Self {
            paths: smallvec![path.into()],
        }
    }

    /// Consume `self` as an [`Event`].
    pub fn into_sse_event(self) -> Event<RemoveSignals> {
        Event::new()
            .try_with_event(EventType::RemoveSignals.as_smol_str())
            .unwrap()
            .with_data(self)
    }

    /// Create a new [`RemoveSignals`] data blob.
    pub fn new_multi(paths: impl IntoIterator<Item = impl Into<SmolStr>>) -> Self {
        Self {
            paths: paths.into_iter().map(Into::into).collect(),
        }
    }
}

impl EventDataWrite for RemoveSignals {
    #[allow(clippy::write_with_newline)]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        let mut paths = self.paths.iter();
        let mut next_path = paths
            .next()
            .context("paths missing for this RemoveSignals blob")?;

        for path in paths {
            write!(w, "paths {}\n", next_path).context("RemoveSignals: write paths")?;
            next_path = path;
        }
        write!(w, "paths {}", next_path).context("RemoveSignals: write last paths")?;

        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`RemoveSignals`].
#[derive(Debug)]
pub struct RemoveSignalsReader(RemoveSignals);

impl EventDataRead for RemoveSignals {
    type Reader = RemoveSignalsReader;

    fn line_reader() -> Self::Reader {
        RemoveSignalsReader(RemoveSignals {
            paths: Default::default(),
        })
    }
}

impl EventDataLineReader for RemoveSignalsReader {
    type Data = RemoveSignals;

    fn read_line(&mut self, line: &str) -> Result<(), OpaqueError> {
        let (keyword, value) = line
            .trim()
            .split_once(' ')
            .context("invalid remove signals line: missing keyword separator")?;

        if keyword.eq_ignore_ascii_case("paths") {
            self.0.paths.push(value.into())
        } else {
            tracing::debug!(
                %keyword,
                %value,
                "RemoveSignalsReader: ignore unknown remove signals line",
            );
        }

        Ok(())
    }

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, OpaqueError> {
        if self.0.paths.is_empty() {
            return Ok(None);
        }

        let signals = std::mem::replace(
            &mut self.0,
            RemoveSignals {
                paths: Default::default(),
            },
        );

        if event
            .and_then(|e| {
                e.parse::<EventType>()
                    .ok()
                    .map(|t| t == EventType::RemoveSignals)
            })
            .unwrap_or_default()
        {
            return Err(OpaqueError::from_display(
                "RemoveSignalsReader: unexpected event type: expected: datastar-remove-signals",
            ));
        }

        Ok(Some(signals))
    }
}
