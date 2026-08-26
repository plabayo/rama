use rama_core::error::{BoxError, ErrorContext};
use rama_utils::{macros::impl_deref, str::arcstr::ArcStr};
use std::{fmt, marker::PhantomData};

use crate::sse::parser::is_lf;

pub(super) struct LinePrefixWriter<'a, W> {
    inner: &'a mut W,
    prefix: &'static [u8],
    pending_cr: bool,
}

impl<'a, W: std::io::Write> LinePrefixWriter<'a, W> {
    pub(super) fn new(inner: &'a mut W, prefix: &'static [u8]) -> Self {
        Self {
            inner,
            prefix,
            pending_cr: false,
        }
    }

    pub(super) fn finish(mut self) -> std::io::Result<()> {
        if self.pending_cr {
            self.inner.write_all(self.prefix)?;
            self.pending_cr = false;
        }
        Ok(())
    }
}

impl<W: std::io::Write> std::io::Write for LinePrefixWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut start = 0;

        if self.pending_cr && !buf.is_empty() {
            self.pending_cr = false;
            if buf[0] == b'\n' {
                self.inner.write_all(&buf[..1])?;
                self.inner.write_all(self.prefix)?;
                start = 1;
            } else {
                self.inner.write_all(self.prefix)?;
            }
        }

        let mut index = start;
        while index < buf.len() {
            match buf[index] {
                b'\r' => {
                    self.inner.write_all(&buf[start..=index])?;
                    index += 1;

                    if index == buf.len() {
                        self.pending_cr = true;
                        start = index;
                    } else {
                        if buf[index] == b'\n' {
                            self.inner.write_all(&buf[index..=index])?;
                            index += 1;
                        }
                        self.inner.write_all(self.prefix)?;
                        start = index;
                    }
                }
                b'\n' => {
                    self.inner.write_all(&buf[start..=index])?;
                    self.inner.write_all(self.prefix)?;
                    index += 1;
                    start = index;
                }
                _ => index += 1,
            }
        }

        self.inner.write_all(&buf[start..])?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Trait that can be implemented for a custom data type that is to be written (by a server).
pub trait EventDataWrite {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), BoxError>;
}

/// Trait that can be implemented for a custom data type that is to be read (by a client).
pub trait EventDataRead: Sized {
    type Reader: EventDataLineReader<Data = Self>;

    fn line_reader() -> Self::Reader;
}

pub trait EventDataLineReader {
    type Data: EventDataRead;

    fn read_line(&mut self, line: &str) -> Result<(), BoxError>;

    fn data(&mut self, event: Option<&str>) -> Result<Option<Self::Data>, BoxError>;
}

macro_rules! write_str_data {
    () => {
        fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), BoxError> {
            w.write_all(self.as_bytes())
                .context("write string event data")
        }
    };
}

impl EventDataWrite for &str {
    write_str_data!();
}

impl EventDataWrite for ArcStr {
    write_str_data!();
}

impl EventDataWrite for String {
    write_str_data!();
}

#[derive(Debug)]
/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`String`].
pub struct EventDataStringReader {
    buf: Option<String>,
    // size of the previously produced payload: streams tend to carry
    // similarly-sized events, so pre-reserving it avoids the realloc
    // ladder (and its copies) while appending line by line
    size_hint: usize,
}

impl EventDataLineReader for EventDataStringReader {
    type Data = String;

    #[inline]
    fn read_line(&mut self, line: &str) -> Result<(), BoxError> {
        let buf = match &mut self.buf {
            Some(buf) => buf,
            None => self
                .buf
                .insert(String::with_capacity(self.size_hint.max(line.len() + 1))),
        };
        buf.push_str(line);
        buf.push('\u{000A}');
        Ok(())
    }

    fn data(&mut self, _event: Option<&str>) -> Result<Option<Self::Data>, BoxError> {
        let Some(mut data) = self.buf.take() else {
            return Ok(None);
        };

        if data.chars().next_back().map(is_lf).unwrap_or_default() {
            data.pop();
        }
        self.size_hint = data.len() + 1;
        Ok(Some(data))
    }
}

impl EventDataRead for String {
    type Reader = EventDataStringReader;

    fn line_reader() -> Self::Reader {
        EventDataStringReader {
            buf: Default::default(),
            size_hint: 0,
        }
    }
}

macro_rules! write_multiline_data {
    () => {
        fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), BoxError> {
            let mut iter = self.iter();
            if let Some(mut next) = iter.next() {
                for element in iter {
                    next.write_data(w)?;
                    next = element;
                    write!(w, "\n").context("write newline")?;
                }
                next.write_data(w)?;
            }
            Ok(())
        }
    };
}

impl<const N: usize, T: EventDataWrite> EventDataWrite for [T; N] {
    write_multiline_data!();
}

impl<T: EventDataWrite> EventDataWrite for [T] {
    write_multiline_data!();
}

impl<T: EventDataWrite> EventDataWrite for Vec<T> {
    write_multiline_data!();
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of [`Vec`].
pub struct EventDataMultiLineReader<T> {
    lines: Vec<T>,
}

impl<T: fmt::Debug> fmt::Debug for EventDataMultiLineReader<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventDataMultiLineReader")
            .field("lines", &self.lines)
            .finish()
    }
}

impl<T: EventDataRead> EventDataLineReader for EventDataMultiLineReader<T> {
    type Data = Vec<T>;

    fn read_line(&mut self, line: &str) -> Result<(), BoxError> {
        let mut reader = T::line_reader();
        reader.read_line(line)?;
        if let Some(data) = reader.data(None)? {
            self.lines.push(data);
        }
        Ok(())
    }

    fn data(&mut self, _event: Option<&str>) -> Result<Option<Self::Data>, BoxError> {
        if self.lines.is_empty() {
            return Ok(None);
        }

        let lines = std::mem::take(&mut self.lines);
        Ok(Some(lines))
    }
}

impl<T: EventDataRead> EventDataRead for Vec<T> {
    type Reader = EventDataMultiLineReader<T>;

    fn line_reader() -> Self::Reader {
        EventDataMultiLineReader {
            lines: Default::default(),
        }
    }
}

/// Wrapper used to create Json event data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonEventData<T>(pub T);

impl_deref!(JsonEventData);

impl<T> From<T> for JsonEventData<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: serde::Serialize> EventDataWrite for JsonEventData<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), BoxError> {
        serde_json::to_writer(w, &self.0).context("serialize json data")?;
        Ok(())
    }
}

/// [`EventDataLineReader`] for the [`EventDataRead`] implementation of any
/// json-compatible [`DeserializeOwned`].
///
/// [`DeserializeOwned`]: serde::de::DeserializeOwned
pub struct EventDataJsonReader<T> {
    buf: String,
    _phantom: PhantomData<fn() -> T>,
}

impl<T> fmt::Debug for EventDataJsonReader<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventDataJsonReader")
            .field("buf", &self.buf)
            .field(
                "_phantom",
                &format_args!("{}", std::any::type_name::<fn() -> T>()),
            )
            .finish()
    }
}

impl<T: serde::de::DeserializeOwned> EventDataLineReader for EventDataJsonReader<T> {
    type Data = JsonEventData<T>;

    fn read_line(&mut self, line: &str) -> Result<(), BoxError> {
        self.buf.push_str(line);
        self.buf.push('\u{000A}');
        Ok(())
    }

    fn data(&mut self, _event: Option<&str>) -> Result<Option<Self::Data>, BoxError> {
        // An event with no `data:` line leaves the buffer empty; in that case
        // there is no JSON to decode and we surface `Ok(None)` rather than
        // erroring on `from_str("")`.
        if self.buf.is_empty() {
            return Ok(None);
        }
        let data: T = serde_json::from_str(&self.buf).context("read json event data")?;
        self.buf.clear();
        Ok(Some(JsonEventData(data)))
    }
}

impl<T: serde::de::DeserializeOwned> EventDataRead for JsonEventData<T> {
    type Reader = EventDataJsonReader<T>;

    fn line_reader() -> Self::Reader {
        EventDataJsonReader {
            buf: Default::default(),
            _phantom: PhantomData,
        }
    }
}

macro_rules! impl_either_event_data_write {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> EventDataWrite for rama_core::combinators::$id<$($param),+>
        where
            $(
                $param: EventDataWrite,
            )+
    {
        fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), BoxError> {
            match self {
                $(
                    rama_core::combinators::$id::$param(d) => d.write_data(w),
                )+
            }
        }
        }
    };
}

rama_core::combinators::impl_either!(impl_either_event_data_write);
