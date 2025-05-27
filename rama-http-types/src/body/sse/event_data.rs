use rama_error::{ErrorContext, OpaqueError};
use rama_utils::macros::impl_deref;
use std::{fmt, sync::Arc};

/// Trait that can be implemented for a custom data type that is to be written (by a server).
pub trait EventDataWrite {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError>;
}

/// Trait that can be implemented for a custom data type that is to be read (by a client).
pub trait EventDataRead: Sized {
    fn read_data(raw_data: String) -> Result<Self, OpaqueError>;
}

impl EventDataWrite for &str {
    #[inline]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        w.write_all(self.as_bytes())
            .context("write String event data")
    }
}

impl EventDataWrite for Arc<str> {
    #[inline]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        w.write_all(self.as_bytes())
            .context("write String event data")
    }
}

impl EventDataWrite for String {
    #[inline]
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        w.write_all(self.as_bytes())
            .context("write String event data")
    }
}

impl EventDataRead for String {
    #[inline]
    fn read_data(raw_data: String) -> Result<Self, OpaqueError> {
        Ok(raw_data)
    }
}

/// Wrapper used to create Json event data.
pub struct JsonEventData<T>(pub T);

impl<T: fmt::Debug> fmt::Debug for JsonEventData<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("JsonEventData").field(&self.0).finish()
    }
}

impl<T: Clone> Clone for JsonEventData<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl_deref!(JsonEventData);

impl<T> From<T> for JsonEventData<T> {
    fn from(inner: T) -> Self {
        Self(inner)
    }
}

impl<T: serde::Serialize> EventDataWrite for JsonEventData<T> {
    fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
        struct IgnoreNewLines<'a, W: std::io::Write>(&'a mut W);

        impl<'a, W: std::io::Write> std::io::Write for IgnoreNewLines<'a, W> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut last_split = 0;
                for delimiter in memchr::memchr2_iter(b'\n', b'\r', buf) {
                    self.0.write_all(&buf[last_split..delimiter])?;
                    last_split = delimiter + 1;
                }
                self.0.write_all(&buf[last_split..])?;
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.0.flush()
            }
        }

        let mut wrapper = IgnoreNewLines(w);
        serde_json::to_writer(&mut wrapper, &self.0).context("serialize json data")?;
        Ok(())
    }
}

impl<T: serde::de::DeserializeOwned> EventDataRead for JsonEventData<T> {
    fn read_data(raw_data: String) -> Result<Self, OpaqueError> {
        Ok(Self(
            serde_json::from_str(&raw_data).context("read json event data")?,
        ))
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
        fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
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
