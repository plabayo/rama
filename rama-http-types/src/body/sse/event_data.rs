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

    fn read_data_borrowed(raw_data: &str) -> Result<Self, OpaqueError> {
        Self::read_data(raw_data.to_owned())
    }
}

macro_rules! write_str_data {
    () => {
        fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
            w.write_all(self.as_bytes())
                .context("write string event data")
        }
    };
}

impl EventDataWrite for &str {
    write_str_data!();
}

impl EventDataWrite for Arc<str> {
    write_str_data!();
}

impl EventDataWrite for String {
    write_str_data!();
}

impl EventDataRead for String {
    #[inline]
    fn read_data(raw_data: String) -> Result<Self, OpaqueError> {
        Ok(raw_data)
    }
}

macro_rules! write_multiline_data {
    () => {
        fn write_data(&self, w: &mut impl std::io::Write) -> Result<(), OpaqueError> {
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

impl<T: EventDataRead> EventDataRead for Vec<T> {
    fn read_data(raw_data: String) -> Result<Self, OpaqueError> {
        let n = raw_data.chars().filter(|&c| c == '\n' || c == '\r').count();
        if n == 0 {
            return Ok(vec![T::read_data(raw_data)?]);
        }

        let mut v = Vec::with_capacity(n);
        for line in raw_data.split(['\n', '\r']) {
            v.push(T::read_data_borrowed(line)?);
        }
        Ok(v)
    }

    fn read_data_borrowed(raw_data: &str) -> Result<Self, OpaqueError> {
        let n = raw_data.chars().filter(|&c| c == '\n' || c == '\r').count();
        let mut v = Vec::with_capacity(n);
        for line in raw_data.split(['\n', '\r']) {
            v.push(T::read_data_borrowed(line)?);
        }
        Ok(v)
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

impl<T: PartialEq> PartialEq for JsonEventData<T> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
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
        serde_json::to_writer(w, &self.0).context("serialize json data")?;
        Ok(())
    }
}

impl<T: serde::de::DeserializeOwned> EventDataRead for JsonEventData<T> {
    #[inline]
    fn read_data(raw_data: String) -> Result<Self, OpaqueError> {
        Self::read_data_borrowed(&raw_data)
    }

    fn read_data_borrowed(raw_data: &str) -> Result<Self, OpaqueError> {
        Ok(Self(
            serde_json::from_str(raw_data).context("read json event data")?,
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
