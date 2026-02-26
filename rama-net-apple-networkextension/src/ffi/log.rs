use super::BytesView;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl LogLevel {
    #[inline]
    fn from_u32_or_debug(x: u32) -> Self {
        if x <= Self::Error as u32 {
            // SAFETY: repr(u32) and valid range 0..=4 maps to a real variant
            unsafe { ::std::mem::transmute::<u32, Self>(x) }
        } else {
            tracing::debug!("invalid raw u32 value transmuted as u32: {x} (defaulting it to DEBUG");
            Self::Debug
        }
    }
}

/// # Safety
///
/// `message.ptr` must be valid for reads of `message.len` bytes for the
/// duration of the call.
pub unsafe fn log_callback(level: u32, message: BytesView) {
    // SAFETY: caller guarantees `message` is valid for the duration of this call.
    let msg = String::from_utf8_lossy(unsafe { message.into_slice() });

    match LogLevel::from_u32_or_debug(level) {
        LogLevel::Trace => tracing::trace!("{}", msg.as_ref()),
        LogLevel::Debug => tracing::debug!("{}", msg.as_ref()),
        LogLevel::Info => tracing::info!("{}", msg.as_ref()),
        LogLevel::Warn => tracing::warn!("{}", msg.as_ref()),
        LogLevel::Error => tracing::error!("{}", msg.as_ref()),
    }
}
