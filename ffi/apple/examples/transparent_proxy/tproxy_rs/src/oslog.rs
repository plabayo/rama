use std::{
    collections::BTreeMap,
    ffi::{CString, c_char, c_void},
    fmt::Debug,
};

use rama::telemetry::tracing::{
    Event, Level, Subscriber,
    field::{Field, Visit},
    subscriber::layer::{Context, Layer},
};

#[cfg(target_vendor = "apple")]
unsafe extern "C" {
    fn os_log_create(subsystem: *const c_char, category: *const c_char) -> *mut c_void;
    fn os_release(object: *mut c_void);
    fn rama_os_log_private(log: *mut c_void, level: u8, message: *const c_char);
}

pub struct PrivateOsLogLayer {
    #[cfg(target_vendor = "apple")]
    logger: *mut c_void,
}

impl PrivateOsLogLayer {
    pub fn new(subsystem: &str, category: &str) -> Self {
        #[cfg(target_vendor = "apple")]
        {
            let subsystem = CString::new(subsystem).expect("invalid os_log subsystem");
            let category = CString::new(category).expect("invalid os_log category");
            let logger = unsafe { os_log_create(subsystem.as_ptr(), category.as_ptr()) };
            Self { logger }
        }
        #[cfg(not(target_vendor = "apple"))]
        {
            let _ = (subsystem, category);
            Self {}
        }
    }
}

// Apple documents os_log objects as thread-safe shared handles.
#[cfg(target_vendor = "apple")]
unsafe impl Send for PrivateOsLogLayer {}
#[cfg(target_vendor = "apple")]
unsafe impl Sync for PrivateOsLogLayer {}

impl<S: Subscriber> Layer<S> for PrivateOsLogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        #[cfg(target_vendor = "apple")]
        {
            let mut fields = BTreeMap::new();
            event.record(&mut FieldVisitor(&mut fields));
            let mut message = fields.remove("message").unwrap_or_default();
            for (key, value) in fields {
                if !message.is_empty() {
                    message.push(' ');
                }
                message.push_str(&key);
                message.push('=');
                message.push_str(&value);
            }
            message.retain(|character| character != '\0');
            let message = CString::new(message).expect("invalid os_log message");
            unsafe {
                rama_os_log_private(
                    self.logger,
                    os_log_level(*event.metadata().level()),
                    message.as_ptr(),
                );
            }
        }
    }
}

#[cfg(target_vendor = "apple")]
impl Drop for PrivateOsLogLayer {
    fn drop(&mut self) {
        unsafe { os_release(self.logger) }
    }
}

#[cfg(target_vendor = "apple")]
fn os_log_level(level: Level) -> u8 {
    match level {
        Level::TRACE => 2,
        Level::DEBUG => 1,
        Level::INFO => 0,
        Level::WARN => 16,
        Level::ERROR => 17,
    }
}

#[cfg(target_vendor = "apple")]
struct FieldVisitor<'a>(&'a mut BTreeMap<String, String>);

#[cfg(target_vendor = "apple")]
impl Visit for FieldVisitor<'_> {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}
