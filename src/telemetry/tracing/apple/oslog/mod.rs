//! A [`tracing_subscriber`] layer for Apple unified logging.
//!
//! [`OsLogLayer`] writes tracing events to an Apple `os_log_t`. By default,
//! spans are represented as signpost intervals for inspection in Instruments.
//! Each interval measures the span's lifetime from creation until final close,
//! rather than only the time during which the span is entered. Span context in
//! event messages remains optional and is disabled by default.
//!
//! The layer checks whether Apple logging is enabled for an event's mapped
//! level before it visits or formats that event. This check is deliberately
//! performed inside [`Layer::on_event`]: returning `false` from
//! [`Layer::enabled`] would disable the event for every other layer in the
//! subscriber stack as well.
//!
//! # Example
//!
//! ```no_run
//! use rama::telemetry::tracing::{
//!     self,
//!     apple::oslog::{OsLogLayer, Privacy},
//!     subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _},
//! };
//!
//! let oslog = OsLogLayer::new("com.example.proxy", "network")?
//!     .with_privacy(Privacy::Public)
//!     .with_span_context(true);
//!
//! tracing::subscriber::registry().with(oslog).try_init()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use ahash::HashMap;
use rama_core::telemetry::tracing::{
    Event, Level, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
};
use rama_utils::octets::kib;
use std::{
    ffi::{CString, NulError, c_char, c_void},
    fmt::{self, Write as _},
    ptr::NonNull,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing_subscriber::{
    layer::{Context, Layer},
    registry::LookupSpan,
};

const DEFAULT_MAX_MESSAGE_BYTES: usize = kib(1);
const MIN_MESSAGE_BYTES: usize = 3;
const OS_SIGNPOST_ID_NULL: u64 = 0;
const OS_SIGNPOST_ID_INVALID: u64 = u64::MAX;

static NEXT_LAYER_ID: AtomicU64 = AtomicU64::new(1);

/// Privacy applied to the event or signpost's dynamic text.
///
/// Apple normally treats dynamic strings as private. Use [`Self::Public`] only
/// when the formatted tracing message and all of its fields are known not to
/// contain user or secret data.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum Privacy {
    /// Redact the dynamic text in persisted logs.
    #[default]
    Private = 0,
    /// Store the dynamic text without redaction.
    Public = 1,
    /// Store the target and event message publicly while keeping structured
    /// fields and span fields private.
    ///
    /// Callers must ensure the tracing `message` itself contains no user or
    /// secret data. Prefer structured fields for values that need redaction.
    PublicMessagePrivateFields = 2,
}

/// Controls whether tracing spans are exported as Apple signposts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SpanMode {
    /// Do not emit signpost intervals.
    ///
    /// This avoids the per-span runtime-enabled check and is useful for
    /// applications that create spans at particularly high volume.
    Disabled,
    /// Emit a signpost interval from span creation until span close.
    ///
    /// This represents the full lifetime of a tracing span, which can include
    /// idle time and multiple enter/exit cycles, rather than only active time.
    ///
    /// Apple signposts require a static interval name, so Rama uses the fixed
    /// name `tracing-span` and writes the tracing target, span name, and fields
    /// into the signpost's dynamic message.
    #[default]
    Signposts,
}

/// Native Apple unified-log types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum OsLogType {
    /// Persisted notice/default message.
    Default = 0x00,
    /// Informational message, normally held in memory only.
    Info = 0x01,
    /// Debug message, captured only when debug logging is enabled.
    Debug = 0x02,
    /// Process-level error.
    Error = 0x10,
    /// System-level or multi-process fault.
    Fault = 0x11,
}

/// Maps tracing levels to Apple unified-log types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LevelMap {
    trace: OsLogType,
    debug: OsLogType,
    info: OsLogType,
    warn: OsLogType,
    error: OsLogType,
}

impl LevelMap {
    /// Create a custom level map.
    pub const fn new(
        trace: OsLogType,
        debug: OsLogType,
        info: OsLogType,
        warn: OsLogType,
        error: OsLogType,
    ) -> Self {
        Self {
            trace,
            debug,
            info,
            warn,
            error,
        }
    }

    /// Match the semantics of Apple's Swift `Logger` convenience methods.
    ///
    /// Trace and debug share Apple's debug type, warning and error share its
    /// error type, and fault is never selected implicitly.
    pub const fn apple() -> Self {
        Self::new(
            OsLogType::Debug,
            OsLogType::Debug,
            OsLogType::Info,
            OsLogType::Error,
            OsLogType::Error,
        )
    }

    /// Persist tracing `INFO` events while keeping ordinary errors below fault.
    ///
    /// This is useful for rare lifecycle events that must survive for later
    /// `log show` inspection.
    pub const fn persistent_info() -> Self {
        Self::new(
            OsLogType::Debug,
            OsLogType::Info,
            OsLogType::Default,
            OsLogType::Error,
            OsLogType::Error,
        )
    }

    /// Preserve the level mapping used by `tracing-oslog` 0.3.
    ///
    /// In particular, every tracing error becomes an Apple fault. Prefer
    /// [`Self::apple`] or [`Self::persistent_info`] for new integrations.
    pub const fn tracing_oslog_compatible() -> Self {
        Self::new(
            OsLogType::Debug,
            OsLogType::Info,
            OsLogType::Default,
            OsLogType::Error,
            OsLogType::Fault,
        )
    }

    const fn get(self, level: Level) -> OsLogType {
        match level {
            Level::TRACE => self.trace,
            Level::DEBUG => self.debug,
            Level::INFO => self.info,
            Level::WARN => self.warn,
            Level::ERROR => self.error,
        }
    }
}

impl Default for LevelMap {
    fn default() -> Self {
        Self::apple()
    }
}

/// Failure to create an Apple unified-log layer.
#[derive(Debug)]
pub enum OsLogError {
    /// The subsystem contained an interior NUL byte.
    InvalidSubsystem(NulError),
    /// The category contained an interior NUL byte.
    InvalidCategory(NulError),
    /// Apple unexpectedly returned a null log handle.
    CreateFailed,
}

impl fmt::Display for OsLogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSubsystem(_) => f.write_str("os_log subsystem contains a NUL byte"),
            Self::InvalidCategory(_) => f.write_str("os_log category contains a NUL byte"),
            Self::CreateFailed => f.write_str("Apple os_log_create returned a null handle"),
        }
    }
}

impl std::error::Error for OsLogError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidSubsystem(err) | Self::InvalidCategory(err) => Some(err),
            Self::CreateFailed => None,
        }
    }
}

/// A composable [`tracing_subscriber::Layer`] that writes to Apple unified
/// logging.
pub struct OsLogLayer {
    log: Arc<LogHandle>,
    layer_id: u64,
    privacy: Privacy,
    span_mode: SpanMode,
    level_map: LevelMap,
    include_target: bool,
    include_span_context: bool,
    max_message_bytes: usize,
}

impl OsLogLayer {
    /// Create a layer for one fixed Apple subsystem/category pair.
    ///
    /// Apple caches these pairs for the lifetime of the process, so callers
    /// should create a small, fixed set rather than derive categories from
    /// request or span data.
    pub fn new(subsystem: impl AsRef<str>, category: impl AsRef<str>) -> Result<Self, OsLogError> {
        let subsystem = CString::new(subsystem.as_ref()).map_err(OsLogError::InvalidSubsystem)?;
        let category = CString::new(category.as_ref()).map_err(OsLogError::InvalidCategory)?;

        // SAFETY: both pointers are valid NUL-terminated strings for the
        // duration of this call. The shim returns the retained os_log_t as an
        // opaque pointer.
        let raw = unsafe { ffi::rama_apple_oslog_create(subsystem.as_ptr(), category.as_ptr()) };

        Self::from_raw(raw)
    }

    /// Create a layer whose subsystem is the main bundle identifier.
    ///
    /// `fallback_subsystem` is used for command-line programs and other
    /// processes without a main application bundle.
    pub fn new_for_main_bundle(
        fallback_subsystem: impl AsRef<str>,
        category: impl AsRef<str>,
    ) -> Result<Self, OsLogError> {
        let fallback_subsystem =
            CString::new(fallback_subsystem.as_ref()).map_err(OsLogError::InvalidSubsystem)?;
        let category = CString::new(category.as_ref()).map_err(OsLogError::InvalidCategory)?;

        // SAFETY: both pointers are valid NUL-terminated strings for the
        // duration of this call. The shim returns the retained os_log_t as an
        // opaque pointer.
        let raw = unsafe {
            ffi::rama_apple_oslog_create_for_main_bundle(
                fallback_subsystem.as_ptr(),
                category.as_ptr(),
            )
        };

        Self::from_raw(raw)
    }

    fn from_raw(raw: *mut c_void) -> Result<Self, OsLogError> {
        let raw = NonNull::new(raw).ok_or(OsLogError::CreateFailed)?;

        Ok(Self {
            log: Arc::new(LogHandle(raw)),
            layer_id: next_layer_id(),
            privacy: Privacy::default(),
            span_mode: SpanMode::default(),
            level_map: LevelMap::default(),
            include_target: true,
            include_span_context: false,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        })
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the privacy applied to all dynamic text emitted by this layer.
        pub fn privacy(mut self, privacy: Privacy) -> Self {
            self.privacy = privacy;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Configure native signpost export for spans.
        ///
        /// Defaults to [`SpanMode::Signposts`].
        pub fn span_mode(mut self, span_mode: SpanMode) -> Self {
            self.span_mode = span_mode;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Set the tracing-to-Apple level mapping.
        pub fn level_map(mut self, level_map: LevelMap) -> Self {
            self.level_map = level_map;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Include or omit the tracing target in event and signpost messages.
        pub fn target(mut self, include_target: bool) -> Self {
            self.include_target = include_target;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Include or omit the event's explicit/contextual span path and fields.
        pub fn span_context(mut self, include_span_context: bool) -> Self {
            self.include_span_context = include_span_context;
            self
        }
    }

    rama_utils::macros::generate_set_and_with! {
        /// Bound the formatted dynamic payload.
        ///
        /// Apple caps persisted dynamic content at roughly 1 KiB. Values
        /// below three bytes are raised to three so truncation can be represented
        /// by `...`.
        pub fn max_message_bytes(mut self, max_message_bytes: usize) -> Self {
            self.max_message_bytes = if max_message_bytes < MIN_MESSAGE_BYTES {
                MIN_MESSAGE_BYTES
            } else {
                max_message_bytes
            };
            self
        }
    }

    fn format_span(&self, state: &SpanState) -> Vec<u8> {
        let mut output = BoundedString::new(self.max_message_bytes);
        if self.include_target {
            _ = write!(output, "[{}] ", state.metadata.target());
        }
        output.push_str(state.metadata.name());
        if !state.fields.is_empty() {
            output.push_str(" ");
            output.push_bounded(&state.fields);
        }
        output.into_c_message()
    }

    fn format_span_split(&self, state: &SpanState) -> (Vec<u8>, Vec<u8>) {
        let mut public = BoundedString::new(self.max_message_bytes);
        if self.include_target {
            _ = write!(public, "[{}] ", state.metadata.target());
        }
        public.push_str(state.metadata.name());

        let mut private = BoundedString::new(self.max_message_bytes);
        private.push_bounded(&state.fields);
        (public.into_c_message(), private.into_c_message())
    }

    fn format_event<S>(&self, event: &Event<'_>, ctx: &Context<'_, S>) -> Vec<u8>
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        let mut message = BoundedString::new(self.max_message_bytes);
        let mut fields = BoundedString::new(self.max_message_bytes);
        event.record(&mut FieldVisitor::event(&mut message, &mut fields));

        let mut output = BoundedString::new(self.max_message_bytes);
        if self.include_target {
            _ = write!(output, "[{}] ", event.metadata().target());
        }

        if !message.is_empty() {
            output.push_bounded(&message);
        }
        if !fields.is_empty() {
            if !message.is_empty() {
                output.push_str(" ");
            }
            output.push_bounded(&fields);
        }

        if self.include_span_context {
            let mut wrote_span = false;
            if let Some(scope) = ctx.event_scope(event) {
                for span in scope.from_root() {
                    let extensions = span.extensions();
                    let Some(states) = extensions.get::<SpanStates>() else {
                        continue;
                    };
                    let Some(state) = states.0.get(&self.layer_id) else {
                        continue;
                    };

                    if !wrote_span {
                        if !output.is_empty() {
                            output.push_str(" ");
                        }
                        output.push_str("spans=[");
                        wrote_span = true;
                    } else {
                        output.push_str(" > ");
                    }

                    output.push_str(state.metadata.name());
                    if !state.fields.is_empty() {
                        output.push_str("{");
                        output.push_bounded(&state.fields);
                        output.push_str("}");
                    }
                }
            }
            if wrote_span {
                output.push_str("]");
            }
        }

        output.into_c_message()
    }

    fn format_event_split<S>(&self, event: &Event<'_>, ctx: &Context<'_, S>) -> (Vec<u8>, Vec<u8>)
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        let mut message = BoundedString::new(self.max_message_bytes);
        let mut fields = BoundedString::new(self.max_message_bytes);
        event.record(&mut FieldVisitor::event(&mut message, &mut fields));

        let mut public = BoundedString::new(self.max_message_bytes);
        if self.include_target {
            _ = write!(public, "[{}] ", event.metadata().target());
        }
        public.push_bounded(&message);

        let mut private = BoundedString::new(self.max_message_bytes);
        private.push_bounded(&fields);
        if self.include_span_context {
            self.append_span_context(event, ctx, &mut private);
        }

        (public.into_c_message(), private.into_c_message())
    }

    fn append_span_context<S>(
        &self,
        event: &Event<'_>,
        ctx: &Context<'_, S>,
        output: &mut BoundedString,
    ) where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        let mut wrote_span = false;
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                let extensions = span.extensions();
                let Some(states) = extensions.get::<SpanStates>() else {
                    continue;
                };
                let Some(state) = states.0.get(&self.layer_id) else {
                    continue;
                };

                if !wrote_span {
                    if !output.is_empty() {
                        output.push_str(" ");
                    }
                    output.push_str("spans=[");
                    wrote_span = true;
                } else {
                    output.push_str(" > ");
                }

                output.push_str(state.metadata.name());
                if !state.fields.is_empty() {
                    output.push_str("{");
                    output.push_bounded(&state.fields);
                    output.push_str("}");
                }
            }
        }
        if wrote_span {
            output.push_str("]");
        }
    }
}

impl Clone for OsLogLayer {
    fn clone(&self) -> Self {
        Self {
            log: Arc::clone(&self.log),
            layer_id: next_layer_id(),
            privacy: self.privacy,
            span_mode: self.span_mode,
            level_map: self.level_map,
            include_target: self.include_target,
            include_span_context: self.include_span_context,
            max_message_bytes: self.max_message_bytes,
        }
    }
}

impl fmt::Debug for OsLogLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsLogLayer")
            .field("layer_id", &self.layer_id)
            .field("privacy", &self.privacy)
            .field("span_mode", &self.span_mode)
            .field("level_map", &self.level_map)
            .field("include_target", &self.include_target)
            .field("include_span_context", &self.include_span_context)
            .field("max_message_bytes", &self.max_message_bytes)
            .finish_non_exhaustive()
    }
}

impl<S> Layer<S> for OsLogLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let signpost_enabled = self.span_mode == SpanMode::Signposts && self.log.signpost_enabled();
        if !self.include_span_context && !signpost_enabled {
            return;
        }

        let Some(span) = ctx.span(id) else {
            return;
        };

        let mut fields = BoundedString::new(self.max_message_bytes);
        attrs.record(&mut FieldVisitor::fields(&mut fields));

        let signpost_id = if signpost_enabled {
            let signpost_id = self.log.signpost_id_generate();
            if is_valid_signpost_id(signpost_id) {
                Some(signpost_id)
            } else {
                None
            }
        } else {
            None
        };

        let state = SpanState {
            metadata: attrs.metadata(),
            fields,
            signpost_id,
        };

        if let Some(signpost_id) = signpost_id {
            if self.privacy == Privacy::PublicMessagePrivateFields {
                let (public, private) = self.format_span_split(&state);
                self.log
                    .signpost_begin_split(signpost_id, &public, &private);
            } else {
                let message = self.format_span(&state);
                self.log.signpost_begin(signpost_id, &message, self.privacy);
            }
        }

        let mut extensions = span.extensions_mut();
        if let Some(states) = extensions.get_mut::<SpanStates>() {
            states.0.insert(self.layer_id, state);
        } else {
            let mut states = HashMap::default();
            states.insert(self.layer_id, state);
            extensions.insert(SpanStates(states));
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(states) = extensions.get_mut::<SpanStates>() else {
            return;
        };
        let Some(state) = states.0.get_mut(&self.layer_id) else {
            return;
        };

        values.record(&mut FieldVisitor::fields(&mut state.fields));
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let os_type = self.level_map.get(*event.metadata().level());
        if !self.log.enabled(os_type) {
            return;
        }

        if self.privacy == Privacy::PublicMessagePrivateFields {
            let (public, private) = self.format_event_split(event, &ctx);
            self.log.emit_split(os_type, &public, &private);
        } else {
            let message = self.format_event(event, &ctx);
            self.log.emit(os_type, &message, self.privacy);
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let mut extensions = span.extensions_mut();
        let Some(states) = extensions.get_mut::<SpanStates>() else {
            return;
        };
        let Some(state) = states.0.remove(&self.layer_id) else {
            return;
        };

        if let Some(signpost_id) = state.signpost_id {
            if self.privacy == Privacy::PublicMessagePrivateFields {
                let (public, private) = self.format_span_split(&state);
                self.log.signpost_end_split(signpost_id, &public, &private);
            } else {
                let message = self.format_span(&state);
                self.log.signpost_end(signpost_id, &message, self.privacy);
            }
        }
    }
}

struct LogHandle(NonNull<c_void>);

// SAFETY: Apple documents os_log_t values as process-wide logging handles;
// os_log calls are safe to make concurrently from different threads.
unsafe impl Send for LogHandle {}
// SAFETY: see the Send implementation above. The handle is immutable and all
// operations are delegated to Apple's thread-safe unified logging runtime.
unsafe impl Sync for LogHandle {}

impl LogHandle {
    fn enabled(&self, os_type: OsLogType) -> bool {
        // SAFETY: self.0 is a retained os_log_t and os_type has one of Apple's
        // documented os_log_type_t values.
        unsafe { ffi::rama_apple_oslog_enabled(self.0.as_ptr(), os_type as u8) != 0 }
    }

    fn emit(&self, os_type: OsLogType, message: &[u8], privacy: Privacy) {
        debug_assert_eq!(message.last(), Some(&0));
        // SAFETY: message is NUL-terminated and lives for the synchronous shim
        // call; self.0 is a valid os_log_t.
        unsafe {
            ffi::rama_apple_oslog_emit(
                self.0.as_ptr(),
                os_type as u8,
                message.as_ptr().cast::<c_char>(),
                privacy as u8,
            );
        }
    }

    fn emit_split(&self, os_type: OsLogType, public: &[u8], private: &[u8]) {
        debug_assert_eq!(public.last(), Some(&0));
        debug_assert_eq!(private.last(), Some(&0));
        if private == [0] {
            self.emit(os_type, public, Privacy::Public);
            return;
        }
        unsafe {
            ffi::rama_apple_oslog_emit_split(
                self.0.as_ptr(),
                os_type as u8,
                public.as_ptr().cast::<c_char>(),
                private.as_ptr().cast::<c_char>(),
            );
        }
    }

    fn signpost_enabled(&self) -> bool {
        // SAFETY: self.0 is a valid os_log_t. The shim also performs the OS
        // availability check before touching signpost APIs.
        unsafe { ffi::rama_apple_oslog_signpost_enabled(self.0.as_ptr()) != 0 }
    }

    fn signpost_id_generate(&self) -> u64 {
        // SAFETY: self.0 is a valid os_log_t and the shim availability-checks
        // the signpost API.
        unsafe { ffi::rama_apple_oslog_signpost_id_generate(self.0.as_ptr()) }
    }

    fn signpost_begin(&self, signpost_id: u64, message: &[u8], privacy: Privacy) {
        debug_assert!(is_valid_signpost_id(signpost_id));
        debug_assert_eq!(message.last(), Some(&0));
        // SAFETY: the ID came from Apple for this handle, message is
        // NUL-terminated, and the shim performs the availability check.
        unsafe {
            ffi::rama_apple_oslog_signpost_begin(
                self.0.as_ptr(),
                signpost_id,
                message.as_ptr().cast::<c_char>(),
                privacy as u8,
            );
        }
    }

    fn signpost_end(&self, signpost_id: u64, message: &[u8], privacy: Privacy) {
        debug_assert!(is_valid_signpost_id(signpost_id));
        debug_assert_eq!(message.last(), Some(&0));
        // SAFETY: this matches a begin emitted by this handle, message is
        // NUL-terminated, and the shim availability-checks the API.
        unsafe {
            ffi::rama_apple_oslog_signpost_end(
                self.0.as_ptr(),
                signpost_id,
                message.as_ptr().cast::<c_char>(),
                privacy as u8,
            );
        }
    }

    fn signpost_begin_split(&self, signpost_id: u64, public: &[u8], private: &[u8]) {
        debug_assert!(is_valid_signpost_id(signpost_id));
        debug_assert_eq!(public.last(), Some(&0));
        debug_assert_eq!(private.last(), Some(&0));
        if private == [0] {
            self.signpost_begin(signpost_id, public, Privacy::Public);
            return;
        }
        unsafe {
            ffi::rama_apple_oslog_signpost_begin_split(
                self.0.as_ptr(),
                signpost_id,
                public.as_ptr().cast::<c_char>(),
                private.as_ptr().cast::<c_char>(),
            );
        }
    }

    fn signpost_end_split(&self, signpost_id: u64, public: &[u8], private: &[u8]) {
        debug_assert!(is_valid_signpost_id(signpost_id));
        debug_assert_eq!(public.last(), Some(&0));
        debug_assert_eq!(private.last(), Some(&0));
        if private == [0] {
            self.signpost_end(signpost_id, public, Privacy::Public);
            return;
        }
        unsafe {
            ffi::rama_apple_oslog_signpost_end_split(
                self.0.as_ptr(),
                signpost_id,
                public.as_ptr().cast::<c_char>(),
                private.as_ptr().cast::<c_char>(),
            );
        }
    }
}

impl Drop for LogHandle {
    fn drop(&mut self) {
        // SAFETY: os_log_create returned this retained handle, and Arc ensures
        // it is released exactly once after the last layer clone is dropped.
        unsafe { ffi::rama_apple_oslog_release(self.0.as_ptr()) };
    }
}

struct SpanStates(HashMap<u64, SpanState>);

struct SpanState {
    metadata: &'static Metadata<'static>,
    fields: BoundedString,
    signpost_id: Option<u64>,
}

struct FieldVisitor<'a> {
    message: Option<&'a mut BoundedString>,
    fields: &'a mut BoundedString,
}

impl<'a> FieldVisitor<'a> {
    fn event(message: &'a mut BoundedString, fields: &'a mut BoundedString) -> Self {
        Self {
            message: Some(message),
            fields,
        }
    }

    fn fields(fields: &'a mut BoundedString) -> Self {
        Self {
            message: None,
            fields,
        }
    }

    fn record_value(&mut self, field: &Field, write_value: impl FnOnce(&mut BoundedString, bool)) {
        if field.name() == "message"
            && let Some(message) = self.message.as_deref_mut()
        {
            write_value(message, true);
            return;
        }

        if !self.fields.is_empty() {
            self.fields.push_str(" ");
        }
        self.fields.push_str(field.name());
        self.fields.push_str("=");
        write_value(self.fields, false);
    }
}

impl Visit for FieldVisitor<'_> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_i128(&mut self, field: &Field, value: i128) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_u128(&mut self, field: &Field, value: u128) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_value(field, |output, is_message| {
            if is_message {
                output.push_str(value);
            } else {
                _ = write!(output, "{value:?}");
            }
        });
    }

    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        self.record_value(field, |output, _| _ = write!(output, "{value:?}"));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_value(field, |output, _| _ = write!(output, "{value}"));
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.record_value(field, |output, _| _ = write!(output, "{value:?}"));
    }
}

#[derive(Debug)]
struct BoundedString {
    value: String,
    max_bytes: usize,
    truncated: bool,
}

impl BoundedString {
    fn new(max_bytes: usize) -> Self {
        Self {
            value: String::with_capacity(max_bytes.min(256)),
            max_bytes,
            truncated: false,
        }
    }

    fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn as_str(&self) -> &str {
        &self.value
    }

    fn push_str(&mut self, value: &str) {
        _ = self.write_str(value);
    }

    fn push_bounded(&mut self, value: &Self) {
        self.push_str(value.as_str());
        self.truncated |= value.truncated;
    }

    fn into_c_message(mut self) -> Vec<u8> {
        if self.truncated {
            let keep = self.max_bytes.saturating_sub(MIN_MESSAGE_BYTES);
            truncate_utf8(&mut self.value, keep);
            self.value.push_str("...");
        }

        if self.value.contains('\0') {
            let mut escaped = Self::new(self.max_bytes);
            for part in self.value.split_inclusive('\0') {
                if let Some(without_nul) = part.strip_suffix('\0') {
                    escaped.push_str(without_nul);
                    escaped.push_str("\\0");
                } else {
                    escaped.push_str(part);
                }
            }
            return escaped.into_c_message();
        }

        let mut bytes = self.value.into_bytes();
        bytes.push(0);
        bytes
    }
}

impl fmt::Write for BoundedString {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let remaining = self.max_bytes.saturating_sub(self.value.len());
        if value.len() <= remaining {
            self.value.push_str(value);
            return Ok(());
        }

        let mut end = remaining;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        self.value.push_str(&value[..end]);
        self.truncated = true;
        Ok(())
    }
}

fn truncate_utf8(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }

    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

fn next_layer_id() -> u64 {
    NEXT_LAYER_ID.fetch_add(1, Ordering::Relaxed)
}

const fn is_valid_signpost_id(signpost_id: u64) -> bool {
    signpost_id != OS_SIGNPOST_ID_NULL && signpost_id != OS_SIGNPOST_ID_INVALID
}

mod ffi {
    use std::ffi::{c_char, c_void};

    unsafe extern "C" {
        pub(super) fn rama_apple_oslog_create(
            subsystem: *const c_char,
            category: *const c_char,
        ) -> *mut c_void;
        pub(super) fn rama_apple_oslog_create_for_main_bundle(
            fallback_subsystem: *const c_char,
            category: *const c_char,
        ) -> *mut c_void;
        pub(super) fn rama_apple_oslog_release(log: *mut c_void);
        pub(super) fn rama_apple_oslog_enabled(log: *mut c_void, os_type: u8) -> u8;
        pub(super) fn rama_apple_oslog_emit(
            log: *mut c_void,
            os_type: u8,
            message: *const c_char,
            is_public: u8,
        );
        pub(super) fn rama_apple_oslog_emit_split(
            log: *mut c_void,
            os_type: u8,
            public_message: *const c_char,
            private_fields: *const c_char,
        );

        pub(super) fn rama_apple_oslog_signpost_enabled(log: *mut c_void) -> u8;
        pub(super) fn rama_apple_oslog_signpost_id_generate(log: *mut c_void) -> u64;
        pub(super) fn rama_apple_oslog_signpost_begin(
            log: *mut c_void,
            signpost_id: u64,
            message: *const c_char,
            is_public: u8,
        );
        pub(super) fn rama_apple_oslog_signpost_end(
            log: *mut c_void,
            signpost_id: u64,
            message: *const c_char,
            is_public: u8,
        );
        pub(super) fn rama_apple_oslog_signpost_begin_split(
            log: *mut c_void,
            signpost_id: u64,
            public_message: *const c_char,
            private_fields: *const c_char,
        );
        pub(super) fn rama_apple_oslog_signpost_end_split(
            log: *mut c_void,
            signpost_id: u64,
            public_message: *const c_char,
            private_fields: *const c_char,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::tracing::{self, subscriber::layer::SubscriberExt as _};
    use std::sync::RwLock;

    struct FormattingCapture {
        formatter: OsLogLayer,
        events: Arc<RwLock<Vec<String>>>,
    }

    impl<S> Layer<S> for FormattingCapture
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
            <OsLogLayer as Layer<S>>::on_new_span(&self.formatter, attrs, id, ctx);
        }

        fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
            <OsLogLayer as Layer<S>>::on_record(&self.formatter, id, values, ctx);
        }

        fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
            let message = if self.formatter.privacy == Privacy::PublicMessagePrivateFields {
                let (public, private) = self.formatter.format_event_split(event, &ctx);
                format!(
                    "{} |private| {}",
                    String::from_utf8(public[..public.len() - 1].to_vec()).unwrap(),
                    String::from_utf8(private[..private.len() - 1].to_vec()).unwrap()
                )
            } else {
                let message = self.formatter.format_event(event, &ctx);
                String::from_utf8(message[..message.len() - 1].to_vec()).unwrap()
            };
            self.events.write().unwrap().push(message);
        }

        fn on_close(&self, id: Id, ctx: Context<'_, S>) {
            <OsLogLayer as Layer<S>>::on_close(&self.formatter, id, ctx);
        }
    }

    #[test]
    fn signposts_are_enabled_by_default() {
        assert_eq!(SpanMode::default(), SpanMode::Signposts);
    }

    #[test]
    fn level_maps_are_explicit_about_faults() {
        assert_eq!(LevelMap::apple().get(Level::ERROR), OsLogType::Error);
        assert_eq!(
            LevelMap::persistent_info().get(Level::INFO),
            OsLogType::Default
        );
        assert_eq!(
            LevelMap::tracing_oslog_compatible().get(Level::ERROR),
            OsLogType::Fault
        );
    }

    #[test]
    fn bounded_message_is_utf8_safe_and_nul_free() {
        let mut message = BoundedString::new(8);
        message.push_str("ééééé");
        let message = message.into_c_message();

        assert_eq!(message.last(), Some(&0));
        std::str::from_utf8(&message[..message.len() - 1]).unwrap();
        assert!(message.len() <= 9);

        let mut message = BoundedString::new(16);
        message.push_str("left\0right");
        let message = message.into_c_message();
        assert_eq!(&message[..message.len() - 1], b"left\\0right");
    }

    #[test]
    fn invalid_subsystem_and_category_are_errors() {
        assert!(matches!(
            OsLogLayer::new("bad\0subsystem", "category"),
            Err(OsLogError::InvalidSubsystem(_))
        ));
        assert!(matches!(
            OsLogLayer::new("com.example", "bad\0category"),
            Err(OsLogError::InvalidCategory(_))
        ));
        assert!(matches!(
            OsLogLayer::new_for_main_bundle("bad\0subsystem", "category"),
            Err(OsLogError::InvalidSubsystem(_))
        ));
        assert!(matches!(
            OsLogLayer::new_for_main_bundle("com.example", "bad\0category"),
            Err(OsLogError::InvalidCategory(_))
        ));
    }

    #[test]
    fn explicit_parents_records_and_multiple_layers_do_not_panic() {
        let first = OsLogLayer::new("org.plabayo.rama.test", "first")
            .unwrap()
            .with_privacy(Privacy::Public)
            .with_level_map(LevelMap::persistent_info())
            .with_span_mode(SpanMode::Signposts)
            .with_span_context(true);
        let second = first.clone().with_target(false);
        let subscriber = tracing::subscriber::registry().with(first).with(second);
        let dispatch = tracing::Dispatch::new(subscriber);

        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!("request", request.id = tracing::field::Empty);
            span.record("request.id", 42_u64);
            tracing::info!(parent: &span, answer = 42, "explicit parent");
            tracing::info!(parent: None, "explicit root");
        });
    }

    #[test]
    fn event_formatting_uses_explicit_scope_and_late_records() {
        let events = Arc::new(RwLock::new(Vec::new()));
        let formatter = OsLogLayer::new("org.plabayo.rama.test", "format")
            .unwrap()
            .with_target(false)
            .with_span_context(true);
        let capture = FormattingCapture {
            formatter,
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(tracing::subscriber::registry().with(capture));

        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!("request", request.id = tracing::field::Empty);
            span.record("request.id", 42_u64);
            tracing::info!(parent: &span, answer = 42, "explicit parent");
            tracing::info!(parent: None, "explicit root");
        });

        let events = events.read().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].contains("explicit parent answer=42"));
        assert!(events[0].contains("spans=[request{request.id=42}]"));
        assert_eq!(events[1], "explicit root");
    }

    #[test]
    fn split_privacy_keeps_fields_out_of_public_message() {
        let events = Arc::new(RwLock::new(Vec::new()));
        let formatter = OsLogLayer::new("org.plabayo.rama.test", "format")
            .unwrap()
            .with_privacy(Privacy::PublicMessagePrivateFields)
            .with_target(false)
            .with_span_context(true);
        let capture = FormattingCapture {
            formatter,
            events: Arc::clone(&events),
        };
        let dispatch = tracing::Dispatch::new(tracing::subscriber::registry().with(capture));

        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!("request", user = "private-user");
            tracing::info!(parent: &span, endpoint = "/private", "request finished");
        });

        let events = events.read().unwrap();
        assert!(events[0].starts_with("request finished |private| "));
        assert!(
            !events[0]
                .split(" |private| ")
                .next()
                .unwrap()
                .contains("private")
        );
        assert!(events[0].contains("endpoint=\"/private\""));
        assert!(events[0].contains("user=\"private-user\""));
    }
}
