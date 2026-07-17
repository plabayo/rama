use std::fmt;

use crate::engine::{GlobalEntry, NamespaceEntry};
use crate::func::{JsFn, RawHostFn};
use crate::runtime::{IntoJsGlobal, JsGlobal};
use crate::value::{JsStr, JsValue};

/// The `console` host object: nothing more than a regular global
/// with the well-known console methods as host functions.
///
/// Every runtime injects [`Console::void`] by default, so console
/// calls always work and silently drop their arguments. Register your
/// own via [`JsRuntimeBuilder::with_global`][crate::JsRuntimeBuilder::with_global]
/// to replace it: [`Console::trace`] routes all methods through rama's
/// standard `tracing` support, and either constructor is just a starting
/// point whose individual methods can be overwritten builder-style with
/// any host function.
pub struct Console {
    log: ConsoleSlot,
    debug: ConsoleSlot,
    info: ConsoleSlot,
    warn: ConsoleSlot,
    error: ConsoleSlot,
}

enum ConsoleSlot {
    Void,
    Tracing(TraceLevel),
    Custom(RawHostFn),
}

#[derive(Clone, Copy)]
enum TraceLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl Default for Console {
    fn default() -> Self {
        Self::void()
    }
}

impl fmt::Debug for Console {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot_name = |slot: &ConsoleSlot| match slot {
            ConsoleSlot::Void => "void",
            ConsoleSlot::Tracing(_) => "tracing",
            ConsoleSlot::Custom(_) => "custom",
        };
        f.debug_struct("Console")
            .field("log", &slot_name(&self.log))
            .field("debug", &slot_name(&self.debug))
            .field("info", &slot_name(&self.info))
            .field("warn", &slot_name(&self.warn))
            .field("error", &slot_name(&self.error))
            .finish()
    }
}

macro_rules! console_method_setters {
    ($($name:ident: $with:ident, $set:ident);+ $(;)?) => {
        $(
            /// Overwrite the
            #[doc = concat!("`console.", stringify!($name), "`")]
            /// method with the given host function.
            #[must_use]
            pub fn $with<A, F: JsFn<A>>(mut self, f: F) -> Self {
                self.$name = ConsoleSlot::Custom(f.into_raw_host_fn());
                self
            }

            /// Overwrite the
            #[doc = concat!("`console.", stringify!($name), "`")]
            /// method with the given host function.
            pub fn $set<A, F: JsFn<A>>(&mut self, f: F) -> &mut Self {
                self.$name = ConsoleSlot::Custom(f.into_raw_host_fn());
                self
            }
        )+
    };
}

impl Console {
    /// A console which silently drops all messages (the default).
    #[must_use]
    pub fn void() -> Self {
        Self {
            log: ConsoleSlot::Void,
            debug: ConsoleSlot::Void,
            info: ConsoleSlot::Void,
            warn: ConsoleSlot::Void,
            error: ConsoleSlot::Void,
        }
    }

    /// A console which routes all messages through rama's
    /// standard `tracing` support, at the matching level
    /// (`console.log` traces at info level).
    #[must_use]
    pub fn trace() -> Self {
        Self {
            log: ConsoleSlot::Tracing(TraceLevel::Info),
            debug: ConsoleSlot::Tracing(TraceLevel::Debug),
            info: ConsoleSlot::Tracing(TraceLevel::Info),
            warn: ConsoleSlot::Tracing(TraceLevel::Warn),
            error: ConsoleSlot::Tracing(TraceLevel::Error),
        }
    }

    console_method_setters! {
        log: with_log, set_log;
        debug: with_debug, set_debug;
        info: with_info, set_info;
        warn: with_warn, set_warn;
        error: with_error, set_error;
    }
}

impl IntoJsGlobal for Console {
    fn into_global_entry(self) -> JsGlobal {
        let Self {
            log,
            debug,
            info,
            warn,
            error,
        } = self;
        let entries = [
            ("log", log),
            ("debug", debug),
            ("info", info),
            ("warn", warn),
            ("error", error),
        ]
        .into_iter()
        .map(|(name, slot)| {
            let func: RawHostFn = match slot {
                ConsoleSlot::Void => std::sync::Arc::new(|_| Ok(JsValue::Undefined)),
                ConsoleSlot::Tracing(level) => std::sync::Arc::new(move |args: Vec<JsValue>| {
                    emit_trace(level, &args);
                    Ok(JsValue::Undefined)
                }),
                ConsoleSlot::Custom(func) => func,
            };
            (JsStr::new_static(name), NamespaceEntry::Fn(func))
        })
        .collect();
        JsGlobal(GlobalEntry::Namespace(entries))
    }
}

/// Space-separated console arguments, formatted in a single
/// pass straight into the subscriber (no intermediate allocations).
struct ConsoleArgs<'a>(&'a [JsValue]);

impl fmt::Display for ConsoleArgs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, value) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            fmt::Display::fmt(value, f)?;
        }
        Ok(())
    }
}

fn emit_trace(level: TraceLevel, args: &[JsValue]) {
    use rama_core::telemetry::tracing;

    let message = ConsoleArgs(args);
    match level {
        TraceLevel::Debug => tracing::debug!(target: "rama_js::console", "{message}"),
        TraceLevel::Info => tracing::info!(target: "rama_js::console", "{message}"),
        TraceLevel::Warn => tracing::warn!(target: "rama_js::console", "{message}"),
        TraceLevel::Error => tracing::error!(target: "rama_js::console", "{message}"),
    }
}
