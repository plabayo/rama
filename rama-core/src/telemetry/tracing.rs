//! Tracing core rexport and utilities, for your conveneince

#[doc(inline)]
pub use tracing::*;

/// Re-export of [`tracing_appender`] plus rama utilities that go with it.
#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
pub mod appender {
    #[doc(inline)]
    pub use ::tracing_appender::*;

    #[doc(inline)]
    pub use ::tracing_appender::{
        non_blocking::{NonBlocking, NonBlockingBuilder, WorkerGuard},
        rolling::{RollingFileAppender, Rotation},
    };

    use std::path::Path;

    /// Build a [`RollingFileAppender`] wrapped in [`NonBlocking`] so
    /// file I/O (including rotation) runs on the appender's worker
    /// thread instead of the caller's. The returned [`WorkerGuard`]
    /// must be kept alive for the program's lifetime; drop it just
    /// before exit to flush pending records.
    pub fn rolling_dedicated_thread(
        rotation: Rotation,
        directory: impl AsRef<Path>,
        file_name_prefix: impl AsRef<Path>,
    ) -> (NonBlocking, WorkerGuard) {
        let appender = RollingFileAppender::new(rotation, directory, file_name_prefix);
        rolling_dedicated_thread_with_builder(NonBlockingBuilder::default(), appender)
    }

    /// [`rolling_dedicated_thread`] variant accepting a pre-configured
    /// [`NonBlockingBuilder`] (custom buffer limit, lossy vs.
    /// blocking back-pressure, thread name, …).
    pub fn rolling_dedicated_thread_with_builder(
        builder: NonBlockingBuilder,
        appender: RollingFileAppender,
    ) -> (NonBlocking, WorkerGuard) {
        builder.finish(appender)
    }
}

#[cfg(feature = "opentelemetry")]
#[cfg_attr(docsrs, doc(cfg(feature = "opentelemetry")))]
#[doc(inline)]
pub use tracing_opentelemetry::*;

/// Tracing setup for test binaries that capture logs per thread.
#[cfg(feature = "test-utils")]
#[cfg_attr(docsrs, doc(cfg(feature = "test-utils")))]
pub mod test_utils {
    use std::sync::OnceLock;
    use tracing::{Dispatch, Event, Metadata, Subscriber, span, subscriber::Interest};

    /// Keep every log line visible to captures installed per thread; call it before a capture.
    ///
    /// Tracing caches for the whole process whether a log line is wanted. While at most one
    /// dispatcher is registered, the first registration of a line asks only the default of the
    /// thread that reaches it: reached first on a thread without a subscriber, the line is cached
    /// as unwanted, and a capture installed with
    /// [`with_default`](tracing::subscriber::with_default) on another thread never sees it.
    ///
    /// The first call registers two dispatchers for the whole process that want nothing and leave
    /// every line undecided. Every later first registration is then decided under tracing's lock,
    /// across all registered dispatchers, so no line is cached as unwanted and each event is
    /// checked against the subscriber of the thread that emits it. Later calls do nothing, and no
    /// global default is set.
    ///
    /// A registration already under way on another thread during the first call can still cache
    /// its line as unwanted, so call it before the test starts any thread that logs. A runner that
    /// gives each test its own process, such as nextest, leaves no such thread.
    pub fn prepare_for_captures() {
        static REGISTERED: OnceLock<[Dispatch; 2]> = OnceLock::new();
        REGISTERED.get_or_init(|| [Dispatch::new(Undecided), Dispatch::new(Undecided)]);
    }

    /// Wants no event, and leaves every log line for the current thread's subscriber to decide.
    struct Undecided;

    impl Subscriber for Undecided {
        fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }

        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            false
        }

        fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

        fn event(&self, _event: &Event<'_>) {}

        fn enter(&self, _span: &span::Id) {}

        fn exit(&self, _span: &span::Id) {}
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use parking_lot::Mutex;
        use std::{
            sync::{
                atomic::{AtomicU8, Ordering},
                mpsc,
            },
            thread::{self, ThreadId},
            time::Duration,
        };
        use tracing::{dispatcher, subscriber::with_default};
        use tracing_core::{
            Kind, Level,
            callsite::{self, Callsite},
            metadata,
        };

        const UNSET: u8 = 0;
        const NEVER: u8 = 1;
        const SOMETIMES: u8 = 2;
        const ALWAYS: u8 = 3;

        /// Pauses the first registration on one thread inside [`Callsite::metadata`], after
        /// tracing chose how to decide the callsite's interest.
        struct PausingCallsite {
            interest: AtomicU8,
            pause: Mutex<Option<Pause>>,
        }

        struct Pause {
            thread: ThreadId,
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }

        impl Callsite for PausingCallsite {
            fn set_interest(&self, interest: Interest) {
                let interest = if interest.is_never() {
                    NEVER
                } else if interest.is_always() {
                    ALWAYS
                } else {
                    SOMETIMES
                };
                self.interest.store(interest, Ordering::SeqCst);
            }

            fn metadata(&self) -> &Metadata<'_> {
                let pause = self
                    .pause
                    .lock()
                    .take_if(|pause| pause.thread == thread::current().id());
                if let Some(pause) = pause {
                    _ = pause.started.send(());
                    // Bounded, so a regression fails the test instead of hanging it.
                    _ = pause.release.recv_timeout(Duration::from_secs(10));
                }
                &PROBE_METADATA
            }
        }

        static PROBE: PausingCallsite = PausingCallsite {
            interest: AtomicU8::new(UNSET),
            pause: Mutex::new(None),
        };

        static PROBE_METADATA: Metadata<'static> = metadata! {
            name: "registration probe",
            target: module_path!(),
            level: Level::DEBUG,
            fields: &[],
            callsite: &PROBE,
            kind: Kind::EVENT,
        };

        /// Wants every event, as a capture does.
        struct Wanting;

        impl Subscriber for Wanting {
            fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
                true
            }

            fn new_span(&self, _span: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }

            fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

            fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

            fn event(&self, _event: &Event<'_>) {}

            fn enter(&self, _span: &span::Id) {}

            fn exit(&self, _span: &span::Id) {}
        }

        #[test]
        fn a_registration_in_flight_under_a_no_op_default_cannot_hide_a_line() {
            prepare_for_captures();

            let (started, on_started) = mpsc::channel();
            let (release, on_release) = mpsc::channel();
            let worker = thread::spawn(move || {
                *PROBE.pause.lock() = Some(Pause {
                    thread: thread::current().id(),
                    started,
                    release: on_release,
                });
                // A default no dispatcher registry knows of, which wants nothing.
                dispatcher::with_default(&Dispatch::none(), || {
                    callsite::register(&PROBE);
                });
            });
            on_started
                .recv_timeout(Duration::from_secs(10))
                .expect("the probe registers on the worker");
            // Released from elsewhere: the capture below may wait for the paused registration.
            let releaser = thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                _ = release.send(());
            });
            with_default(Wanting, || worker.join().unwrap());
            releaser.join().unwrap();
            assert_eq!(PROBE.interest.load(Ordering::SeqCst), SOMETIMES);
        }
    }
}

// NOTE: once <https://github.com/tokio-rs/tracing/issues/3310>
// is resolved (if ever) we should be able to remove these utility macros again

#[doc(hidden)]
pub mod __private {
    pub use tracing::span as __og_span;
}

#[cfg(not(feature = "opentelemetry"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, )
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                $lvl,
                $name,
                $($fields)*
            )
        }
    };
    (target: $target:expr, parent: $parent:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                parent: $parent,
                $lvl,
                $name,
                $($fields)*
            )
        }
    };
}

#[cfg(feature = "opentelemetry")]
#[macro_export]
#[doc(hidden)]
macro_rules! __span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, )
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::{OpenTelemetrySpanExt as _, field};
            use $crate::telemetry::opentelemetry::trace::TraceContextExt as _;
            use $crate::telemetry::opentelemetry::{SpanId, TraceId};

            let span = $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                $lvl,
                $name,
                span.id = field::Empty,
                trace.id = field::Empty,
                $($fields)*
            );

            if !span.is_disabled() {
                let otel_ctx = span.context();
                let span_ref = otel_ctx.span();
                let span_ctx = span_ref.span_context();

                let span_id = span_ctx.span_id();
                if span_id != SpanId::INVALID {
                    span.record("span.id", span_id.to_string());
                }

                let trace_id = span_ctx.trace_id();
                if trace_id != TraceId::INVALID {
                    span.record("trace.id", trace_id.to_string());
                }
            }

            span
        }
    };
    (target: $target:expr, parent: $parent:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::{OpenTelemetrySpanExt as _, field};
            use $crate::telemetry::opentelemetry::trace::TraceContextExt as _;
            use $crate::telemetry::opentelemetry::{SpanId, TraceId};

            let span = $crate::telemetry::tracing::__private::__og_span!(
                target: $target,
                parent: $parent,
                $lvl,
                $name,
                span.id = field::Empty,
                trace.id = field::Empty,
                $($fields)*
            );

            if !span.is_disabled() {
                let otel_ctx = span.context();
                let span_ref = otel_ctx.span();
                let span_ctx = span_ref.span_context();

                let span_id = span_ctx.span_id();
                if span_id != SpanId::INVALID {
                    span.record("span.id", span_id.to_string());
                }

                let trace_id = span_ctx.trace_id();
                if trace_id != TraceId::INVALID {
                    span.record("trace.id", trace_id.to_string());
                }
            }

            span
        }
    };
}

#[doc(inline)]
pub use crate::__span as span;

#[macro_export]
#[doc(hidden)]
macro_rules! __trace_span {
    ($name:expr) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::TRACE, $name)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: $target, $crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__trace_span as trace_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __debug_span {
    ($name:expr) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::DEBUG, $name)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: $target, $crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__debug_span as debug_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __info_span {
    ($name:expr) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::INFO, $name)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!($crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::span!(target: $target, $crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__info_span as info_span;

#[cfg(not(feature = "opentelemetry"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __root_span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name,)
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            let span = $crate::telemetry::tracing::span!(
                target: $target,
                parent: None,
                $lvl,
                $name,
                $($fields)*
            );

            if !span.is_disabled() {
                span.follows_from($crate::telemetry::tracing::Span::current());
            }

            span
        }
    };
}

#[cfg(feature = "opentelemetry")]
#[macro_export]
#[doc(hidden)]
macro_rules! __root_span {
    ($lvl:expr, $name:expr) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name,)
    };
    ($lvl:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: module_path!(), $lvl, $name, $($fields)*)
    };
    (target: $target:expr, $lvl:expr, $name:expr, $($fields:tt)*) => {
        {
            use $crate::telemetry::tracing::OpenTelemetrySpanExt as _;
            use $crate::telemetry::opentelemetry::{trace::{get_active_span, TraceContextExt}, KeyValue};

            let span = $crate::telemetry::tracing::span!(
                target: $target,
                parent: None,
                $lvl,
                $name,
                $($fields)*
            );

            // Linking allocates and walks the OTel context: skip it for a
            // span the subscriber filtered out (the common case per connection).
            if !span.is_disabled() {
                let src_span = $crate::telemetry::tracing::Span::current();
                src_span.add_link_with_attributes(
                    span.context().span().span_context().clone(),
                    vec![KeyValue::new("opentracing.ref_type", "child_of")],
                );

                span.follows_from(&src_span);
                span.add_link_with_attributes(
                    get_active_span(|span| span.span_context().clone()),
                    vec![KeyValue::new("opentracing.ref_type", "follows_from")],
                );
            }

            span
        }
    };
}

#[doc(inline)]
pub use crate::__root_span as root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __trace_root_span {
    ($name:expr) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::TRACE, $name,)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::TRACE, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__trace_root_span as trace_root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __debug_root_span {
    ($name:expr) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::DEBUG, $name,)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::DEBUG, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__debug_root_span as debug_root_span;

#[macro_export]
#[doc(hidden)]
macro_rules! __info_root_span {
    ($name:expr) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::INFO, $name,)
    };
    ($name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!($crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    };
    (target: $target:expr, $name:expr, $($fields:tt)*) => {
        $crate::telemetry::tracing::root_span!(target: $target, $crate::telemetry::tracing::Level::INFO, $name, $($fields)*)
    }
}

#[doc(inline)]
pub use crate::__info_root_span as info_root_span;
