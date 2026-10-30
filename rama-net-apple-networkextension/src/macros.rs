/// Emit the C ABI of `rama_apple_ne_ffi.h` for one transparent proxy.
///
/// ```text
/// transparent_proxy_ffi! {
///     init = init,                     // fn(Option<TransparentProxyInitConfig>) -> bool
///     engine_builder = make_builder(), // a `TransparentProxyEngineBuilder`
/// }
/// ```
///
/// `init` receives the decoded, owned
/// [`TransparentProxyInitConfig`](crate::tproxy::TransparentProxyInitConfig)
/// (`None` when the foreign caller passed no config), so it needs no unsafe
/// code and cannot keep foreign memory alive.
///
/// # Safety of the generated symbols
///
/// The caller of a generated `unsafe extern "C"` function must uphold
/// *Values* and every other rule below that the function's `# Safety` cites.
///
/// * **Engine handles**: an `engine` argument is null or a handle returned by
///   `rama_transparent_proxy_engine_new*` of the same expansion and not yet
///   passed to `_engine_free` or `_engine_stop`. Calls on one engine may
///   overlap each other, but none may overlap or follow the freeing call.
/// * **Session handles**: a `session` argument is null or a handle returned
///   by the matching `_new_tcp_session` / `_new_udp_session` of the same
///   expansion and not yet passed to its `_session_free`. Calls on one session
///   never overlap, including from inside that session's callbacks, and none
///   follows its `_session_free`.
/// * **Byte ranges**: every `BytesView` and pointer + length argument meets
///   the byte-range contract of `rama_net_apple_networkextension::ffi::BytesView`
///   for the duration of the call.
/// * **Struct pointers**: a `*const` struct argument is null or points to an
///   aligned, initialized value of that type (every `bool` 0 or 1) that
///   nothing writes during the call; its pointer + length pairs follow
///   *Byte ranges*.
/// * **Callbacks**: a callback struct meets the callback contract of
///   `rama_net_apple_networkextension::ffi::tproxy::TransparentProxyTcpSessionCallbacks`.
/// * **Values**: every by-value argument is a valid value of its Rust type:
///   each `bool` is 0 or 1 and each non-null function pointer points to a
///   function of the declared signature.
///
/// None of these functions unwinds: a Rust panic escaping one aborts the
/// process, as for any `extern "C"` function. `_initialize` and
/// `_engine_new*` catch panics from user code and report failure instead.
///
/// **Linking**: every symbol is exported unmangled under a fixed name, so
/// this macro must expand at most once per linked image and no other object
/// in it may define these names.
#[macro_export]
#[doc(hidden)]
macro_rules! __transparent_proxy_ffi {
    ($($tt:tt)*) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: ()]
            [engine_builder: ()]
            $($tt)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_parse {
    (
        [init: $init:tt]
        [engine_builder: $engine_builder:tt]
    ) => {
        $crate::__transparent_proxy_ffi_require_init!($init);
        $crate::__transparent_proxy_ffi_require_engine_builder!($engine_builder);
        $crate::__transparent_proxy_ffi_emit! {
            $init,
            $engine_builder
        }
    };
    (
        [init: $init:tt]
        [engine_builder: $engine_builder:tt]
        ,
        $($rest:tt)*
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [engine_builder: $engine_builder]
            $($rest)*
        }
    };
    (
        [init: $init:tt]
        [engine_builder: $engine_builder:tt]
        init = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: ($value)]
            [engine_builder: $engine_builder]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [engine_builder: $engine_builder:tt]
        engine_builder = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [engine_builder: ($value)]
            $($($rest)*)?
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_require_init {
    (()) => {
        compile_error!("transparent_proxy_ffi!: missing required `init = ...` entry");
    };
    (($value:expr)) => {};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_require_engine_builder {
    (()) => {
        compile_error!("transparent_proxy_ffi!: missing required `engine_builder = ...` entry");
    };
    (($value:expr)) => {};
}

// The generated FFI shares one engine across threads and moves sessions
// between them; the *Engine handles* / *Session handles* rules rely on this.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    const fn assert_send<T: Send>() {}
    assert_send_sync::<crate::tproxy::BoxedTransparentProxyEngine>();
    assert_send::<crate::tproxy::TransparentProxyTcpSession>();
    assert_send::<crate::tproxy::TransparentProxyUdpSession>();
};

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_emit {
    (($init:expr), ($engine_builder:expr)) => {
        pub type RamaTransparentProxyEngine = $crate::tproxy::BoxedTransparentProxyEngine;
        pub type RamaTransparentProxyTcpSession = $crate::tproxy::TransparentProxyTcpSession;
        pub type RamaTransparentProxyUdpSession = $crate::tproxy::TransparentProxyUdpSession;
        pub type RamaTcpDeliverStatus = $crate::tproxy::TcpDeliverStatus;

        pub type RamaTransparentProxyFlowMeta = $crate::ffi::tproxy::TransparentProxyFlowMeta;
        pub type RamaTransparentProxyFlowAction = $crate::ffi::tproxy::TransparentProxyFlowAction;
        pub type RamaTransparentProxyConfig = $crate::ffi::tproxy::TransparentProxyConfig;
        pub type RamaTransparentProxyInitConfig = $crate::ffi::tproxy::TransparentProxyInitConfig;
        pub type RamaTransparentProxyTcpSessionCallbacks =
            $crate::ffi::tproxy::TransparentProxyTcpSessionCallbacks;
        pub type RamaTransparentProxyUdpSessionCallbacks =
            $crate::ffi::tproxy::TransparentProxyUdpSessionCallbacks;
        pub type RamaNwEgressParameters = $crate::ffi::tproxy::NwEgressParameters;
        pub type RamaTcpEgressConnectOptions = $crate::ffi::tproxy::TcpEgressConnectOptions;
        pub type RamaTransparentProxyTcpEgressCallbacks =
            $crate::ffi::tproxy::TransparentProxyTcpEgressCallbacks;
        pub type RamaTransparentProxyTcpPromoteCallbacks =
            $crate::ffi::tproxy::TransparentProxyTcpPromoteCallbacks;
        pub type RamaPromoteConfirmStatus =
            $crate::ffi::tproxy::PromoteConfirmStatus;

        #[repr(C)]
        pub struct RamaTransparentProxyTcpSessionResult {
            pub action: RamaTransparentProxyFlowAction,
            pub session: *mut RamaTransparentProxyTcpSession,
        }

        #[repr(C)]
        pub struct RamaTransparentProxyUdpSessionResult {
            pub action: RamaTransparentProxyFlowAction,
            pub session: *mut RamaTransparentProxyUdpSession,
        }

        // ABI pins against `rama_apple_ne_ffi.h` on 64-bit Apple targets.
        #[cfg(target_pointer_width = "64")]
        const _: () = {
            assert!(::std::mem::size_of::<RamaTransparentProxyTcpSessionResult>() == 16);
            assert!(::std::mem::offset_of!(RamaTransparentProxyTcpSessionResult, session) == 8);
            assert!(::std::mem::size_of::<RamaTransparentProxyUdpSessionResult>() == 16);
            assert!(::std::mem::offset_of!(RamaTransparentProxyUdpSessionResult, session) == 8);
        };

        fn __rama_build_transparent_proxy_engine(
            opaque_config: Option<::std::sync::Arc<[u8]>>,
        ) -> Result<
            RamaTransparentProxyEngine,
            ::std::boxed::Box<dyn ::std::error::Error + Send + Sync + 'static>,
        > {
            let builder = ($engine_builder).maybe_with_opaque_config(opaque_config);
            let engine = builder.build()?;
            Ok(engine.into())
        }

        // Pins the `init` signature so closures infer their argument type.
        fn __rama_run_transparent_proxy_init<F>(
            init: F,
            config: Option<$crate::tproxy::TransparentProxyInitConfig>,
        ) -> bool
        where
            F: FnOnce(Option<$crate::tproxy::TransparentProxyInitConfig>) -> bool,
        {
            init(config)
        }

        /// # Safety
        ///
        /// The caller must uphold *Struct pointers* for `config` (see
        /// `transparent_proxy_ffi!`). The config is copied before `init` runs.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_initialize(
            config: *const RamaTransparentProxyInitConfig,
        ) -> bool {
            let config = if config.is_null() {
                None
            } else {
                // SAFETY: `&*config` needs an aligned pointer to an initialized,
                // unwritten config for the borrow; non-null is checked and the
                // rest is *Struct pointers* for this call.
                let config = unsafe { &*config };
                // SAFETY: `as_owned_rust_type` needs every pair to meet the
                // byte-range contract for this call: *Struct pointers*.
                Some(unsafe { config.as_owned_rust_type() })
            };

            match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                __rama_run_transparent_proxy_init($init, config)
            })) {
                Ok(initialized) => initialized,
                Err(_) => {
                    $crate::tproxy::log_engine_build_panic(
                        "initialize transparent proxy application",
                    );
                    false
                }
            }
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see
        /// `transparent_proxy_ffi!`). Returns null or a `Box::into_raw` config
        /// built by `TransparentProxyConfig::from_rust_type`, owned by the
        /// caller until `rama_transparent_proxy_config_free`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_get_config(
            engine: *mut RamaTransparentProxyEngine,
        ) -> *mut RamaTransparentProxyConfig {
            if engine.is_null() {
                return ::std::ptr::null_mut();
            }

            // SAFETY: `&*engine` needs an aligned pointer to a live engine with
            // no `&mut` alias; non-null is checked and *Engine handles* gives the
            // rest (overlapping `&` borrows are fine as the engine is `Sync`).
            let engine = unsafe { &*engine };

            let config = engine.transparent_proxy_config();
            let ffi_cfg = RamaTransparentProxyConfig::from_rust_type(&config);
            ::std::boxed::Box::into_raw(::std::boxed::Box::new(ffi_cfg))
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_udp_idle_timeout_ms(
            engine: *mut RamaTransparentProxyEngine,
        ) -> u64 {
            if engine.is_null() {
                return 0;
            }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            let engine = unsafe { &*engine };
            engine.udp_idle_timeout_ms()
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_udp_channel_capacity(
            engine: *mut RamaTransparentProxyEngine,
        ) -> usize {
            if engine.is_null() { return 0; }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            unsafe { &*engine }.udp_channel_capacity()
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_udp_ingress_per_flow_max_bytes(
            engine: *mut RamaTransparentProxyEngine,
        ) -> usize {
            if engine.is_null() { return 0; }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            unsafe { &*engine }.udp_ingress_per_flow_max_bytes()
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_udp_ingress_global_max_bytes(
            engine: *mut RamaTransparentProxyEngine,
        ) -> usize {
            if engine.is_null() { return 0; }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            unsafe { &*engine }.udp_ingress_global_max_bytes()
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_writer_memory_max_bytes(
            engine: *mut RamaTransparentProxyEngine,
        ) -> usize {
            if engine.is_null() { return 0; }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            unsafe { &*engine }.writer_memory_max_bytes()
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_writer_memory_max_items(
            engine: *mut RamaTransparentProxyEngine,
        ) -> usize {
            if engine.is_null() { return 0; }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            unsafe { &*engine }.writer_memory_max_items()
        }

        /// # Safety
        ///
        /// The caller must ensure `config` is null or a pointer returned by
        /// `rama_transparent_proxy_get_config` of this expansion, with the
        /// pointee unmodified, not freed before and not used afterwards.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_config_free(
            config: *mut RamaTransparentProxyConfig,
        ) {
            if config.is_null() {
                return;
            }

            // SAFETY: `Box::from_raw` needs an unfreed `Box::into_raw` pointer of
            // this type with no other user. Non-null is checked; the
            // precondition and `_get_config`'s postcondition give the rest.
            let config = unsafe { ::std::boxed::Box::from_raw(config) };
            // SAFETY: `free` needs unmodified `from_rust_type` fields freed once;
            // `_get_config`'s postcondition and this fn's precondition give that.
            unsafe { config.free() }
        }

        /// Allocate a new transparent proxy engine. Returns null on failure,
        /// else a `Box::into_raw` handle owned by the caller until
        /// `rama_transparent_proxy_engine_free` or `_engine_stop`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub extern "C" fn rama_transparent_proxy_engine_new()
        -> *mut RamaTransparentProxyEngine {
            // SAFETY: a null, zero-length view meets *Byte ranges*.
            unsafe {
                rama_transparent_proxy_engine_new_with_config($crate::ffi::BytesView {
                    ptr: ::std::ptr::null(),
                    len: 0,
                })
            }
        }

        /// # Safety
        ///
        /// The caller must uphold *Byte ranges* for `engine_config` (see
        /// `transparent_proxy_ffi!`); the bytes are copied. Returns null on
        /// failure, else a `Box::into_raw` handle owned by the caller until
        /// `rama_transparent_proxy_engine_free` or `_engine_stop`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new_with_config(
            engine_config: $crate::ffi::BytesView,
        ) -> *mut RamaTransparentProxyEngine {
            let opaque_config = if engine_config.ptr.is_null() || engine_config.len == 0 {
                None
            } else {
                // SAFETY: `into_slice` needs the byte-range contract for the
                // borrow, which ends at the `Arc` copy; *Byte ranges* gives it.
                let bytes = unsafe { engine_config.into_slice() };
                Some(::std::sync::Arc::<[u8]>::from(bytes))
            };

            let engine = match ::std::panic::catch_unwind(
                ::std::panic::AssertUnwindSafe(|| {
                    __rama_build_transparent_proxy_engine(opaque_config)
                }),
            ) {
                Ok(Ok(engine)) => engine,
                Ok(Err(err)) => {
                    $crate::tproxy::log_engine_build_error(
                        err.as_ref(),
                        "create transparent proxy engine",
                    );
                    return ::std::ptr::null_mut();
                }
                Err(_) => {
                    $crate::tproxy::log_engine_build_panic(
                        "create transparent proxy engine",
                    );
                    return ::std::ptr::null_mut();
                }
            };

            ::std::boxed::Box::into_raw(::std::boxed::Box::new(engine))
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see
        /// `transparent_proxy_ffi!`); the handle is consumed.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_free(
            engine: *mut RamaTransparentProxyEngine,
        ) {
            if engine.is_null() {
                return;
            }

            // SAFETY: `Box::from_raw` needs an unfreed `Box::into_raw` pointer of
            // this type with no other user. Non-null is checked; the
            // `_engine_new_with_config` postcondition and *Engine handles* (no
            // overlapping or later call) give the rest. Sessions own no borrow
            // of the engine (`'static` types), so they may outlive it.
            unsafe { drop(::std::boxed::Box::from_raw(engine)) };
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see
        /// `transparent_proxy_ffi!`); the handle is consumed.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_stop(
            engine: *mut RamaTransparentProxyEngine,
            reason: i32,
        ) {
            if engine.is_null() {
                return;
            }

            // SAFETY: as in `rama_transparent_proxy_engine_free`.
            let engine = unsafe { ::std::boxed::Box::from_raw(engine) };
            engine.stop(reason);
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_notify_system_sleep(
            engine: *mut RamaTransparentProxyEngine,
        ) {
            if engine.is_null() {
                return;
            }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            let engine = unsafe { &*engine };
            engine.notify_system_sleep();
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_notify_system_wake(
            engine: *mut RamaTransparentProxyEngine,
        ) {
            if engine.is_null() {
                return;
            }
            // SAFETY: as in `rama_transparent_proxy_get_config`.
            let engine = unsafe { &*engine };
            engine.notify_system_wake();
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles* and *Byte ranges* for
        /// `message` (see `transparent_proxy_ffi!`). The reply is empty or
        /// built by `BytesOwned::try_from`; release it with
        /// `rama_owned_bytes_free`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_handle_app_message(
            engine: *mut RamaTransparentProxyEngine,
            message: $crate::ffi::BytesView,
        ) -> $crate::ffi::BytesOwned {
            if engine.is_null() {
                return $crate::ffi::BytesOwned {
                    ptr: ::std::ptr::null_mut(),
                    len: 0,
                    cap: 0,
                };
            }

            // SAFETY: as in `rama_transparent_proxy_get_config`.
            let engine = unsafe { &*engine };
            // SAFETY: `into_slice` needs the byte-range contract for the borrow,
            // which ends at the copy below; *Byte ranges* gives it.
            let message = unsafe { message.into_slice() };
            let reply =
                engine.handle_app_message($crate::__private::Bytes::copy_from_slice(message));

            match reply
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default()
                .try_into()
            {
                Ok(bytes) => bytes,
                Err(err) => {
                    $crate::__private::tracing::debug!(%err, "failed to encode transparent proxy app message reply");
                    $crate::ffi::BytesOwned {
                        ptr: ::std::ptr::null_mut(),
                        len: 0,
                        cap: 0,
                    }
                }
            }
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles*, *Struct pointers* for
        /// `meta` and *Callbacks* for `callbacks` (see
        /// `transparent_proxy_ffi!`). A non-null `session` in the result is a
        /// `Box::into_raw` handle owned by the caller until
        /// `rama_transparent_proxy_tcp_session_free`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new_tcp_session(
            engine: *mut RamaTransparentProxyEngine,
            meta: *const RamaTransparentProxyFlowMeta,
            callbacks: RamaTransparentProxyTcpSessionCallbacks,
        ) -> RamaTransparentProxyTcpSessionResult {
            if engine.is_null() {
                return RamaTransparentProxyTcpSessionResult {
                    action: RamaTransparentProxyFlowAction::Passthrough,
                    session: ::std::ptr::null_mut(),
                };
            }

            let typed_meta = if meta.is_null() {
                $crate::tproxy::TransparentProxyFlowMeta::new(
                    $crate::tproxy::TransparentProxyFlowProtocol::Tcp,
                )
            } else {
                // SAFETY: `&*meta` needs an aligned pointer to a valid, unwritten
                // flow meta for the borrow; non-null is checked and *Struct
                // pointers* gives the rest for this call.
                let meta = unsafe { &*meta };
                // SAFETY: `as_owned_rust_type` needs every pair of `meta` to meet
                // the byte-range contract for this call: *Struct pointers*.
                match unsafe { meta.as_owned_rust_type() } {
                    Ok(meta) => meta,
                    Err(invalid) => {
                        // Unknown / future ABI protocol code on a TCP
                        // thunk. Fail-safe to passthrough rather than
                        // fabricate a TCP flow with possibly wrong
                        // semantics.
                        $crate::__private::tracing::warn!(
                            invalid_protocol = invalid,
                            "rama_transparent_proxy_engine_new_tcp_session: unknown protocol code; passing flow through"
                        );
                        return RamaTransparentProxyTcpSessionResult {
                            action: RamaTransparentProxyFlowAction::Passthrough,
                            session: ::std::ptr::null_mut(),
                        };
                    }
                }
            };

            // Kept as an integer so the closures are `Send + Sync`; *Callbacks*
            // lets `context` be used from any thread.
            let context = callbacks.context as usize;
            let on_server_bytes = callbacks.on_server_bytes;
            let on_client_read_demand = callbacks.on_client_read_demand;
            let on_server_closed = callbacks.on_server_closed;

            // SAFETY: as in `rama_transparent_proxy_get_config`.
            let engine = unsafe { &*engine };
            // Safety-usable invariant of `new_tcp_session`: these closures run
            // only until the returned session's `cancel` (run by `Drop`, so by
            // `_tcp_session_free`) returns, and never without a session.
            let result = engine.new_tcp_session(
                typed_meta,
                ::std::sync::Arc::new(move |bytes: &[u8]| -> RamaTcpDeliverStatus {
                    let Some(callback) = on_server_bytes else {
                        // No Swift writer registered → behave as accepted
                        // so the bridge keeps draining the duplex; bytes
                        // simply go nowhere.
                        return RamaTcpDeliverStatus::Accepted;
                    };
                    if bytes.is_empty() {
                        return RamaTcpDeliverStatus::Accepted;
                    }
                    // SAFETY: the callback needs a live `context` and a view
                    // meeting the byte-range contract for the call. *Callbacks*
                    // makes it a valid non-unwinding fn with `context` live
                    // until `_tcp_session_free` returns, which the invariant noted
                    // above orders after this call; the view borrows `bytes`.
                    let raw: u8 = unsafe {
                        callback(
                            context as *mut ::std::ffi::c_void,
                            $crate::ffi::BytesView {
                                ptr: bytes.as_ptr(),
                                len: bytes.len(),
                            },
                        )
                    };
                    RamaTcpDeliverStatus::from_ffi_u8(raw)
                }),
                ::std::sync::Arc::new(move || {
                    if let Some(callback) = on_client_read_demand {
                        // SAFETY: as for `on_server_bytes` above, without a view.
                        unsafe { callback(context as *mut ::std::ffi::c_void) };
                    }
                }),
                ::std::sync::Arc::new(move || {
                    if let Some(callback) = on_server_closed {
                        // SAFETY: as for `on_server_bytes` above, without a view.
                        unsafe { callback(context as *mut ::std::ffi::c_void) };
                    }
                }),
            );

            match result {
                $crate::tproxy::SessionFlowAction::Intercept(session) => {
                    RamaTransparentProxyTcpSessionResult {
                        action: RamaTransparentProxyFlowAction::Intercept,
                        session: ::std::boxed::Box::into_raw(::std::boxed::Box::new(session)),
                    }
                }
                $crate::tproxy::SessionFlowAction::Blocked => {
                    RamaTransparentProxyTcpSessionResult {
                        action: RamaTransparentProxyFlowAction::Blocked,
                        session: ::std::ptr::null_mut(),
                    }
                }
                $crate::tproxy::SessionFlowAction::Passthrough => {
                    RamaTransparentProxyTcpSessionResult {
                        action: RamaTransparentProxyFlowAction::Passthrough,
                        session: ::std::ptr::null_mut(),
                    }
                }
            }
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see
        /// `transparent_proxy_ffi!`); the handle is consumed. Once this
        /// returns, no callback of the session runs or will run.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_free(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: `Box::from_raw` needs an unfreed `Box::into_raw` pointer of
            // this type with no other user. Non-null is checked; the
            // `_new_tcp_session` postcondition and *Session handles* (no
            // overlapping or later call) give the rest.
            unsafe { drop(::std::boxed::Box::from_raw(session)) };
        }

        /// Deliver bytes from the intercepted client flow into the Rust TCP
        /// session.
        ///
        /// Returns a [`RamaTcpDeliverStatus`] code:
        /// - `0` (`Accepted`): Swift may keep reading from the kernel.
        /// - `1` (`Paused`): the per-flow ingress channel is full; Swift must
        ///   pause `flow.readData` until the matching `on_client_read_demand`
        ///   callback fires.
        /// - `2` (`Closed`): the session is being torn down; Swift must
        ///   terminate the read pump immediately — no further demand
        ///   callback will fire.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Byte ranges* for
        /// `bytes` (see `transparent_proxy_ffi!`); the bytes are copied.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_bytes(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesView,
        ) -> RamaTcpDeliverStatus {
            if session.is_null() {
                return RamaTcpDeliverStatus::Closed;
            }

            // SAFETY: `into_slice` needs the byte-range contract for the borrow,
            // which ends before return; *Byte ranges* gives it.
            let slice = unsafe { bytes.into_slice() };
            // SAFETY: `&mut *session` needs an aligned pointer to a live session
            // with no other access during the borrow. Non-null is checked;
            // *Session handles* (live, no overlapping or re-entrant call) gives
            // the rest.
            unsafe { (*session).on_client_bytes(slice) }
        }

        /// Owned-buffer variant of
        /// `rama_transparent_proxy_tcp_session_on_client_bytes`: the
        /// caller transfers ownership of the buffer so Rust can enqueue
        /// it without copying. See `RamaBytesOwnedView` for the contract
        /// — Rust takes ownership (and will invoke `release`) IFF this
        /// returns `Accepted` (0). On `Paused` (1) / `Closed` (2) the
        /// caller keeps ownership (and must replay on `Paused`, free on
        /// `Closed`), and `release` is NOT called.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see
        /// `transparent_proxy_ffi!`) and pass a `bytes` value satisfying the
        /// field invariants of `rama_net_apple_networkextension::ffi::BytesOwnedView`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_bytes_owned(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesOwnedView,
        ) -> RamaTcpDeliverStatus {
            if session.is_null() {
                // No session: ownership stays with the caller (the
                // `Closed` contract), so we must NOT release here.
                return RamaTcpDeliverStatus::Closed;
            }
            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_client_bytes_owned(bytes) }
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_eof(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_client_eof() };
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see
        /// `transparent_proxy_ffi!`). Once this returns, no callback of the
        /// session runs or will run.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_cancel(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).cancel() };
        }

        /// Register a Swift callback fired when the in-Rust service
        /// calls `PromoteHandle::into_passthrough` on this session.
        ///
        /// Idempotent: a later call replaces any prior registration.
        /// Calling on a null session is a no-op.
        ///
        /// See [`RamaTransparentProxyTcpPromoteCallbacks`] for the
        /// `context` lifetime / threading contract. Same-session FFI work must
        /// be queue-hopped rather than called synchronously in the callback.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Callbacks* for
        /// `callbacks` (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_register_promote_callbacks(
            session: *mut RamaTransparentProxyTcpSession,
            callbacks: RamaTransparentProxyTcpPromoteCallbacks,
        ) {
            if session.is_null() {
                return;
            }
            let Some(on_promote_request) = callbacks.on_promote_request else {
                return;
            };
            // SAFETY: `&*session` needs an aligned pointer to a live session
            // with no `&mut` alias during the borrow. Non-null is checked;
            // *Session handles* (live, no overlapping or re-entrant call) gives
            // the rest.
            let session = unsafe { &*session };
            // SAFETY: the callee needs `on_promote_request(context)` sound to call
            // repeatedly from any thread until this session's `cancel` returns.
            // *Callbacks* gives a valid non-unwinding fn callable from any thread
            // with `context` live until `_tcp_session_free` returns, and that
            // free runs `cancel` (via `Drop`) before returning.
            unsafe {
                session.register_promote_request_callback_raw(
                    callbacks.context,
                    on_promote_request,
                )
            };
        }

        /// Swift → Rust ACK for a pending promote cutover.
        ///
        /// On `Ok` the engine drops its ingress sender so the
        /// service sees EOF after draining in-flight bytes, then
        /// `into_passthrough` resolves with `Ok(())`.
        ///
        /// On `Failed`, `reason_ptr`/`reason_len` (optional UTF-8;
        /// pass `(null, 0)` for none) is surfaced via
        /// `PromoteError::SwiftCutoverFailed`; the in-Rust data
        /// path keeps running unchanged.
        ///
        /// Calling without a pending promote (e.g. before any
        /// service ran `into_passthrough`, or after a previous
        /// confirm) is a no-op.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Byte ranges* for
        /// `(reason_ptr, reason_len)` (see `transparent_proxy_ffi!`); the
        /// reason is copied.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_confirm_promoted(
            session: *mut RamaTransparentProxyTcpSession,
            status: u8,
            reason_ptr: *const ::std::ffi::c_char,
            reason_len: usize,
        ) {
            if session.is_null() {
                return;
            }
            // Decode the raw byte defensively: taking `u8` (not the enum)
            // at the boundary avoids UB if a caller passes an
            // out-of-range discriminant.
            let result = match RamaPromoteConfirmStatus::from_ffi_u8(status) {
                RamaPromoteConfirmStatus::Ok => Ok(()),
                RamaPromoteConfirmStatus::Failed => {
                    let reason = if reason_ptr.is_null() || reason_len == 0 {
                        String::new()
                    } else {
                        // SAFETY: `slice::from_raw_parts` needs a non-null `u8`
                        // pointer valid for `reason_len` initialized bytes in one
                        // allocation, `reason_len <= isize::MAX`, unwritten for
                        // the borrow. Non-null and non-zero are checked; *Byte
                        // ranges* gives the rest, and the borrow ends at the copy.
                        let slice = unsafe {
                            ::std::slice::from_raw_parts(reason_ptr.cast::<u8>(), reason_len)
                        };
                        ::std::str::from_utf8(slice)
                            .unwrap_or("<non-utf8 reason>")
                            .to_owned()
                    };
                    Err($crate::tproxy::PromoteError::SwiftCutoverFailed { reason })
                }
            };
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { (*session).confirm_promoted(result) };
        }

        /// # Safety
        ///
        /// The caller must uphold *Engine handles*, *Struct pointers* for
        /// `meta` and *Callbacks* for `callbacks` (see
        /// `transparent_proxy_ffi!`). A non-null `session` in the result is a
        /// `Box::into_raw` handle owned by the caller until
        /// `rama_transparent_proxy_udp_session_free`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new_udp_session(
            engine: *mut RamaTransparentProxyEngine,
            meta: *const RamaTransparentProxyFlowMeta,
            callbacks: RamaTransparentProxyUdpSessionCallbacks,
        ) -> RamaTransparentProxyUdpSessionResult {
            if engine.is_null() {
                return RamaTransparentProxyUdpSessionResult {
                    action: RamaTransparentProxyFlowAction::Passthrough,
                    session: ::std::ptr::null_mut(),
                };
            }

            let typed_meta = if meta.is_null() {
                $crate::tproxy::TransparentProxyFlowMeta::new(
                    $crate::tproxy::TransparentProxyFlowProtocol::Udp,
                )
            } else {
                // SAFETY: as in `rama_transparent_proxy_engine_new_tcp_session`.
                let meta = unsafe { &*meta };
                // SAFETY: as in `rama_transparent_proxy_engine_new_tcp_session`.
                match unsafe { meta.as_owned_rust_type() } {
                    Ok(meta) => meta,
                    Err(invalid) => {
                        $crate::__private::tracing::warn!(
                            invalid_protocol = invalid,
                            "rama_transparent_proxy_engine_new_udp_session: unknown protocol code; passing flow through"
                        );
                        return RamaTransparentProxyUdpSessionResult {
                            action: RamaTransparentProxyFlowAction::Passthrough,
                            session: ::std::ptr::null_mut(),
                        };
                    }
                }
            };

            // Kept as an integer so the closures are `Send + Sync`; *Callbacks*
            // lets `context` be used from any thread.
            let context = callbacks.context as usize;
            let on_server_datagram = callbacks.on_server_datagram;
            let on_client_read_demand = callbacks.on_client_read_demand;
            let on_server_closed = callbacks.on_server_closed;

            // SAFETY: as in `rama_transparent_proxy_get_config`.
            let engine = unsafe { &*engine };
            // Safety-usable invariant of `new_udp_session`: as for TCP, ending
            // when `on_client_close` (run by `Drop`, so by `_udp_session_free`)
            // returns.
            let result = engine.new_udp_session(
                typed_meta,
                ::std::sync::Arc::new(
                    move |bytes: &[u8], peer: ::std::option::Option<::std::net::SocketAddr>| {
                        let Some(callback) = on_server_datagram else {
                            return;
                        };
                        // Do NOT short-circuit on `bytes.is_empty()`: a
                        // zero-length UDP datagram is valid per RFC 768
                        // (DTLS heartbeats, NAT-binding probes, keep-
                        // alives rely on them). The analogous TCP filter
                        // is correct because an empty TCP read carries
                        // no semantic information.
                        let peer_scratch = $crate::ffi::UdpPeerScratch::new(peer);
                        // SAFETY: as for TCP `on_server_bytes`; the peer view
                        // points into `peer_scratch`, which stays unmoved and
                        // alive across the call (`as_view` safety-usable
                        // invariant).
                        unsafe {
                            callback(
                                context as *mut ::std::ffi::c_void,
                                $crate::ffi::BytesView {
                                    ptr: bytes.as_ptr(),
                                    len: bytes.len(),
                                },
                                peer_scratch.as_view(),
                            );
                        }
                        // Keep `peer_scratch` alive past the call above.
                        let _ = &peer_scratch;
                    },
                ),
                ::std::sync::Arc::new(move |probe_id| {
                    if let Some(callback) = on_client_read_demand {
                        // SAFETY: as for TCP `on_server_bytes`, without a view.
                        unsafe { callback(context as *mut ::std::ffi::c_void, probe_id) };
                    }
                }),
                ::std::sync::Arc::new(move || {
                    if let Some(callback) = on_server_closed {
                        // SAFETY: as for TCP `on_server_bytes`, without a view.
                        unsafe { callback(context as *mut ::std::ffi::c_void) };
                    }
                }),
            );

            match result {
                $crate::tproxy::SessionFlowAction::Intercept(session) => {
                    RamaTransparentProxyUdpSessionResult {
                        action: RamaTransparentProxyFlowAction::Intercept,
                        session: ::std::boxed::Box::into_raw(::std::boxed::Box::new(session)),
                    }
                }
                $crate::tproxy::SessionFlowAction::Blocked => {
                    RamaTransparentProxyUdpSessionResult {
                        action: RamaTransparentProxyFlowAction::Blocked,
                        session: ::std::ptr::null_mut(),
                    }
                }
                $crate::tproxy::SessionFlowAction::Passthrough => {
                    RamaTransparentProxyUdpSessionResult {
                        action: RamaTransparentProxyFlowAction::Passthrough,
                        session: ::std::ptr::null_mut(),
                    }
                }
            }
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see
        /// `transparent_proxy_ffi!`); the handle is consumed. Once this
        /// returns, no callback of the session runs or will run.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_free(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: as in `rama_transparent_proxy_tcp_session_free`, with the
            // `_new_udp_session` postcondition.
            unsafe { drop(::std::boxed::Box::from_raw(session)) };
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Byte ranges* for
        /// `bytes` and, when `peer.present`, for the peer host (see
        /// `transparent_proxy_ffi!`); both are copied.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_datagram(
            session: *mut RamaTransparentProxyUdpSession,
            bytes: $crate::ffi::BytesView,
            peer: $crate::ffi::UdpPeerView,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: `into_socket_addr` needs the byte-range contract for a
            // present host during the call; *Byte ranges* gives it.
            let peer = unsafe { peer.into_socket_addr() };
            // SAFETY: `into_slice` needs the byte-range contract for the borrow,
            // which ends before return; *Byte ranges* gives it.
            let slice = unsafe { bytes.into_slice() };
            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_client_datagram(slice, peer) };
        }

        /// Mark a completed UDP read before submitting any datagram from
        /// that completion. The demand callback must queue the foreign read
        /// and return rather than synchronously re-entering this session.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_read_complete(
            session: *mut RamaTransparentProxyUdpSession,
            probe_id: u64,
        ) {
            if session.is_null() { return; }
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { (*session).on_client_read_complete(probe_id) };
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see
        /// `transparent_proxy_ffi!`). Once this returns, no callback of the
        /// session runs or will run.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_close(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_client_close() };
        }

        /// Stable flow join key; zero for a null session.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_flow_id(
            session: *mut RamaTransparentProxyTcpSession,
        ) -> u64 {
            if session.is_null() {
                return 0;
            }
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { &*session }.flow_id()
        }

        /// Whether the existing establishment event is enabled. No session is needed.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub extern "C" fn rama_transparent_proxy_tcp_egress_reporting_enabled() -> bool {
            $crate::tproxy::tcp_egress_reporting_enabled()
        }

        /// Borrowed strings are logged synchronously; valid after cancel until free.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Struct pointers* for
        /// `report` (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_report_egress(
            session: *mut RamaTransparentProxyTcpSession,
            report: *const $crate::ffi::tproxy::TcpEgressReport,
        ) {
            if session.is_null() || report.is_null() || !$crate::tproxy::tcp_egress_reporting_enabled() {
                return;
            }
            // SAFETY: `&*report` needs an aligned pointer to a valid, unwritten
            // report for the borrow; non-null is checked and *Struct pointers*
            // gives the rest for this call.
            let report = unsafe { &*report };
            // SAFETY: `to_rust_type` needs both pairs to meet the byte-range
            // contract while the result is used, which ends before return.
            let report = unsafe { report.to_rust_type() };
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { &*session }.report_egress(&report);
        }

        // ── TCP egress ──────────────────────────────────────────────────────────

        /// Query handler-supplied egress connect options for a TCP session.
        ///
        /// Returns `true` and fills `out_options` when the handler provided custom
        /// options. Returns `false` when Swift should use `NWParameters` defaults.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see
        /// `transparent_proxy_ffi!`) and pass an `out_options` that is null or
        /// aligned and valid for writes of one `RamaTcpEgressConnectOptions`
        /// (it may be uninitialized). It is fully written iff `true` returns.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_get_egress_connect_options(
            session: *mut RamaTransparentProxyTcpSession,
            out_options: *mut RamaTcpEgressConnectOptions,
        ) -> bool {
            if session.is_null() || out_options.is_null() {
                return false;
            }

            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            let session = unsafe { &*session };
            let Some(opts) = session.egress_connect_options() else {
                return false;
            };

            let c_opts = RamaTcpEgressConnectOptions {
                parameters: $crate::ffi::tproxy::NwEgressParameters::from_rust_type(&opts.parameters),
                has_connect_timeout_ms: opts.connect_timeout.is_some(),
                // Saturate: an `as` cast would wrap a >u32::MAX-ms duration to a tiny value.
                connect_timeout_ms: opts
                    .connect_timeout
                    .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX))
                    .unwrap_or(0),
                has_linger_close_ms: opts.linger_close_timeout.is_some(),
                linger_close_ms: opts
                    .linger_close_timeout
                    .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX))
                    .unwrap_or(0),
                has_egress_eof_grace_ms: opts.egress_eof_grace.is_some(),
                egress_eof_grace_ms: opts
                    .egress_eof_grace
                    .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX))
                    .unwrap_or(0),
                // Keepalive: `enabled` always sent; unset timings (`has_`
                // false) let Swift apply its own defaults.
                tcp_keepalive_enabled: opts.tcp_keepalive_enabled,
                has_tcp_keepalive_idle_secs: opts.tcp_keepalive_idle.is_some(),
                // Round up to whole seconds (the NW API's unit): a sub-second
                // override must not floor to 0 and silently override Swift's
                // default with a degenerate value.
                tcp_keepalive_idle_secs: opts
                    .tcp_keepalive_idle
                    .map(|d| u32::try_from(d.as_millis().div_ceil(1000)).unwrap_or(u32::MAX))
                    .unwrap_or(0),
                has_tcp_keepalive_interval_secs: opts.tcp_keepalive_interval.is_some(),
                tcp_keepalive_interval_secs: opts
                    .tcp_keepalive_interval
                    .map(|d| u32::try_from(d.as_millis().div_ceil(1000)).unwrap_or(u32::MAX))
                    .unwrap_or(0),
                has_tcp_keepalive_count: opts.tcp_keepalive_count.is_some(),
                tcp_keepalive_count: opts.tcp_keepalive_count.unwrap_or(0),
                tcp_no_delay: opts.tcp_no_delay,
                has_tcp_no_push: opts.tcp_no_push.is_some(),
                tcp_no_push: opts.tcp_no_push.unwrap_or(false),
                has_tcp_no_options: opts.tcp_no_options.is_some(),
                tcp_no_options: opts.tcp_no_options.unwrap_or(false),
                has_tcp_retransmit_fin_drop: opts.tcp_retransmit_fin_drop.is_some(),
                tcp_retransmit_fin_drop: opts.tcp_retransmit_fin_drop.unwrap_or(false),
                has_tcp_disable_ack_stretching: opts.tcp_disable_ack_stretching.is_some(),
                tcp_disable_ack_stretching: opts.tcp_disable_ack_stretching.unwrap_or(false),
                has_tcp_enable_fast_open: opts.tcp_enable_fast_open.is_some(),
                tcp_enable_fast_open: opts.tcp_enable_fast_open.unwrap_or(false),
                has_tcp_disable_ecn: opts.tcp_disable_ecn.is_some(),
                tcp_disable_ecn: opts.tcp_disable_ecn.unwrap_or(false),
                has_tcp_maximum_segment_size: opts.tcp_maximum_segment_size.is_some(),
                tcp_maximum_segment_size: opts.tcp_maximum_segment_size.unwrap_or(0),
                // Same whole-second round-up as the keepalive timings above.
                has_tcp_connection_drop_time_secs: opts.tcp_connection_drop_time.is_some(),
                tcp_connection_drop_time_secs: opts
                    .tcp_connection_drop_time
                    .map(|d| u32::try_from(d.as_millis().div_ceil(1000)).unwrap_or(u32::MAX))
                    .unwrap_or(0),
                has_tcp_persist_timeout_secs: opts.tcp_persist_timeout.is_some(),
                tcp_persist_timeout_secs: opts
                    .tcp_persist_timeout
                    .map(|d| u32::try_from(d.as_millis().div_ceil(1000)).unwrap_or(u32::MAX))
                    .unwrap_or(0),
            };
            // SAFETY: `ptr::write` needs `out_options` aligned and valid for
            // writes of one value; non-null is checked and the precondition
            // gives the rest. It neither reads nor drops the old contents.
            unsafe { out_options.write(c_opts) };
            true
        }

        /// Activate a TCP session after the egress `NWConnection` is ready and the
        /// intercepted flow has been successfully opened.
        ///
        /// `callbacks` provides the Rust→Swift write channel: Rust calls
        /// `on_write_to_egress` to push bytes to the NWConnection, and
        /// `on_close_egress` when the egress write direction is done.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Callbacks* for
        /// `callbacks` (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_activate(
            session: *mut RamaTransparentProxyTcpSession,
            callbacks: RamaTransparentProxyTcpEgressCallbacks,
        ) {
            if session.is_null() {
                return;
            }

            // Kept as an integer so the closures are `Send + Sync`; *Callbacks*
            // lets `context` be used from any thread.
            let context = callbacks.context as usize;
            let on_write_to_egress = callbacks.on_write_to_egress;
            let on_close_egress = callbacks.on_close_egress;
            let on_egress_read_demand = callbacks.on_egress_read_demand;

            // Safety-usable invariant of `TransparentProxyTcpSession::activate`:
            // these closures run only until `cancel` (run by `Drop`) returns.
            let on_write = move |bytes: &[u8]| -> RamaTcpDeliverStatus {
                let Some(callback) = on_write_to_egress else {
                    // No Swift writer registered: behave as accepted
                    // so the bridge keeps pulling bytes; they go
                    // nowhere but at least the session doesn't stall.
                    return RamaTcpDeliverStatus::Accepted;
                };
                if bytes.is_empty() {
                    return RamaTcpDeliverStatus::Accepted;
                }
                // SAFETY: as for `on_server_bytes` in
                // `rama_transparent_proxy_engine_new_tcp_session`.
                let raw: u8 = unsafe {
                    callback(
                        context as *mut ::std::ffi::c_void,
                        $crate::ffi::BytesView {
                            ptr: bytes.as_ptr(),
                            len: bytes.len(),
                        },
                    )
                };
                RamaTcpDeliverStatus::from_ffi_u8(raw)
            };
            let on_demand = move || {
                if let Some(callback) = on_egress_read_demand {
                    // SAFETY: as for `on_write` above, without a view.
                    unsafe { callback(context as *mut ::std::ffi::c_void) };
                }
            };
            let on_close = move || {
                if let Some(callback) = on_close_egress {
                    // SAFETY: as for `on_write` above, without a view.
                    unsafe { callback(context as *mut ::std::ffi::c_void) };
                }
            };

            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).activate(on_write, on_demand, on_close) };
        }

        /// First recorded abnormal stream terminal as a POSIX code, or zero.
        /// Safe to query after a close callback while the session remains alive.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_terminal_error_code(
            session: *const RamaTransparentProxyTcpSession,
        ) -> i32 {
            if session.is_null() {
                return 0;
            }
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { (*session).terminal_error_code() }
        }

        /// Whether the service aborted the egress stream, so its connection is reset at once.
        /// Safe to query after a close callback while the session remains alive.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_egress_aborted(
            session: *const RamaTransparentProxyTcpSession,
        ) -> bool {
            if session.is_null() {
                return false;
            }
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { (*session).egress_aborted() }
        }

        /// Swift → Rust: signal that the `TcpClientWritePump` has drained
        /// capacity after `on_server_bytes` returned `Paused`.
        ///
        /// Wakes the Rust bridge so it resumes forwarding response bytes.
        /// Idempotent — collapses redundant calls into a single permit.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_signal_server_drain(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { (*session).signal_server_drain() };
        }

        /// Swift → Rust: signal that the `NwTcpConnectionWritePump` has
        /// drained capacity after `on_write_to_egress` returned `Paused`.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_signal_egress_drain(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }
            // SAFETY: as for `&*session` in `..._register_promote_callbacks`.
            unsafe { (*session).signal_egress_drain() };
        }

        /// Deliver bytes from the egress `NWConnection` into the Rust TCP session.
        ///
        /// Called by Swift when the NWConnection receives data from the remote
        /// server. Same [`RamaTcpDeliverStatus`] return contract as
        /// `rama_transparent_proxy_tcp_session_on_client_bytes`.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* and *Byte ranges* for
        /// `bytes` (see `transparent_proxy_ffi!`); the bytes are copied.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_egress_bytes(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesView,
        ) -> RamaTcpDeliverStatus {
            if session.is_null() {
                return RamaTcpDeliverStatus::Closed;
            }

            // SAFETY: as for `into_slice` in `..._tcp_session_on_client_bytes`.
            let slice = unsafe { bytes.into_slice() };
            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_egress_bytes(slice) }
        }

        /// Owned-buffer variant of
        /// `rama_transparent_proxy_tcp_session_on_egress_bytes`; same
        /// ownership contract as
        /// `rama_transparent_proxy_tcp_session_on_client_bytes_owned`.
        ///
        /// # Safety
        ///
        /// Same as `rama_transparent_proxy_tcp_session_on_client_bytes_owned`.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_egress_bytes_owned(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesOwnedView,
        ) -> RamaTcpDeliverStatus {
            if session.is_null() {
                // No session: ownership stays with the caller (the
                // `Closed` contract), so we must NOT release here.
                return RamaTcpDeliverStatus::Closed;
            }
            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_egress_bytes_owned(bytes) }
        }

        /// Signal EOF on the egress `NWConnection` direction.
        ///
        /// Called by Swift when the NWConnection closes or fails.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_egress_eof(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_egress_eof() };
        }

        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_egress_error(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).on_egress_error() };
        }

        // ── UDP session control ─────────────────────────────────────────────────

        /// Activate a UDP session.
        ///
        /// Hands the prepared ingress `UdpFlow` to the waiting service
        /// task; Swift does not own any egress for UDP. Egress (socket
        /// open / pool / per-datagram routing) is entirely the
        /// service's responsibility — see the `match_udp_flow` doc in
        /// `TransparentProxyHandler` for the contract.
        ///
        /// # Safety
        ///
        /// The caller must uphold *Session handles* (see `transparent_proxy_ffi!`).
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_activate(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }
            // SAFETY: as for `&mut *session` in `..._tcp_session_on_client_bytes`.
            unsafe { (*session).activate() };
        }

        /// # Safety
        ///
        /// The caller must ensure `bytes` is a value returned by
        /// `rama_transparent_proxy_engine_handle_app_message` of this
        /// expansion, unmodified, and freed only once.
        // SAFETY: unique symbol; see *Linking* on `transparent_proxy_ffi!`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_owned_bytes_free(bytes: $crate::ffi::BytesOwned) {
            // SAFETY: `free` needs the empty value or unmodified
            // `BytesOwned::try_from` parts freed once; `_handle_app_message`'s
            // postcondition and this fn's precondition give that.
            unsafe { bytes.free() };
        }
    };
}
