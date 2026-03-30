#[macro_export]
macro_rules! transparent_proxy_ffi {
    ($($tt:tt)*) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: ()]
            [config: ()]
            [should_intercept_flow: ()]
            [tcp_service: none]
            [udp_service: none]
            [runtime: none]
            [tcp_buffer_size: none]
            $($tt)*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_parse {
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
    ) => {
        $crate::__transparent_proxy_ffi_require_init!($init);
        $crate::__transparent_proxy_ffi_require_config!($config);
        $crate::__transparent_proxy_ffi_require_should_intercept_flow!($should_intercept_flow);
        $crate::__transparent_proxy_ffi_emit! {
            $init,
            $config,
            $should_intercept_flow,
            $tcp_service,
            $udp_service,
            $runtime,
            $tcp_buffer_size
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        ,
        $($rest:tt)*
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: $config]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: $tcp_service]
            [udp_service: $udp_service]
            [runtime: $runtime]
            [tcp_buffer_size: $tcp_buffer_size]
            $($rest)*
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        init = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: ($value)]
            [config: $config]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: $tcp_service]
            [udp_service: $udp_service]
            [runtime: $runtime]
            [tcp_buffer_size: $tcp_buffer_size]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        config = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: ($value)]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: $tcp_service]
            [udp_service: $udp_service]
            [runtime: $runtime]
            [tcp_buffer_size: $tcp_buffer_size]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        should_intercept_flow = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: $config]
            [should_intercept_flow: ($value)]
            [tcp_service: $tcp_service]
            [udp_service: $udp_service]
            [runtime: $runtime]
            [tcp_buffer_size: $tcp_buffer_size]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        tcp_service = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: $config]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: ($value)]
            [udp_service: $udp_service]
            [runtime: $runtime]
            [tcp_buffer_size: $tcp_buffer_size]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        udp_service = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: $config]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: $tcp_service]
            [udp_service: ($value)]
            [runtime: $runtime]
            [tcp_buffer_size: $tcp_buffer_size]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        runtime = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: $config]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: $tcp_service]
            [udp_service: $udp_service]
            [runtime: ($value)]
            [tcp_buffer_size: $tcp_buffer_size]
            $($($rest)*)?
        }
    };
    (
        [init: $init:tt]
        [config: $config:tt]
        [should_intercept_flow: $should_intercept_flow:tt]
        [tcp_service: $tcp_service:tt]
        [udp_service: $udp_service:tt]
        [runtime: $runtime:tt]
        [tcp_buffer_size: $tcp_buffer_size:tt]
        tcp_buffer_size = $value:expr $(, $($rest:tt)*)?
    ) => {
        $crate::__transparent_proxy_ffi_parse! {
            [init: $init]
            [config: $config]
            [should_intercept_flow: $should_intercept_flow]
            [tcp_service: $tcp_service]
            [udp_service: $udp_service]
            [runtime: $runtime]
            [tcp_buffer_size: ($value)]
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
macro_rules! __transparent_proxy_ffi_require_config {
    (()) => {
        compile_error!("transparent_proxy_ffi!: missing required `config = ...` entry");
    };
    (($value:expr)) => {};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_require_should_intercept_flow {
    (()) => {
        compile_error!(
            "transparent_proxy_ffi!: missing required `should_intercept_flow = ...` entry"
        );
    };
    (($value:expr)) => {};
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_apply_tcp_service {
    ($builder:ident, none) => {};
    ($builder:ident, ($value:expr)) => {
        $builder = $builder.with_tcp_service_factory($value);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_apply_udp_service {
    ($builder:ident, none) => {};
    ($builder:ident, ($value:expr)) => {
        $builder = $builder.with_udp_service_factory($value);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_apply_runtime {
    ($builder:ident, none) => {};
    ($builder:ident, ($value:expr)) => {
        $builder = $builder.with_runtime(Some(($value)()));
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_apply_tcp_buffer_size {
    ($builder:ident, none) => {};
    ($builder:ident, ($value:expr)) => {
        $builder = $builder.with_tcp_flow_buffer_size(Some($value));
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_emit {
    (
        ($init:expr),
        ($config:expr),
        ($should_intercept_flow:expr),
        $tcp_service:tt,
        $udp_service:tt,
        $runtime:tt,
        $tcp_buffer_size:tt
    ) => {
        pub type RamaTransparentProxyEngine = $crate::tproxy::TransparentProxyEngine;
        pub type RamaTransparentProxyTcpSession = $crate::tproxy::TransparentProxyTcpSession;
        pub type RamaTransparentProxyUdpSession = $crate::tproxy::TransparentProxyUdpSession;

        pub type RamaTransparentProxyFlowMeta = $crate::ffi::tproxy::TransparentProxyFlowMeta;
        pub type RamaTransparentProxyConfig = $crate::ffi::tproxy::TransparentProxyConfig;
        pub type RamaTransparentProxyInitConfig = $crate::ffi::tproxy::TransparentProxyInitConfig;
        pub type RamaTransparentProxyTcpSessionCallbacks =
            $crate::ffi::tproxy::TransparentProxyTcpSessionCallbacks;
        pub type RamaTransparentProxyUdpSessionCallbacks =
            $crate::ffi::tproxy::TransparentProxyUdpSessionCallbacks;

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// This function is FFI entrypoint and may be called from Swift/C.
        pub unsafe extern "C" fn rama_transparent_proxy_initialize(
            config: *const RamaTransparentProxyInitConfig,
        ) -> bool {
            let config = if config.is_null() {
                None
            } else {
                Some(unsafe { &*config })
            };

            ($init)(config)
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// Returned [`RamaTransparentProxyConfig`] should be valid.
        pub unsafe extern "C" fn rama_transparent_proxy_get_config()
        -> *mut RamaTransparentProxyConfig {
            let config = ($config)();
            let ffi_cfg = RamaTransparentProxyConfig::from_rust_type(&config);
            ::std::boxed::Box::into_raw(::std::boxed::Box::new(ffi_cfg))
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `config` must be either null or a pointer returned by
        /// `rama_transparent_proxy_get_config` that was not freed yet.
        pub unsafe extern "C" fn rama_transparent_proxy_config_free(
            config: *mut RamaTransparentProxyConfig,
        ) {
            if config.is_null() {
                return;
            }

            let config = unsafe { ::std::boxed::Box::from_raw(config) };
            unsafe { config.free() }
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `meta` must be either null or a valid pointer to `RamaTransparentProxyFlowMeta`.
        pub unsafe extern "C" fn rama_transparent_proxy_should_intercept_flow(
            meta: *const RamaTransparentProxyFlowMeta,
        ) -> bool {
            if meta.is_null() {
                return false;
            }

            let meta = unsafe { (*meta).as_owned_rust_type() };
            ($should_intercept_flow)(&meta)
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// This function is FFI entrypoint and may be called from Swift/C.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new()
        -> *mut RamaTransparentProxyEngine {
            unsafe {
                rama_transparent_proxy_engine_new_with_config($crate::ffi::BytesView {
                    ptr: ::std::ptr::null(),
                    len: 0,
                })
            }
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// This function is FFI entrypoint and may be called from Swift/C.
        /// `engine_config` is borrowed for the duration of the call.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new_with_config(
            engine_config: $crate::ffi::BytesView,
        ) -> *mut RamaTransparentProxyEngine {
            let opaque_config = if engine_config.ptr.is_null() || engine_config.len == 0 {
                None
            } else {
                Some(::std::sync::Arc::<[u8]>::from(unsafe {
                    engine_config.into_slice()
                }))
            };

            let mut engine_builder =
                $crate::tproxy::TransparentProxyEngineBuilder::new().opaque_config(opaque_config);
            $crate::__transparent_proxy_ffi_apply_tcp_service!(engine_builder, $tcp_service);
            $crate::__transparent_proxy_ffi_apply_udp_service!(engine_builder, $udp_service);
            $crate::__transparent_proxy_ffi_apply_runtime!(engine_builder, $runtime);
            $crate::__transparent_proxy_ffi_apply_tcp_buffer_size!(
                engine_builder,
                $tcp_buffer_size
            );

            let engine = engine_builder.build();
            ::std::boxed::Box::into_raw(::std::boxed::Box::new(engine))
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `engine` must either be null or a pointer returned by
        /// `rama_transparent_proxy_engine_new` that has not been freed.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_free(
            engine: *mut RamaTransparentProxyEngine,
        ) {
            if engine.is_null() {
                return;
            }

            unsafe { drop(::std::boxed::Box::from_raw(engine)) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `engine` must be a valid pointer returned by
        /// `rama_transparent_proxy_engine_new`.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_start(
            engine: *mut RamaTransparentProxyEngine,
        ) -> $crate::ffi::BytesOwned {
            if engine.is_null() {
                return ::std::vec::Vec::from("null transparent proxy engine pointer".as_bytes())
                    .try_into()
                    .unwrap_or($crate::ffi::BytesOwned {
                        ptr: ::std::ptr::null_mut(),
                        len: 0,
                        cap: 0,
                    });
            }

            match unsafe { (*engine).start() } {
                Ok(()) => $crate::ffi::BytesOwned {
                    ptr: ::std::ptr::null_mut(),
                    len: 0,
                    cap: 0,
                },
                Err(err) => {
                    err.to_string()
                        .into_bytes()
                        .try_into()
                        .unwrap_or($crate::ffi::BytesOwned {
                            ptr: ::std::ptr::null_mut(),
                            len: 0,
                            cap: 0,
                        })
                }
            }
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `engine` must be a valid pointer returned by
        /// `rama_transparent_proxy_engine_new`.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_stop(
            engine: *mut RamaTransparentProxyEngine,
            reason: i32,
        ) {
            if engine.is_null() {
                return;
            }

            unsafe { (*engine).stop(reason) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `engine` must be valid and `meta` must be either null or point to a valid
        /// `RamaTransparentProxyFlowMeta`.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new_tcp_session(
            engine: *mut RamaTransparentProxyEngine,
            meta: *const RamaTransparentProxyFlowMeta,
            callbacks: RamaTransparentProxyTcpSessionCallbacks,
        ) -> *mut RamaTransparentProxyTcpSession {
            if engine.is_null() {
                return ::std::ptr::null_mut();
            }

            let typed_meta = if meta.is_null() {
                $crate::tproxy::TransparentProxyFlowMeta::new(
                    $crate::tproxy::TransparentProxyFlowProtocol::Tcp,
                )
            } else {
                unsafe { (*meta).as_owned_rust_type() }
            };

            let context = callbacks.context as usize;
            let on_server_bytes = callbacks.on_server_bytes;
            let on_server_closed = callbacks.on_server_closed;

            let engine = unsafe { &*engine };
            let session = engine.new_tcp_session(
                typed_meta,
                move |bytes| {
                    let Some(callback) = on_server_bytes else {
                        return;
                    };
                    if bytes.is_empty() {
                        return;
                    }
                    unsafe {
                        callback(
                            context as *mut ::std::ffi::c_void,
                            $crate::ffi::BytesView {
                                ptr: bytes.as_ptr(),
                                len: bytes.len(),
                            },
                        );
                    }
                },
                move || {
                    if let Some(callback) = on_server_closed {
                        unsafe { callback(context as *mut ::std::ffi::c_void) };
                    }
                },
            );

            match session {
                Some(session) => ::std::boxed::Box::into_raw(::std::boxed::Box::new(session)),
                None => ::std::ptr::null_mut(),
            }
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `session` must either be null or a pointer returned by
        /// `rama_transparent_proxy_engine_new_tcp_session`.
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_free(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { drop(::std::boxed::Box::from_raw(session)) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `session` must be valid. `bytes` must reference readable memory for this call.
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_bytes(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesView,
        ) {
            if session.is_null() {
                return;
            }

            let slice = unsafe { bytes.into_slice() };
            unsafe { (*session).on_client_bytes(slice) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `session` must be valid.
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_eof(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { (*session).on_client_eof() };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `engine` must be valid and `meta` must be either null or point to a valid
        /// `RamaTransparentProxyFlowMeta`.
        pub unsafe extern "C" fn rama_transparent_proxy_engine_new_udp_session(
            engine: *mut RamaTransparentProxyEngine,
            meta: *const RamaTransparentProxyFlowMeta,
            callbacks: RamaTransparentProxyUdpSessionCallbacks,
        ) -> *mut RamaTransparentProxyUdpSession {
            if engine.is_null() {
                return ::std::ptr::null_mut();
            }

            let typed_meta = if meta.is_null() {
                $crate::tproxy::TransparentProxyFlowMeta::new(
                    $crate::tproxy::TransparentProxyFlowProtocol::Udp,
                )
            } else {
                unsafe { (*meta).as_owned_rust_type() }
            };

            let context = callbacks.context as usize;
            let on_server_datagram = callbacks.on_server_datagram;
            let on_server_closed = callbacks.on_server_closed;

            let engine = unsafe { &*engine };
            let session = engine.new_udp_session(
                typed_meta,
                move |bytes| {
                    let Some(callback) = on_server_datagram else {
                        return;
                    };
                    if bytes.is_empty() {
                        return;
                    }
                    unsafe {
                        callback(
                            context as *mut ::std::ffi::c_void,
                            $crate::ffi::BytesView {
                                ptr: bytes.as_ptr(),
                                len: bytes.len(),
                            },
                        );
                    }
                },
                move || {
                    if let Some(callback) = on_server_closed {
                        unsafe { callback(context as *mut ::std::ffi::c_void) };
                    }
                },
            );

            match session {
                Some(session) => ::std::boxed::Box::into_raw(::std::boxed::Box::new(session)),
                None => ::std::ptr::null_mut(),
            }
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `session` must either be null or a pointer returned by
        /// `rama_transparent_proxy_engine_new_udp_session`.
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_free(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { drop(::std::boxed::Box::from_raw(session)) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `session` must be valid. `bytes` must reference readable memory for this call.
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_datagram(
            session: *mut RamaTransparentProxyUdpSession,
            bytes: $crate::ffi::BytesView,
        ) {
            if session.is_null() {
                return;
            }

            let slice = unsafe { bytes.into_slice() };
            unsafe { (*session).on_client_datagram(slice) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `session` must be valid.
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_close(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { (*session).on_client_close() };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `message.ptr` must be readable for `message.len` bytes for this call.
        pub unsafe extern "C" fn rama_log(level: u32, message: $crate::ffi::BytesView) {
            unsafe { $crate::ffi::log_callback(level, message) };
        }

        #[unsafe(no_mangle)]
        /// # Safety
        ///
        /// `bytes` must have been returned by this Rust FFI layer and not freed yet.
        pub unsafe extern "C" fn rama_owned_bytes_free(bytes: $crate::ffi::BytesOwned) {
            unsafe { bytes.free() };
        }
    };
}
