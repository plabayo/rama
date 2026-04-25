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

#[doc(hidden)]
#[macro_export]
macro_rules! __transparent_proxy_ffi_emit {
    (($init:expr), ($engine_builder:expr)) => {
        pub type RamaTransparentProxyEngine = $crate::tproxy::BoxedTransparentProxyEngine;
        pub type RamaTransparentProxyTcpSession = $crate::tproxy::TransparentProxyTcpSession;
        pub type RamaTransparentProxyUdpSession = $crate::tproxy::TransparentProxyUdpSession;

        pub type RamaTransparentProxyFlowMeta = $crate::ffi::tproxy::TransparentProxyFlowMeta;
        pub type RamaTransparentProxyFlowAction = $crate::ffi::tproxy::TransparentProxyFlowAction;
        pub type RamaTransparentProxyConfig = $crate::ffi::tproxy::TransparentProxyConfig;
        pub type RamaTransparentProxyInitConfig = $crate::ffi::tproxy::TransparentProxyInitConfig;
        pub type RamaTransparentProxyTcpSessionCallbacks =
            $crate::ffi::tproxy::TransparentProxyTcpSessionCallbacks;
        pub type RamaTransparentProxyUdpSessionCallbacks =
            $crate::ffi::tproxy::TransparentProxyUdpSessionCallbacks;

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

        #[unsafe(no_mangle)]
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
        pub unsafe extern "C" fn rama_transparent_proxy_get_config(
            engine: *mut RamaTransparentProxyEngine,
        ) -> *mut RamaTransparentProxyConfig {
            if engine.is_null() {
                return ::std::ptr::null_mut();
            }

            let engine = unsafe { &*engine };

            let config = engine.transparent_proxy_config();
            let ffi_cfg = RamaTransparentProxyConfig::from_rust_type(&config);
            ::std::boxed::Box::into_raw(::std::boxed::Box::new(ffi_cfg))
        }

        #[unsafe(no_mangle)]
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

            let engine = match __rama_build_transparent_proxy_engine(opaque_config) {
                Ok(engine) => engine,
                Err(err) => {
                    $crate::tproxy::log_engine_build_error(
                        err.as_ref(),
                        "create transparent proxy engine",
                    );
                    return ::std::ptr::null_mut();
                }
            };

            ::std::boxed::Box::into_raw(::std::boxed::Box::new(engine))
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_free(
            engine: *mut RamaTransparentProxyEngine,
        ) {
            if engine.is_null() {
                return;
            }

            unsafe { drop(::std::boxed::Box::from_raw(engine)) };
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_engine_stop(
            engine: *mut RamaTransparentProxyEngine,
            reason: i32,
        ) {
            if engine.is_null() {
                return;
            }

            let engine = unsafe { ::std::boxed::Box::from_raw(engine) };
            engine.stop(reason);
        }

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

            let engine = unsafe { &*engine };
            let reply = engine.handle_app_message($crate::__RamaBytes::copy_from_slice(
                unsafe { message.into_slice() },
            ));

            match reply
                .map(|bytes| bytes.to_vec())
                .unwrap_or_default()
                .try_into()
            {
                Ok(bytes) => bytes,
                Err(err) => {
                    $crate::__tracing::debug!(%err, "failed to encode transparent proxy app message reply");
                    $crate::ffi::BytesOwned {
                        ptr: ::std::ptr::null_mut(),
                        len: 0,
                        cap: 0,
                    }
                }
            }
        }

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
                unsafe { (*meta).as_owned_rust_type() }
            };

            let context = callbacks.context as usize;
            let on_server_bytes = callbacks.on_server_bytes;
            let on_server_closed = callbacks.on_server_closed;

            let engine = unsafe { &*engine };
            let result = engine.new_tcp_session(
                typed_meta,
                ::std::sync::Arc::new(move |bytes: &[u8]| {
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
                }),
                ::std::sync::Arc::new(move || {
                    if let Some(callback) = on_server_closed {
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

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_free(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { drop(::std::boxed::Box::from_raw(session)) };
        }

        #[unsafe(no_mangle)]
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
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_eof(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { (*session).on_client_eof() };
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_cancel(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { (*session).cancel() };
        }

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
                unsafe { (*meta).as_owned_rust_type() }
            };

            let context = callbacks.context as usize;
            let on_server_datagram = callbacks.on_server_datagram;
            let on_client_read_demand = callbacks.on_client_read_demand;
            let on_server_closed = callbacks.on_server_closed;

            let engine = unsafe { &*engine };
            let result = engine.new_udp_session(
                typed_meta,
                ::std::sync::Arc::new(move |bytes: &[u8]| {
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
                }),
                ::std::sync::Arc::new(move || {
                    if let Some(callback) = on_client_read_demand {
                        unsafe { callback(context as *mut ::std::ffi::c_void) };
                    }
                }),
                ::std::sync::Arc::new(move || {
                    if let Some(callback) = on_server_closed {
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

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_free(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { drop(::std::boxed::Box::from_raw(session)) };
        }

        #[unsafe(no_mangle)]
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
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_on_client_close(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { (*session).on_client_close() };
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_log(level: u32, message: $crate::ffi::BytesView) {
            unsafe { $crate::ffi::log_callback(level, message) };
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_owned_bytes_free(bytes: $crate::ffi::BytesOwned) {
            unsafe { bytes.free() };
        }
    };
}
