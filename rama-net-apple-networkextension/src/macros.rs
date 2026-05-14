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
            let reply = engine.handle_app_message($crate::__private::Bytes::copy_from_slice(
                unsafe { message.into_slice() },
            ));

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
                match unsafe { (*meta).as_owned_rust_type() } {
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

            let context = callbacks.context as usize;
            let on_server_bytes = callbacks.on_server_bytes;
            let on_client_read_demand = callbacks.on_client_read_demand;
            let on_server_closed = callbacks.on_server_closed;

            let engine = unsafe { &*engine };
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
                    unsafe {
                        callback(
                            context as *mut ::std::ffi::c_void,
                            $crate::ffi::BytesView {
                                ptr: bytes.as_ptr(),
                                len: bytes.len(),
                            },
                        )
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
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_client_bytes(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesView,
        ) -> RamaTcpDeliverStatus {
            if session.is_null() {
                return RamaTcpDeliverStatus::Closed;
            }

            let slice = unsafe { bytes.into_slice() };
            unsafe { (*session).on_client_bytes(slice) }
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
                match unsafe { (*meta).as_owned_rust_type() } {
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

            let context = callbacks.context as usize;
            let on_server_datagram = callbacks.on_server_datagram;
            let on_client_read_demand = callbacks.on_client_read_demand;
            let on_server_closed = callbacks.on_server_closed;

            let engine = unsafe { &*engine };
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
                        // `peer_scratch` is held to the end of the
                        // closure block — `as_view()` borrows pointers
                        // into it, so the C callback (line above) must
                        // observe them while the scratch is still
                        // live. Dropping at scope end is sufficient.
                        let _ = &peer_scratch;
                    },
                ),
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
            peer: $crate::ffi::UdpPeerView,
        ) {
            if session.is_null() {
                return;
            }

            // SAFETY: caller contract on `peer` matches `bytes` — both
            // pointers are valid for the duration of this call.
            let peer = unsafe { peer.into_socket_addr() };
            let slice = unsafe { bytes.into_slice() };
            unsafe { (*session).on_client_datagram(slice, peer) };
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

        // ── TCP egress ──────────────────────────────────────────────────────────

        /// Query handler-supplied egress connect options for a TCP session.
        ///
        /// Returns `true` and fills `out_options` when the handler provided custom
        /// options. Returns `false` when Swift should use `NWParameters` defaults.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_get_egress_connect_options(
            session: *mut RamaTransparentProxyTcpSession,
            out_options: *mut RamaTcpEgressConnectOptions,
        ) -> bool {
            if session.is_null() || out_options.is_null() {
                return false;
            }

            let session = unsafe { &*session };
            let Some(opts) = session.egress_connect_options() else {
                return false;
            };

            let c_opts = RamaTcpEgressConnectOptions {
                parameters: $crate::ffi::tproxy::NwEgressParameters::from_rust_type(&opts.parameters),
                has_connect_timeout_ms: opts.connect_timeout.is_some(),
                connect_timeout_ms: opts
                    .connect_timeout
                    .map(|d| d.as_millis() as u32)
                    .unwrap_or(0),
                has_linger_close_ms: opts.linger_close_timeout.is_some(),
                linger_close_ms: opts
                    .linger_close_timeout
                    .map(|d| d.as_millis() as u32)
                    .unwrap_or(0),
                has_egress_eof_grace_ms: opts.egress_eof_grace.is_some(),
                egress_eof_grace_ms: opts
                    .egress_eof_grace
                    .map(|d| d.as_millis() as u32)
                    .unwrap_or(0),
            };
            unsafe { *out_options = c_opts };
            true
        }

        /// Activate a TCP session after the egress `NWConnection` is ready and the
        /// intercepted flow has been successfully opened.
        ///
        /// `callbacks` provides the Rust→Swift write channel: Rust calls
        /// `on_write_to_egress` to push bytes to the NWConnection, and
        /// `on_close_egress` when the egress write direction is done.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_activate(
            session: *mut RamaTransparentProxyTcpSession,
            callbacks: RamaTransparentProxyTcpEgressCallbacks,
        ) {
            if session.is_null() {
                return;
            }

            let context = callbacks.context as usize;
            let on_write_to_egress = callbacks.on_write_to_egress;
            let on_close_egress = callbacks.on_close_egress;
            let on_egress_read_demand = callbacks.on_egress_read_demand;

            unsafe {
                (*session).activate(
                    move |bytes: $crate::__private::Bytes| -> RamaTcpDeliverStatus {
                        let Some(callback) = on_write_to_egress else {
                            // No Swift writer registered: behave as accepted
                            // so the bridge keeps pulling bytes; they go
                            // nowhere but at least the session doesn't stall.
                            return RamaTcpDeliverStatus::Accepted;
                        };
                        if bytes.is_empty() {
                            return RamaTcpDeliverStatus::Accepted;
                        }
                        unsafe {
                            callback(
                                context as *mut ::std::ffi::c_void,
                                $crate::ffi::BytesView {
                                    ptr: bytes.as_ptr(),
                                    len: bytes.len(),
                                },
                            )
                        }
                    },
                    move || {
                        if let Some(callback) = on_egress_read_demand {
                            unsafe { callback(context as *mut ::std::ffi::c_void) };
                        }
                    },
                    move || {
                        if let Some(callback) = on_close_egress {
                            unsafe { callback(context as *mut ::std::ffi::c_void) };
                        }
                    },
                )
            };
        }

        /// Swift → Rust: signal that the `TcpClientWritePump` has drained
        /// capacity after `on_server_bytes` returned `Paused`.
        ///
        /// Wakes the Rust bridge so it resumes forwarding response bytes.
        /// Idempotent — collapses redundant calls into a single permit.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_signal_server_drain(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }
            unsafe { (*session).signal_server_drain() };
        }

        /// Swift → Rust: signal that the `NwTcpConnectionWritePump` has
        /// drained capacity after `on_write_to_egress` returned `Paused`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_signal_egress_drain(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }
            unsafe { (*session).signal_egress_drain() };
        }

        /// Deliver bytes from the egress `NWConnection` into the Rust TCP session.
        ///
        /// Called by Swift when the NWConnection receives data from the remote
        /// server. Same [`RamaTcpDeliverStatus`] return contract as
        /// `rama_transparent_proxy_tcp_session_on_client_bytes`.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_egress_bytes(
            session: *mut RamaTransparentProxyTcpSession,
            bytes: $crate::ffi::BytesView,
        ) -> RamaTcpDeliverStatus {
            if session.is_null() {
                return RamaTcpDeliverStatus::Closed;
            }

            let slice = unsafe { bytes.into_slice() };
            unsafe { (*session).on_egress_bytes(slice) }
        }

        /// Signal EOF on the egress `NWConnection` direction.
        ///
        /// Called by Swift when the NWConnection closes or fails.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_tcp_session_on_egress_eof(
            session: *mut RamaTransparentProxyTcpSession,
        ) {
            if session.is_null() {
                return;
            }

            unsafe { (*session).on_egress_eof() };
        }

        // ── UDP session control ─────────────────────────────────────────────────

        /// Activate a UDP session.
        ///
        /// Hands the prepared ingress `UdpFlow` to the waiting service
        /// task; Swift does not own any egress for UDP. Egress (socket
        /// open / pool / per-datagram routing) is entirely the
        /// service's responsibility — see the `match_udp_flow` doc in
        /// `TransparentProxyHandler` for the contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn rama_transparent_proxy_udp_session_activate(
            session: *mut RamaTransparentProxyUdpSession,
        ) {
            if session.is_null() {
                return;
            }
            unsafe { (*session).activate() };
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
