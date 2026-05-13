use std::{
    ffi::{CStr, c_void},
    ptr,
};

// `xpc_connection_copy_invalidation_reason` returns a libc-malloc'd C string that the
// caller must `free`. We declare `free` locally rather than pulling in the `libc` crate
// for one symbol; `extern "C" { fn free(p: *mut c_void); }` is exactly Apple's libSystem
// signature and resolves through the standard libc the process is already linked against.
unsafe extern "C" {
    #[link_name = "free"]
    fn libc_free(ptr: *mut c_void);
}

use parking_lot::Mutex;
use rama_core::{
    Service,
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::{
    mpsc::{Receiver, Sender, channel, error::TrySendError},
    oneshot,
};

use block2::RcBlock;

/// Default capacity for the per-connection event channel.
///
/// Sized generously so that well-behaved peers never see back-pressure-induced
/// drops, while still bounding the worst-case memory footprint of a misbehaving
/// or stuck reader. Override per-connection via
/// [`XpcClientConfig::with_max_pending_events`](crate::XpcClientConfig::with_max_pending_events)
/// or via the listener-level knobs on
/// [`XpcListenerConfig`](crate::XpcListenerConfig).
pub const DEFAULT_MAX_PENDING_EVENTS: usize = 10_000;

use crate::{
    call::XpcCall,
    error::{XpcConnectionError, XpcError},
    ffi::{
        _xpc_error_connection_interrupted, _xpc_error_connection_invalid,
        _xpc_error_key_description, _xpc_error_peer_code_signing_requirement, _xpc_type_connection,
        _xpc_type_error, xpc_connection_cancel, xpc_connection_copy_invalidation_reason,
        xpc_connection_get_asid, xpc_connection_get_egid, xpc_connection_get_euid,
        xpc_connection_get_name, xpc_connection_get_pid, xpc_connection_resume,
        xpc_connection_send_message, xpc_connection_send_message_with_reply,
        xpc_connection_set_event_handler, xpc_connection_suspend, xpc_connection_t,
        xpc_dictionary_create_reply, xpc_dictionary_get_string, xpc_dictionary_set_value,
        xpc_get_type, xpc_object_t,
    },
    message::XpcMessage,
    object::OwnedXpcObject,
    router::extract_result,
    util::make_c_string,
    xpc_serde,
};

/// An event received on an [`XpcConnection`].
#[derive(Debug)]
pub enum XpcEvent {
    /// An incoming peer connection from a listener-style connection.
    Connection(XpcConnection),
    /// An incoming message from the peer.
    Message(ReceivedXpcMessage),
    /// A connection lifecycle error. After this event the connection is permanently closed.
    Error(XpcConnectionError),
}

/// An incoming XPC message together with the context needed to send a reply.
///
/// Obtained from [`XpcEvent::Message`] via [`XpcConnection::recv`]. Holds its own
/// retained reference to the originating connection: the parent
/// [`XpcConnection`] may be dropped while a `ReceivedXpcMessage` is still in
/// flight, and [`reply`](Self::reply) remains safe to call.
#[derive(Debug)]
pub struct ReceivedXpcMessage {
    // Independent retained reference to the originating connection — keeps it alive
    // for the lifetime of this message even if the parent XpcConnection is dropped.
    connection: OwnedXpcObject,
    message: XpcMessage,
    raw_event: OwnedXpcObject,
}

impl ReceivedXpcMessage {
    /// Borrow the decoded message.
    pub fn message(&self) -> &XpcMessage {
        &self.message
    }

    /// Consume this wrapper and return the decoded message, discarding reply capability.
    pub fn into_message(self) -> XpcMessage {
        self.message
    }

    /// Send a reply to the peer.
    ///
    /// `message` must be a [`XpcMessage::Dictionary`]; any other variant returns
    /// [`XpcError::ReplyNotExpected`]. The reply is delivered to the future awaiting
    /// [`XpcConnection::send_request`] on the other side.
    ///
    /// `reply` consumes the message: each incoming message may be replied to at most
    /// once. To inspect the message without replying use [`message`](Self::message);
    /// to extract without replying use [`into_message`](Self::into_message).
    pub fn reply(self, message: XpcMessage) -> Result<(), XpcError> {
        let XpcMessage::Dictionary(values) = message else {
            return Err(XpcError::ReplyNotExpected);
        };

        // SAFETY: self.raw_event.raw is a valid XPC dictionary object retained by
        // OwnedXpcObject. xpc_dictionary_create_reply returns a new retained dictionary
        // or NULL if the message does not support replies.
        let reply = unsafe { xpc_dictionary_create_reply(self.raw_event.raw) };
        let reply = OwnedXpcObject::from_raw(reply, "reply message")?;

        for (key, value) in values {
            let key = make_c_string(&key)?;
            let value = OwnedXpcObject::from_message(value)?;
            // SAFETY: reply.raw is a valid mutable XPC dictionary. key.as_ptr() is a
            // valid null-terminated C string. value.raw is a valid retained XPC object.
            unsafe { xpc_dictionary_set_value(reply.raw, key.as_ptr(), value.raw) };
        }

        // SAFETY: self.connection holds an independent retain on the originating
        // xpc_connection_t (taken when the event was decoded), so it is guaranteed
        // valid for this call regardless of whether the parent XpcConnection has
        // already been dropped. reply.raw is a valid retained XPC object.
        unsafe {
            xpc_connection_send_message(self.connection.raw as xpc_connection_t, reply.raw);
        }
        Ok(())
    }
}

/// A bidirectional async XPC connection to a peer process.
///
/// On the **client** side, create one with [`XpcConnection::connect`].
/// On the **server** side, connections are delivered by [`XpcListener::accept`](crate::XpcListener::accept).
/// An [`XpcEndpoint`](crate::XpcEndpoint) can also produce a connection via
/// [`XpcEndpoint::into_connection`](crate::XpcEndpoint::into_connection) without a launchd service name.
///
/// ## Sending
///
/// - [`send`](Self::send) — fire-and-forget; queues the message and returns immediately.
/// - [`send_request`](Self::send_request) — awaits a [`XpcMessage::Dictionary`] reply
///   from the peer (the peer calls [`ReceivedXpcMessage::reply`]).
///
/// ## Receiving
///
/// [`recv`](Self::recv) yields the next [`XpcEvent`]. After an
/// [`XpcEvent::Error`] the connection is permanently closed; further `recv` calls
/// return `None`.
///
/// ## Lifecycle
///
/// The connection is cancelled automatically on [`Drop`]. You may also call
/// [`cancel`](Self::cancel) explicitly. [`suspend`](Self::suspend) and
/// [`resume`](Self::resume) gate event delivery and must be called in balanced pairs.
///
/// ## Peer identity
///
/// [`pid`](Self::pid), [`euid`](Self::euid), [`egid`](Self::egid),
/// [`asid`](Self::asid), and [`name`](Self::name) expose kernel-reported peer
/// credentials. For security decisions, prefer [`asid`](Self::asid) over
/// [`pid`](Self::pid): audit session IDs are stable within a login session and
/// are not subject to PID recycling.
///
/// ## Security
///
/// Pass a [`PeerSecurityRequirement`](crate::PeerSecurityRequirement) to
/// [`XpcClientConfig`](crate::XpcClientConfig) or
/// [`XpcListenerConfig`](crate::XpcListenerConfig) to restrict which peer binaries
/// may connect. The kernel enforces the constraint before any message is delivered.
#[derive(Debug)]
pub struct XpcConnection {
    connection: OwnedXpcObject,
    extensions: Extensions,
    receiver: Receiver<XpcEvent>,
}

// SAFETY: `XpcConnection` wraps an `OwnedXpcObject` (an `xpc_connection_t`), an
// `Extensions` map, and an `mpsc::Receiver<XpcEvent>`. Apple documents
// `xpc_connection_t` as safe to use from any thread. `Extensions` is `Send`.
// `Receiver` is `Send` for `T: Send`.
unsafe impl Send for XpcConnection {}
// SAFETY: every `&self` method on `XpcConnection` only touches the
// xpc_connection_t (Apple-documented thread-safe) and `Extensions`. The
// `Receiver` is exclusively reached via `&mut self` (`recv`), so two
// threads sharing `&XpcConnection` cannot race on it. The auto `Sync` derive
// is blocked only because `Receiver` is not `Sync`; we re-assert
// here under that exclusive-access guarantee.
unsafe impl Sync for XpcConnection {}

impl XpcConnection {
    pub(crate) fn from_owned_peer(connection: OwnedXpcObject) -> Result<Self, XpcError> {
        Self::from_owned_peer_with_capacity(
            connection,
            DEFAULT_MAX_PENDING_EVENTS,
            DEFAULT_MAX_PENDING_EVENTS,
        )
    }

    pub(crate) fn from_owned_peer_with_capacity(
        connection: OwnedXpcObject,
        capacity: usize,
        peer_event_capacity: usize,
    ) -> Result<Self, XpcError> {
        let capacity = capacity.max(1);
        let peer_event_capacity = peer_event_capacity.max(1);
        let (sender, receiver) = channel(capacity);
        let raw_connection = connection.raw as xpc_connection_t;

        let block = RcBlock::new(move |event: xpc_object_t| {
            // Retain the event so it survives the event-handler scope before we
            // classify it. Errors, peer connections, and messages all flow through
            // `map_event`, which preserves the specific connection-error variant.
            let Ok(retained) = OwnedXpcObject::retain(event, "peer event") else {
                tracing::warn!("xpc peer received null event object, dropping");
                return;
            };

            let event = map_event(raw_connection, retained, peer_event_capacity);
            forward_event(&sender, event);
        });

        // SAFETY: `raw_connection` is a valid, non-null xpc_connection_t held by
        // OwnedXpcObject for the lifetime of this Self. The `RcBlock` lives on the
        // heap and `RcBlock::as_ptr` is documented (block2 rc_block.rs) to be valid
        // for at least as long as the `RcBlock` is alive. Apple's
        // `xpc_connection_set_event_handler` is documented to `_Block_copy` the
        // block, which bumps the heap allocation's refcount — so when the local
        // `RcBlock` is dropped at end-of-scope its refcount goes from 2 to 1 and
        // libxpc's copy keeps the heap block alive for as long as it needs to
        // invoke the handler. `xpc_connection_resume` activates the connection;
        // it must be called exactly once before any messages are sent or received.
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "set-handler-then-resume is a single XPC initialization sequence; the SAFETY comment above covers both calls"
        )]
        unsafe {
            xpc_connection_set_event_handler(
                raw_connection,
                RcBlock::as_ptr(&block).cast::<c_void>(),
            );
            xpc_connection_resume(raw_connection);
        }

        tracing::debug!(
            // SAFETY: `raw_connection` is the live xpc_connection_t we just resumed
            // above; it remains valid for the remainder of this scope. Returns the
            // peer's pid or 0 if not yet known — both are safe values.
            pid = unsafe { xpc_connection_get_pid(raw_connection) },
            "xpc peer connection activated"
        );

        Ok(Self {
            connection,
            extensions: Extensions::new(),
            receiver,
        })
    }

    /// Await the next event from the peer.
    ///
    /// Cancel-safe: dropping this future before it resolves does not discard any
    /// pending event; the next call to `recv` will yield it.
    ///
    /// Returns `None` when the connection has been closed and the internal channel
    /// is drained. After receiving [`XpcEvent::Error`] the channel will close and
    /// subsequent calls will return `None`.
    pub async fn recv(&mut self) -> Option<XpcEvent> {
        self.receiver.recv().await
    }

    /// Send a message to the peer without waiting for a reply.
    ///
    /// The message is queued and the call returns immediately. Use
    /// [`send_request`](Self::send_request) when you need the peer's response.
    pub fn send(&self, message: XpcMessage) -> Result<(), XpcError> {
        tracing::trace!(message = ?message, "xpc send");
        let object = OwnedXpcObject::from_message(message)?;
        // SAFETY: self.connection.raw is a valid xpc_connection_t held by OwnedXpcObject
        // for the lifetime of &self. object.raw is a valid retained XPC object.
        unsafe { xpc_connection_send_message(self.connection.raw as xpc_connection_t, object.raw) };
        Ok(())
    }

    /// Send a message and await a [`XpcMessage::Dictionary`] reply from the peer.
    ///
    /// **Not cancel-safe.** The message is enqueued with XPC before this future is
    /// polled for the reply. If the future is dropped after the message has been sent
    /// but before the peer replies, the message is already in flight — the peer will
    /// still receive and process it, but the reply will be silently discarded.
    ///
    /// The peer satisfies the future by calling [`ReceivedXpcMessage::reply`] on the
    /// corresponding received message. Returns [`XpcError::ReplyCanceled`] if the
    /// connection closes before a reply is delivered.
    pub async fn send_request(&self, message: XpcMessage) -> Result<XpcMessage, XpcError> {
        tracing::trace!(message = ?message, "xpc send request");
        let object = OwnedXpcObject::from_message(message)?;
        let (reply_sender, reply_receiver) = oneshot::channel();
        let reply_sender = Mutex::new(Some(reply_sender));
        let raw_connection = self.connection.raw as xpc_connection_t;

        {
            let block = RcBlock::new(move |reply: xpc_object_t| {
                let result = match OwnedXpcObject::retain(reply, "async reply") {
                    Err(err) => Err(err),
                    Ok(reply_obj) => {
                        if raw_is_error(reply) {
                            // Preserve the specific connection-error variant
                            // (Interrupted / Invalidated / PeerRequirementFailed)
                            // rather than collapsing every error to `Invalidated(None)`.
                            let error = map_connection_error(raw_connection, &reply_obj)
                                .unwrap_or(XpcConnectionError::Invalidated(None));
                            Err(XpcError::Connection(error))
                        } else {
                            reply_obj.to_message()
                        }
                    }
                };

                if let Some(reply_sender) = reply_sender.lock().take() {
                    _ = reply_sender.send(result);
                }
            });

            // SAFETY: raw_connection is a valid xpc_connection_t held by
            // self.connection for the lifetime of &self. object.raw is a valid retained
            // XPC object. The queue argument is null, so XPC uses the connection's own
            // queue. The `RcBlock` lives on the heap and `RcBlock::as_ptr` is documented
            // (block2 rc_block.rs) to be valid for at least as long as the RcBlock is
            // alive; Apple's `xpc_connection_send_message_with_reply` is documented to
            // `_Block_copy` the handler block, so libxpc bumps the heap refcount before
            // we drop our local `RcBlock` at end-of-scope. libxpc invokes the block
            // exactly once and releases its copy afterwards.
            unsafe {
                xpc_connection_send_message_with_reply(
                    raw_connection,
                    object.raw,
                    ptr::null_mut(),
                    RcBlock::as_ptr(&block).cast::<c_void>(),
                );
            }
        }

        let reply = reply_receiver
            .await
            .map_err(|_e| XpcError::ReplyCanceled)??;
        tracing::trace!(reply = ?reply, "xpc received reply");
        Ok(reply)
    }

    /// Send a selector call to the peer without waiting for a reply.
    ///
    /// Encodes `selector` and `arguments` into the standard
    /// `{"$selector": …, "$arguments": […]}` wire format and calls [`send`](Self::send).
    pub fn send_selector(
        &self,
        selector: ArcStr,
        arguments: Vec<XpcMessage>,
    ) -> Result<(), XpcError> {
        let call = XpcCall::with_arguments(selector, arguments);
        self.send(call.into())
    }

    /// Send a selector call and await a reply [`XpcMessage`].
    ///
    /// Encodes the call in the standard wire format and calls
    /// [`send_request`](Self::send_request).  The raw reply dictionary is returned
    /// as-is; use [`extract_result`](crate::router::extract_result) to decode a
    /// `{"$result": …}` reply produced by a typed [`XpcMessageRouter`](crate::XpcMessageRouter) handler.
    ///
    /// **Not cancel-safe** — see [`send_request`](Self::send_request).
    pub async fn request_selector(
        &self,
        selector: ArcStr,
        arguments: Vec<XpcMessage>,
    ) -> Result<XpcMessage, XpcError> {
        let call = XpcCall::with_arguments(selector, arguments);
        self.send_request(call.into()).await
    }

    /// Send a typed request to a selector and await a deserialized reply.
    ///
    /// `req` is serialized via [`to_xpc_message`](crate::to_xpc_message) and
    /// placed as the sole entry in the `$arguments` array.  The reply is expected to
    /// be a `{"$result": …}` dictionary as produced by a typed
    /// [`XpcMessageRouter`](crate::XpcMessageRouter) handler; the `$result` value is
    /// deserialized as `Res`.
    ///
    /// **Not cancel-safe** — see [`send_request`](Self::send_request).
    pub async fn request_typed<Req, Res>(
        &self,
        selector: ArcStr,
        req: &Req,
    ) -> Result<Res, XpcError>
    where
        Req: serde::Serialize,
        Res: serde::de::DeserializeOwned,
    {
        let arg = xpc_serde::to_xpc_message(req)?;
        let reply = self.request_selector(selector, vec![arg]).await?;
        extract_result(reply)
    }

    /// Process ID of the remote peer at the time the connection was established.
    ///
    /// PIDs are recycled by the kernel. For session-stable identity, use [`asid`](Self::asid).
    pub fn pid(&self) -> i32 {
        // SAFETY: self.connection.raw is a valid, non-null xpc_connection_t for &self's lifetime.
        unsafe { xpc_connection_get_pid(self.connection.raw as xpc_connection_t) }
    }

    /// Effective user ID of the remote peer.
    pub fn euid(&self) -> u32 {
        // SAFETY: Same as pid().
        unsafe { xpc_connection_get_euid(self.connection.raw as xpc_connection_t) }
    }

    /// Effective group ID of the remote peer.
    pub fn egid(&self) -> u32 {
        // SAFETY: Same as pid().
        unsafe { xpc_connection_get_egid(self.connection.raw as xpc_connection_t) }
    }

    /// Audit session identifier of the remote peer.
    ///
    /// The audit session ID is a kernel-assigned, per-session identity that is stable
    /// across PID recycling within the same login session. It is more reliable than
    /// [`pid`](Self::pid) for session-level identity checks.
    pub fn asid(&self) -> i32 {
        // SAFETY: Same as pid().
        unsafe { xpc_connection_get_asid(self.connection.raw as xpc_connection_t) }
    }

    /// Service name of this connection, if any.
    ///
    /// Returns `None` for anonymous or peer connections created from endpoints.
    pub fn name(&self) -> Option<String> {
        // SAFETY: self.connection.raw is a valid xpc_connection_t. The returned pointer
        // is either null or a valid C string borrowed from the connection object; it
        // remains valid for &self's lifetime. We copy it to a String before returning.
        let ptr = unsafe { xpc_connection_get_name(self.connection.raw as xpc_connection_t) };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: ptr is non-null and points to a valid, null-terminated C string
        // owned by the XPC connection object, as guaranteed by the API contract above.
        Some(
            unsafe { std::ffi::CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }

    /// Explicitly cancel the connection.
    ///
    /// Safe to call multiple times — canceling an already-canceled connection is a no-op.
    /// The connection is also canceled automatically on [`Drop`].
    pub fn cancel(&self) {
        tracing::debug!("xpc connection cancel");
        // SAFETY: self.connection.raw is a valid xpc_connection_t. xpc_connection_cancel
        // is idempotent per Apple's documentation.
        unsafe { xpc_connection_cancel(self.connection.raw as xpc_connection_t) };
    }

    /// Suspend event delivery on the connection.
    ///
    /// Every call to `suspend` must be balanced by a corresponding call to [`resume`](Self::resume)
    /// before the connection is released. Unbalanced suspends will cause a crash.
    pub fn suspend(&self) {
        tracing::trace!("xpc connection suspend");
        // SAFETY: self.connection.raw is a valid xpc_connection_t for &self's lifetime.
        unsafe { xpc_connection_suspend(self.connection.raw as xpc_connection_t) };
    }

    /// Resume a previously suspended connection.
    ///
    /// Must be called once for each preceding call to [`suspend`](Self::suspend).
    pub fn resume(&self) {
        tracing::trace!("xpc connection resume");
        // SAFETY: Same as suspend().
        unsafe { xpc_connection_resume(self.connection.raw as xpc_connection_t) };
    }

    pub(crate) fn connection_raw(&self) -> xpc_connection_t {
        self.connection.raw as xpc_connection_t
    }
}

impl ExtensionsRef for XpcConnection {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Drop for XpcConnection {
    fn drop(&mut self) {
        // SAFETY: self.connection.raw is a valid xpc_connection_t. xpc_connection_cancel
        // is idempotent, so calling it here after an explicit cancel() is safe.
        unsafe { xpc_connection_cancel(self.connection.raw as xpc_connection_t) };
    }
}

impl Service<XpcMessage> for XpcConnection {
    type Output = ();
    type Error = XpcError;

    async fn serve(&self, input: XpcMessage) -> Result<Self::Output, Self::Error> {
        self.send(input)
    }
}

/// Caller must pass a valid, non-null `xpc_object_t` (we always do — these
/// helpers are reached only from a connection event-handler block where libxpc
/// hands us a retained event).
fn raw_is_type(event: xpc_object_t, ty: *const c_void) -> bool {
    // SAFETY: see function-level comment — `event` is a valid xpc_object_t.
    let value_type = unsafe { xpc_get_type(event) };
    ptr::eq(value_type.cast::<c_void>(), ty)
}

fn raw_is_error(event: xpc_object_t) -> bool {
    raw_is_type(event, unsafe {
        // SAFETY: `_xpc_type_error` is a static XPC type singleton exported by
        // libxpc and valid for the lifetime of the process.
        &_xpc_type_error as *const _ as *const c_void
    })
}

pub(crate) fn map_event(
    connection: xpc_connection_t,
    event: OwnedXpcObject,
    peer_event_capacity: usize,
) -> XpcEvent {
    if let Some(error) = map_connection_error(connection, &event) {
        tracing::debug!(?error, "xpc connection lifecycle event");
        return XpcEvent::Error(error);
    }

    // SAFETY: `_xpc_type_connection` is a static XPC type singleton exported
    // by libxpc and valid for the lifetime of the process.
    if event.is_type(unsafe { &_xpc_type_connection as *const _ as *const std::ffi::c_void }) {
        tracing::debug!("xpc listener received peer connection");
        return match XpcConnection::from_owned_peer_with_capacity(
            event,
            peer_event_capacity,
            peer_event_capacity,
        ) {
            Ok(connection) => XpcEvent::Connection(connection),
            Err(err) => XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
                err.to_string(),
            )))),
        };
    }

    match event.to_message() {
        Ok(message) => {
            tracing::trace!(message = ?message, "xpc incoming message");
            // Independent retain on the connection so a held ReceivedXpcMessage outlives
            // its parent XpcConnection if necessary (reply remains safe).
            let connection_ref =
                match OwnedXpcObject::retain(connection.cast(), "received connection ref") {
                    Ok(c) => c,
                    Err(err) => {
                        return XpcEvent::Error(XpcConnectionError::Invalidated(Some(
                            ArcStr::from(err.to_string()),
                        )));
                    }
                };
            XpcEvent::Message(ReceivedXpcMessage {
                connection: connection_ref,
                message,
                raw_event: event,
            })
        }
        Err(err) => XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
            err.to_string(),
        )))),
    }
}

/// Send `event` on `sender` with backpressure-aware semantics.
///
/// On a full channel we **drop the new event** and log a warning. Graceful-by-default:
/// a stuck reader cannot make us crash, deadlock, or grow memory without bound.
/// Closed channels (receiver dropped) silently drop — the connection is being torn down.
pub(crate) fn forward_event(sender: &Sender<XpcEvent>, event: XpcEvent) {
    if let Err(TrySendError::Full(_)) = sender.try_send(event) {
        tracing::warn!(
            capacity = sender.max_capacity(),
            "xpc connection event channel full; dropping event"
        );
    }
    // Ok and Closed are both no-ops: send succeeded, or the receiver was dropped
    // because the connection is being torn down.
}

pub(crate) fn map_connection_error(
    connection: xpc_connection_t,
    event: &OwnedXpcObject,
) -> Option<XpcConnectionError> {
    // SAFETY: `_xpc_type_error` is a static XPC type singleton exported by
    // libxpc and valid for the lifetime of the process.
    if !event.is_type(unsafe { &_xpc_type_error as *const _ as *const std::ffi::c_void }) {
        return None;
    }

    if ptr::eq(
        event.raw.cast_const(),
        (&raw const _xpc_error_connection_interrupted).cast(),
    ) {
        return Some(XpcConnectionError::Interrupted);
    }

    if ptr::eq(
        event.raw.cast_const(),
        (&raw const _xpc_error_peer_code_signing_requirement).cast(),
    ) {
        return Some(XpcConnectionError::PeerRequirementFailed(
            connection_error_description(connection, event.raw),
        ));
    }

    if ptr::eq(
        event.raw.cast_const(),
        (&raw const _xpc_error_connection_invalid).cast(),
    ) {
        return Some(XpcConnectionError::Invalidated(
            connection_error_description(connection, event.raw),
        ));
    }

    Some(XpcConnectionError::Invalidated(
        connection_error_description(connection, event.raw),
    ))
}

fn connection_error_description(
    connection: xpc_connection_t,
    event: xpc_object_t,
) -> Option<ArcStr> {
    // SAFETY: `connection` is a live xpc_connection_t (we hold an OwnedXpcObject that
    // outlives this call). `xpc_connection_copy_invalidation_reason` either returns
    // NULL or a libc-malloc'd, NUL-terminated C string that the caller must `free()`.
    // We must NOT use `CString::from_raw` here — its `Drop` deallocates with Rust's
    // global allocator using a layout derived from string length, which is
    // incompatible with libc `free`. Instead we copy the string contents into an
    // `ArcStr` while the buffer is still live, then free it with libc::free.
    let copied = unsafe { xpc_connection_copy_invalidation_reason(connection) };
    if !copied.is_null() {
        // SAFETY: `copied` is non-null and points to a NUL-terminated C string owned
        // by libxpc (malloc'd) until we call `free` below. The borrow ends before the
        // free.
        let value = ArcStr::from(unsafe { CStr::from_ptr(copied) }.to_string_lossy());
        // SAFETY: `copied` was returned by `xpc_connection_copy_invalidation_reason`
        // (which malloc's the buffer per Apple's <xpc/connection.h>); the contract
        // requires the caller to `free` it. No other code holds the pointer.
        unsafe { libc_free(copied.cast::<c_void>()) };
        return Some(value);
    }

    // SAFETY: `_xpc_error_key_description` is a static XPC dictionary key
    // exported by libxpc; reading it is always sound.
    let key = unsafe { _xpc_error_key_description };
    if key.is_null() {
        return None;
    }

    // SAFETY: `event` is a valid retained xpc_object_t (caller passed it down
    // from the live OwnedXpcObject). `key` is a valid XPC dictionary key
    // checked non-null above. `xpc_dictionary_get_string` returns a borrowed
    // NUL-terminated C string (or NULL if the key is absent / type mismatch),
    // valid for the lifetime of `event`.
    let value = unsafe { xpc_dictionary_get_string(event, key) };
    if value.is_null() {
        return None;
    }

    Some(ArcStr::from(
        // SAFETY: `value` was just checked non-null and is a NUL-terminated
        // C string borrowed from `event`; the borrow ends before this scope.
        unsafe { CStr::from_ptr(value) }.to_string_lossy(),
    ))
}
