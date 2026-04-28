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
    mpsc::{UnboundedReceiver, unbounded_channel},
    oneshot,
};

use block2::RcBlock;

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
/// Obtained from [`XpcEvent::Message`] via [`XpcConnection::recv`].
#[derive(Debug)]
pub struct ReceivedXpcMessage {
    connection: xpc_connection_t,
    message: XpcMessage,
    raw_event: OwnedXpcObject,
}

// SAFETY: `connection` is an `xpc_connection_t`, which Apple documents as thread-safe
// (xpc_connection_send_message and friends may be called from any thread). `raw_event`
// is held inside an `OwnedXpcObject` whose own Send+Sync impls cover its xpc_object_t.
// `message` is owned, plain Rust data. No mutable shared state is exposed.
unsafe impl Send for ReceivedXpcMessage {}
unsafe impl Sync for ReceivedXpcMessage {}

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
    pub fn reply(&self, message: XpcMessage) -> Result<(), XpcError> {
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

        // SAFETY: self.connection is the raw connection from which this message was
        // received; it remains valid because the kernel keeps the connection alive while
        // an event handler block is executing. reply.raw is a valid retained XPC object.
        unsafe { xpc_connection_send_message(self.connection, reply.raw) };
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
    receiver: UnboundedReceiver<XpcEvent>,
}

unsafe impl Send for XpcConnection {}
unsafe impl Sync for XpcConnection {}

impl XpcConnection {
    pub(crate) fn from_owned_peer(connection: OwnedXpcObject) -> Result<Self, XpcError> {
        let (sender, receiver) = unbounded_channel();
        let raw_connection = connection.raw as xpc_connection_t;

        let block = RcBlock::new(move |event: xpc_object_t| {
            if raw_is_error(event) {
                tracing::debug!("xpc peer got error event");
                let _ = sender.send(XpcEvent::Error(XpcConnectionError::Invalidated(None)));
                return;
            }

            let Ok(retained) = OwnedXpcObject::retain(event, "peer event") else {
                return;
            };

            let event = map_event(raw_connection, retained);
            let _ = sender.send(event);
        });

        // SAFETY: raw_connection is a valid, non-null xpc_connection_t from OwnedXpcObject.
        // RcBlock is a heap-allocated reference-counted Block; XPC retains it internally
        // after xpc_connection_set_event_handler so it remains valid for the connection's
        // lifetime. xpc_connection_resume activates the connection; it must be called
        // exactly once before any messages are sent or received.
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
                let result = if raw_is_error(reply) {
                    Err(XpcError::Connection(XpcConnectionError::Invalidated(None)))
                } else {
                    match OwnedXpcObject::retain(reply, "async reply") {
                        Ok(reply) => reply.to_message(),
                        Err(err) => Err(err),
                    }
                };

                if let Some(reply_sender) = reply_sender.lock().take() {
                    let _ = reply_sender.send(result);
                }
            });

            // SAFETY: raw_connection is a valid xpc_connection_t. object.raw is a valid
            // retained XPC object. The queue argument is null, so XPC uses the connection's
            // own queue. RcBlock is a heap-allocated reference-counted Block; XPC retains
            // it until after the callback fires, at which point it is released.
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
            .map_err(|_| XpcError::ReplyCanceled)??;
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

fn raw_is_type(event: xpc_object_t, ty: *const c_void) -> bool {
    let value_type = unsafe { xpc_get_type(event) };
    ptr::eq(value_type.cast::<c_void>(), ty)
}

fn raw_is_error(event: xpc_object_t) -> bool {
    raw_is_type(event, unsafe {
        &_xpc_type_error as *const _ as *const c_void
    })
}

pub(crate) fn map_event(connection: xpc_connection_t, event: OwnedXpcObject) -> XpcEvent {
    if let Some(error) = map_connection_error(connection, &event) {
        tracing::debug!(?error, "xpc connection lifecycle event");
        return XpcEvent::Error(error);
    }

    if event.is_type(unsafe { &_xpc_type_connection as *const _ as *const std::ffi::c_void }) {
        tracing::debug!("xpc listener received peer connection");
        return match XpcConnection::from_owned_peer(event) {
            Ok(connection) => XpcEvent::Connection(connection),
            Err(err) => XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
                err.to_string(),
            )))),
        };
    }

    match event.to_message() {
        Ok(message) => {
            tracing::trace!(message = ?message, "xpc incoming message");
            XpcEvent::Message(ReceivedXpcMessage {
                connection,
                message,
                raw_event: event,
            })
        }
        Err(err) => XpcEvent::Error(XpcConnectionError::Invalidated(Some(ArcStr::from(
            err.to_string(),
        )))),
    }
}

pub(crate) fn map_connection_error(
    connection: xpc_connection_t,
    event: &OwnedXpcObject,
) -> Option<XpcConnectionError> {
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

    let key = unsafe { _xpc_error_key_description };
    if key.is_null() {
        return None;
    }

    let value = unsafe { xpc_dictionary_get_string(event, key) };
    if value.is_null() {
        return None;
    }

    Some(ArcStr::from(
        unsafe { CStr::from_ptr(value) }.to_string_lossy(),
    ))
}
