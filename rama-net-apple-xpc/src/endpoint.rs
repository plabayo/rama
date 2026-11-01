use std::{fmt, ptr, sync::Arc};

use parking_lot::Mutex;
use rama_core::telemetry::tracing;

use crate::{
    connection::{DEFAULT_MAX_PENDING_EVENTS, InactiveXpcConnection, XpcConnection},
    error::XpcError,
    ffi::{
        _xpc_type_endpoint, xpc_connection_create, xpc_connection_create_from_endpoint,
        xpc_endpoint_create,
    },
    object::OwnedXpcObject,
    util::DispatchQueue,
};

/// An XPC endpoint that can be embedded in messages and passed across process boundaries.
///
/// An endpoint is a serializable reference to an XPC listener. The receiver can call
/// [`XpcEndpoint::into_connection`] to establish a peer connection to that listener
/// without needing to know a launchd service name. This is the standard technique for
/// bootstrapping connections that are not registered with launchd.
///
/// # Creating an endpoint
///
/// ```no_run
/// use rama_net_apple_xpc::{XpcConnection, XpcClientConfig, XpcEndpoint, XpcMessage};
/// use std::collections::BTreeMap;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let conn = XpcConnection::connect(XpcClientConfig::new("com.example.myservice"))?;
/// let endpoint = XpcEndpoint::from_connection(&conn)?;
///
/// let mut msg = BTreeMap::new();
/// msg.insert("endpoint".to_string(), XpcMessage::Endpoint(endpoint));
/// conn.send(XpcMessage::Dictionary(msg))?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct XpcEndpoint {
    inner: Arc<EndpointObject>,
}

/// Serialises Rust's libxpc calls on endpoint objects. One lock for all endpoints:
/// independently decoded messages can yield separate Rust aliases of one endpoint.
static ENDPOINT_CALLS: Mutex<()> = Mutex::new(());

struct EndpointObject {
    // Safety invariant: `object` has type `XPC_TYPE_ENDPOINT`. The only libxpc call this
    // crate makes with an endpoint as its target, `xpc_connection_create_from_endpoint`,
    // holds `ENDPOINT_CALLS`. Retain/release, `xpc_get_type` (the object's fixed type),
    // insertion into a collection (a retain) and libxpc's own threads are outside it.
    object: OwnedXpcObject,
}

// SAFETY: Rust's endpoint calls are serialised by `ENDPOINT_CALLS` (field invariant), and
// xpc_object(3) permits using and releasing an object on a queue other than the one that
// retained it.
unsafe impl Send for EndpointObject {}
// SAFETY: `&EndpointObject` reaches the object only through calls listed in the field
// invariant.
unsafe impl Sync for EndpointObject {}

impl XpcEndpoint {
    /// Create an endpoint from an existing connection.
    ///
    /// The endpoint can be embedded in an [`XpcMessage`](crate::XpcMessage) and sent to
    /// another process, which can then call [`into_connection`](Self::into_connection) to
    /// connect back to the listener.
    ///
    /// Returns [`XpcError::EndpointUnsupported`] for a peer connection delivered by a
    /// listener: libxpc only supports endpoints for connections this process created.
    pub fn from_connection(connection: &XpcConnection) -> Result<Self, XpcError> {
        let endpoint = connection.with_created_raw(|raw_conn| {
            // SAFETY: <xpc/endpoint.h> only permits connections obtained from
            // `xpc_connection_create*` calls; `with_created_raw` passes only such a live
            // connection, under its call lock. Returns a +1 endpoint
            // (`XPC_RETURNS_RETAINED`).
            unsafe { xpc_endpoint_create(raw_conn) }
        })?;
        // SAFETY: `endpoint` is null or the +1 object just returned; ownership moves.
        let obj = unsafe { OwnedXpcObject::from_raw(endpoint.cast(), "endpoint") }?;
        tracing::debug!("create xpc endpoint from existing connection");
        Self::from_raw_object(obj)
    }

    /// Establish a peer connection to the listener represented by this endpoint.
    ///
    /// This is the receiving side of the endpoint hand-off: after obtaining an endpoint
    /// from a message, call this to get a live [`XpcConnection`] to the listener that
    /// created the endpoint.
    pub fn into_connection(self) -> Result<XpcConnection, XpcError> {
        let conn = {
            let _calls = ENDPOINT_CALLS.lock();
            // SAFETY: requires a live endpoint (`XPC_NONNULL_ALL`); `inner.object` is one,
            // and `ENDPOINT_CALLS` is held (field invariant). Returns a +1, inactive
            // connection with no other alias (`XPC_RETURNS_RETAINED`).
            unsafe { xpc_connection_create_from_endpoint(self.inner.object.as_raw().cast()) }
        };
        // SAFETY: `conn` is null or the +1, not yet activated result of an
        // `xpc_connection_create*` call with no other alias; ownership moves.
        let connection = unsafe { InactiveXpcConnection::from_raw(conn, "endpoint connection") }?;
        tracing::debug!("create xpc connection from endpoint");
        Ok(XpcConnection::from_inactive(
            connection,
            DEFAULT_MAX_PENDING_EVENTS,
            DEFAULT_MAX_PENDING_EVENTS,
        ))
    }

    /// Create an anonymous XPC channel without launchd registration.
    ///
    /// Returns a `(XpcConnection, XpcEndpoint)` pair:
    /// - The `XpcConnection` is the server side; call [`XpcConnection::recv`] to receive events.
    /// - The `XpcEndpoint` can be embedded in an [`XpcMessage::Endpoint`](crate::XpcMessage) and
    ///   sent to a peer; that peer calls [`XpcEndpoint::into_connection`] to connect back.
    ///
    /// Unlike named listeners created via [`XpcListenerConfig`](crate::XpcListenerConfig), an
    /// anonymous channel requires no launchd registration and no installed plist. It is the
    /// correct choice for in-process tests and ephemeral services that hand out their endpoint
    /// out-of-band (e.g. embedded in a bootstrap message).
    ///
    /// The returned [`XpcConnection`] is a *listener-style* anonymous endpoint. Each peer
    /// that holds the endpoint and calls [`Self::into_connection`] arrives as an
    /// [`XpcEvent::Connection`](crate::XpcEvent::Connection) on the server's
    /// [`XpcConnection::recv`] stream. Anonymous endpoints can be handed out to multiple
    /// peers; clone the endpoint and pass it to each peer that should be able to connect.
    /// Cancel the listener when no further peers should be accepted.
    ///
    /// `queue_label` is an optional GCD dispatch-queue label for the server connection's event
    /// handler. Pass `None` for an anonymous queue.
    pub fn anonymous_channel(queue_label: Option<&str>) -> Result<(XpcConnection, Self), XpcError> {
        let queue = DispatchQueue::new(queue_label)?;
        // SAFETY: a NULL name creates an anonymous listener connection; `targetq` may be
        // NULL, otherwise `queue.as_raw()` is a live queue. Returns a +1, inactive
        // connection (`XPC_RETURNS_RETAINED`).
        let raw_conn = unsafe { xpc_connection_create(ptr::null(), queue.as_raw()) };
        // SAFETY: `raw_conn` is null or the +1, not yet activated result of an
        // `xpc_connection_create*` call with no other alias; ownership moves.
        let connection = unsafe { InactiveXpcConnection::from_raw(raw_conn, "anonymous channel") }?;
        // SAFETY: <xpc/endpoint.h> only permits connections obtained from
        // `xpc_connection_create*` calls; `connection.as_raw()` is such a live connection
        // with no other Rust alias, so no call lock is needed. Returns a +1 endpoint
        // (`XPC_RETURNS_RETAINED`).
        let raw_ep = unsafe { xpc_endpoint_create(connection.as_raw()) };
        // SAFETY: `raw_ep` is null or the +1 object just returned; ownership moves.
        let ep_obj =
            unsafe { OwnedXpcObject::from_raw(raw_ep.cast(), "anonymous channel endpoint") }?;
        let endpoint = Self::from_raw_object(ep_obj)?;
        let conn = XpcConnection::from_inactive(
            connection,
            DEFAULT_MAX_PENDING_EVENTS,
            DEFAULT_MAX_PENDING_EVENTS,
        );
        tracing::debug!("create anonymous xpc listener/endpoint pair");
        Ok((conn, endpoint))
    }

    /// Fails with [`XpcError::UnsupportedObjectType`] unless `obj` is an endpoint.
    pub(crate) fn from_raw_object(obj: OwnedXpcObject) -> Result<Self, XpcError> {
        if !obj.is_type(&raw const _xpc_type_endpoint) {
            return Err(XpcError::UnsupportedObjectType("expected xpc endpoint"));
        }
        Ok(Self {
            inner: Arc::new(EndpointObject { object: obj }),
        })
    }

    /// A new reference to the endpoint, e.g. to embed it in a message.
    pub(crate) fn retain_object(&self) -> OwnedXpcObject {
        self.inner.object.retain_clone()
    }
}

impl PartialEq for XpcEndpoint {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl fmt::Debug for XpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XpcEndpoint")
            .field("ptr", &self.inner.object.as_raw())
            .finish()
    }
}
