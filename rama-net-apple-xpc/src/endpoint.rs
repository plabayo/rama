use std::{fmt, ptr, sync::Arc};

use rama_core::telemetry::tracing;

use crate::{
    connection::XpcConnection,
    error::XpcError,
    ffi::{
        xpc_connection_create, xpc_connection_create_from_endpoint, xpc_endpoint_create,
        xpc_endpoint_t,
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
    inner: Arc<OwnedXpcObject>,
}

impl XpcEndpoint {
    /// Create an endpoint from an existing connection.
    ///
    /// The endpoint can be embedded in an [`XpcMessage`](crate::XpcMessage) and sent to
    /// another process, which can then call [`into_connection`](Self::into_connection) to
    /// connect back to the listener.
    pub fn from_connection(connection: &XpcConnection) -> Result<Self, XpcError> {
        let raw_conn = connection.connection_raw();
        // SAFETY: raw_conn is a valid xpc_connection_t obtained from XpcConnection,
        // which must have been created via xpc_connection_create* (as documented by
        // the xpc_endpoint_create precondition in <xpc/endpoint.h>). The returned
        // xpc_endpoint_t is a new retained XPC object or NULL on failure.
        let endpoint = unsafe { xpc_endpoint_create(raw_conn) };
        let obj = OwnedXpcObject::from_raw(endpoint as _, "endpoint")?;
        tracing::debug!("create xpc endpoint from existing connection");
        Ok(Self {
            inner: Arc::new(obj),
        })
    }

    /// Establish a peer connection to the listener represented by this endpoint.
    ///
    /// This is the receiving side of the endpoint hand-off: after obtaining an endpoint
    /// from a message, call this to get a live [`XpcConnection`] to the listener that
    /// created the endpoint.
    pub fn into_connection(self) -> Result<XpcConnection, XpcError> {
        let endpoint_raw = self.inner.raw as xpc_endpoint_t;
        // SAFETY: endpoint_raw is a valid xpc_endpoint_t stored as xpc_object_t (void*)
        // inside the Arc<OwnedXpcObject>. The cast back to xpc_endpoint_t is safe because
        // OwnedXpcObject always stores the pointer in the same bit-width void* format.
        // xpc_connection_create_from_endpoint returns a new retained connection or NULL.
        let conn = unsafe { xpc_connection_create_from_endpoint(endpoint_raw) };
        let owned = OwnedXpcObject::from_raw(conn as _, "endpoint connection")?;
        tracing::debug!("create xpc connection from endpoint");
        XpcConnection::from_owned_peer(owned)
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
    /// An anonymous channel accepts exactly one client connection via the returned endpoint.
    ///
    /// `queue_label` is an optional GCD dispatch-queue label for the server connection's event
    /// handler. Pass `None` for an anonymous queue.
    pub fn anonymous_channel(queue_label: Option<&str>) -> Result<(XpcConnection, Self), XpcError> {
        let queue = DispatchQueue::new(queue_label)?;
        // SAFETY: xpc_connection_create with a NULL name creates an anonymous connection
        // that acts as the server side of a single-peer channel. queue.raw is either a
        // valid dispatch_queue_t or null (anonymous queue). Returns a new retained
        // xpc_connection_t or NULL on failure.
        let raw_conn = unsafe { xpc_connection_create(ptr::null(), queue.raw) };
        let connection = OwnedXpcObject::from_raw(raw_conn as _, "anonymous channel")?;
        // SAFETY: connection.raw is a valid xpc_connection_t created by xpc_connection_create.
        // xpc_endpoint_create requires a connection created by xpc_connection_create* (not
        // from_endpoint). Returns a new retained xpc_endpoint_t or NULL on failure.
        let raw_ep = unsafe { xpc_endpoint_create(connection.raw as _) };
        let ep_obj = OwnedXpcObject::from_raw(raw_ep as _, "anonymous channel endpoint")?;
        let endpoint = Self::from_raw_object(ep_obj);
        let conn = XpcConnection::from_owned_peer(connection)?;
        tracing::debug!("create anonymous xpc listener/endpoint pair");
        Ok((conn, endpoint))
    }

    pub(crate) fn from_raw_object(obj: OwnedXpcObject) -> Self {
        Self {
            inner: Arc::new(obj),
        }
    }

    pub(crate) fn raw_object(&self) -> &OwnedXpcObject {
        &self.inner
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
            .field("ptr", &self.inner.raw)
            .finish()
    }
}
