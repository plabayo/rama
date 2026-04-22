use std::{fmt, sync::Arc};

use crate::{
    connection::XpcConnection,
    error::XpcError,
    ffi::{xpc_connection_create_from_endpoint, xpc_endpoint_create, xpc_endpoint_t},
    object::OwnedXpcObject,
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
        let endpoint = unsafe { xpc_endpoint_create(raw_conn) };
        let obj = OwnedXpcObject::from_raw(endpoint as _, "endpoint")?;
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
        let conn = unsafe { xpc_connection_create_from_endpoint(endpoint_raw) };
        let owned = OwnedXpcObject::from_raw(conn as _, "endpoint connection")?;
        XpcConnection::from_owned_peer(owned)
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
