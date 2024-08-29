use crate::service::Context;
use std::{fmt, net::SocketAddr};

/// The established connection to a server returned for the http client to be used.
pub struct EstablishedClientConnection<S, State, Request> {
    /// The [`Context`] of the `Request` for which a connection was established.
    pub ctx: Context<State>,
    /// The `Request` for which a connection was established.
    pub req: Request,
    /// The established connection stream/service/... to the server.
    pub conn: S,
    /// The target address connected to.
    pub addr: SocketAddr,
}

impl<S: fmt::Debug, State: fmt::Debug, Request: fmt::Debug> fmt::Debug
    for EstablishedClientConnection<S, State, Request>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EstablishedClientConnection")
            .field("ctx", &self.ctx)
            .field("req", &self.req)
            .field("conn", &self.conn)
            .field("addr", &self.addr)
            .finish()
    }
}

impl<S: Clone, State, Request: Clone> Clone for EstablishedClientConnection<S, State, Request> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            req: self.req.clone(),
            conn: self.conn.clone(),
            addr: self.addr,
        }
    }
}
