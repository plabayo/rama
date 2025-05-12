use super::Interface;
use rama_core::{Context, Service, error::BoxError};

/// Glue trait that is used as the trait bound for
/// code creating/preparing a socket on one layer or another.
///
/// Can also be manually implemented as an alternative [`Service`] trait,
/// but from a Rama POV it is mostly used for UX trait bounds.
pub trait SocketService<State>: Send + Sync + 'static {
    /// Socket returned by the [`SocketService`]
    type Socket: Send + 'static;
    /// Error returned in case of connection / setup failure
    type Error: Into<BoxError> + Send + 'static;

    /// Create a binding to a Unix/Linux/Windows socket.
    fn bind(
        &self,
        ctx: Context<State>,
        interface: impl Into<Interface>,
    ) -> impl Future<Output = Result<(Self::Socket, Context<State>), Self::Error>> + Send + '_;
}

impl<S, State, Socket> SocketService<State> for S
where
    S: Service<
            State,
            Interface,
            Response = (Socket, Context<State>),
            Error: Into<BoxError> + Send + 'static,
        >,
    Socket: Send + 'static,
{
    type Socket = Socket;
    type Error = S::Error;

    fn bind(
        &self,
        ctx: Context<State>,
        interface: impl Into<Interface>,
    ) -> impl Future<Output = Result<(Self::Socket, Context<State>), Self::Error>> + Send + '_ {
        self.serve(ctx, interface.into())
    }
}
