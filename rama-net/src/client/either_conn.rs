use rama_core::Context;
use rama_core::Service;
use rama_core::combinators::{define_either, impl_async_read_write_either, impl_iterator_either};
use rama_core::error::BoxError;
use std::fmt;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncWrite, Error as IoError, ReadBuf, Result as IoResult};

/// `EitherConn` can be used like you would normally use `Either`, but works with different
/// return types, which is needed when combining different connectors.
macro_rules! impl_either_conn {
    ($macro:ident) => {
        $macro!(EitherConn, A, B,);
        $macro!(EitherConn3, A, B, C,);
        $macro!(EitherConn4, A, B, C, D,);
        $macro!(EitherConn5, A, B, C, D, E,);
        $macro!(EitherConn6, A, B, C, D, E, F,);
        $macro!(EitherConn7, A, B, C, D, E, F, G,);
        $macro!(EitherConn8, A, B, C, D, E, F, G, H,);
        $macro!(EitherConn9, A, B, C, D, E, F, G, H, I,);
    };
}

impl_either_conn!(define_either);
impl_either_conn!(impl_iterator_either);

use crate::client::EstablishedClientConnection;

use super::ConnectorService;

macro_rules! impl_service_either_conn {
    ($id:ident, $($param:ident),+ $(,)?) => {
        rama_macros::paste! {
            impl<$($param, [<Conn $param>]),+, State, Request> Service<State, Request> for $id<$($param),+>
            where
                $(
                    $param: Service<
                        State,
                        Request,
                        Response = EstablishedClientConnection<[<Conn $param>], State, Request>,
                        Error: Into<BoxError>,
                    >,
                    [<Conn $param>]: Send + 'static,
                )+
                Request: Send + 'static,
                State: Clone + Send + Sync + 'static,

            {
                type Response = EstablishedClientConnection<[<$id Connected>]<$([<Conn $param>]),+,>, State, Request>;
                type Error = BoxError;

                async fn serve(&self, ctx: Context<State>, req: Request) -> Result<Self::Response, Self::Error> {
                    match self {
                        $(
                            $id::$param(s) => {
                                let resp = s.serve(ctx, req).await.map_err(Into::into)?;
                                Ok(EstablishedClientConnection {
                                    conn: [<$id Connected>]::$param(resp.conn),
                                    ctx: resp.ctx,
                                    req: resp.req,
                                })
                            },
                        )+
                    }
                }
            }
        }
    };
}

impl_either_conn!(impl_service_either_conn);

/// `EitherConnConnected` is created when `EitherConn` has been connected and we now have an actual
/// connection instead of a connector
macro_rules! impl_either_conn_connected {
    ($macro:ident) => {
        $macro!(EitherConnConnected, A, B,);
        $macro!(EitherConn3Connected, A, B, C,);
        $macro!(EitherConn4Connected, A, B, C, D,);
        $macro!(EitherConn5Connected, A, B, C, D, E,);
        $macro!(EitherConn6Connected, A, B, C, D, E, F,);
        $macro!(EitherConn7Connected, A, B, C, D, E, F, G,);
        $macro!(EitherConn8Connected, A, B, C, D, E, F, G, H,);
        $macro!(EitherConn9Connected, A, B, C, D, E, F, G, H, I,);
    };
}

impl_either_conn_connected!(define_either);
impl_either_conn_connected!(impl_async_read_write_either);
impl_either_conn_connected!(impl_iterator_either);

macro_rules! impl_service_either_conn_connected {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+, State, Request, Response> Service<State, Request> for $id<$($param),+>
        where
            $(
                $param: Service<State, Request, Response = Response, Error: Into<BoxError>>,
            )+
            Request: Send + 'static,
            State: Clone + Send + Sync + 'static,
            Response: Send + 'static,
        {
            type Response = Response;
            type Error = BoxError;

            async fn serve(&self, ctx: Context<State>, req: Request) -> Result<Self::Response, Self::Error> {
                match self {
                    $(
                        $id::$param(s) => s.serve(ctx, req).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

impl_either_conn_connected!(impl_service_either_conn_connected);

pub struct EitherConnector<S, T, F> {
    conditional: T,
    default: S,
    decider: F,
}

impl<S, T, F> EitherConnector<S, T, F> {
    pub fn new(
        conditional: T,
        default: S,
        decider: F,
    ) -> EitherConnector<EitherConn<T, S>, EitherConn<T, S>, F> {
        let conditional: EitherConn<T, S> = EitherConn::A(conditional);
        let default: EitherConn<T, S> = EitherConn::B(default);

        EitherConnector {
            conditional,
            default,
            decider,
        }
    }
}

impl<State, Request, T, S, X, Y, F> Service<State, Request>
    for EitherConnector<EitherConn<T, S>, EitherConn<T, S>, F>
where
    Request: Send + 'static,
    State: Clone + Send + Sync + 'static,
    S: Service<
            State,
            Request,
            Response = EstablishedClientConnection<X, State, Request>,
            Error: Into<BoxError>,
        >,
    T: Service<
            State,
            Request,
            Response = EstablishedClientConnection<Y, State, Request>,
            Error: Into<BoxError>,
        >,
    X: Send + 'static,
    Y: Send + 'static,
    F: Fn(&Context<State>, &Request) -> bool + Send + Sync + 'static,
{
    type Response = EstablishedClientConnection<EitherConnConnected<Y, X>, State, Request>;
    type Error = BoxError;

    async fn serve(
        &self,
        ctx: Context<State>,
        req: Request,
    ) -> Result<Self::Response, Self::Error> {
        match (self.decider)(&ctx, &req) {
            true => self.conditional.serve(ctx, req).await.map_err(Into::into),
            false => self.default.serve(ctx, req).await.map_err(Into::into),
        }
    }
}
