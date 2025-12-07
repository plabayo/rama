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

macro_rules! impl_service_either_conn {
    ($id:ident, $($param:ident),+ $(,)?) => {
        rama_macros::paste! {
            impl<$($param, [<Conn $param>]),+, Input> Service<Input> for $id<$($param),+>
            where
                $(
                    $param: Service<
                        Input,
                        Output = EstablishedClientConnection<[<Conn $param>], Input>,
                        Error: Into<BoxError>,
                    >,
                    [<Conn $param>]: Send + 'static,
                )+
                Input: Send + 'static,
            {
                type Output = EstablishedClientConnection<[<$id Connected>]<$([<Conn $param>]),+,>, Input>;
                type Error = BoxError;

                async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
                    match self {
                        $(
                            $id::$param(s) => {
                                let resp = s.serve(input).await.map_err(Into::into)?;
                                Ok(EstablishedClientConnection {
                                    conn: [<$id Connected>]::$param(resp.conn),
                                    input: resp.input,
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
        impl<$($param),+, Input, Output> Service<Input> for $id<$($param),+>
        where
            $(
                $param: Service<Input, Output = Output, Error: Into<BoxError>>,
            )+
            Input: Send + 'static,
            Output: Send + 'static,
        {
            type Output = Output;
            type Error = BoxError;

            async fn serve(&self, input: Input) -> Result<Self::Output, Self::Error> {
                match self {
                    $(
                        $id::$param(s) => s.serve(input).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

impl_either_conn_connected!(impl_service_either_conn_connected);
