/*
/// Trait used internally by [`tcp_connect`] and the `TcpConnector`
/// to actually establish the [`TcpStream`.]
pub trait TcpStreamConnector: Send + Sync + 'static {
    /// Type of error that can occurr when establishing the connection failed.
    type Error;

    /// Connect to the target via the given [`SocketAddr`]ess to establish a [`TcpStream`].
    fn connect(
        &self,
        addr: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, Self::Error>> + Send + '_;
}
*/

use rama_core::error::BoxError;
use rama_core::Context;
use std::{convert::Infallible, future::Future, sync::Arc};

use crate::client::TcpStreamConnector;

pub struct CreatedTcpStreamConnector<State, Connector> {
    pub ctx: Context<State>,
    pub connector: Connector,
}

pub trait TcpStreamConnectorFactory<State>: Send + Sync + 'static {
    type Connector: TcpStreamConnector;
    type Error;

    fn make_connector(
        &self,
        ctx: Context<State>,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<State, Self::Connector>, Self::Error>>
           + Send
           + '_;
}

impl<State: Send + Sync + 'static> TcpStreamConnectorFactory<State> for () {
    type Connector = ();
    type Error = Infallible;

    fn make_connector(
        &self,
        ctx: Context<State>,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<State, Self::Connector>, Self::Error>>
           + Send
           + '_ {
        std::future::ready(Ok(CreatedTcpStreamConnector { ctx, connector: () }))
    }
}

pub struct TcpStreamConnectorCloneFactory<C>(pub(super) C);

impl<State, C> TcpStreamConnectorFactory<State> for TcpStreamConnectorCloneFactory<C>
where
    C: TcpStreamConnector + Clone,
    State: Send + Sync + 'static,
{
    type Connector = C;
    type Error = Infallible;

    fn make_connector(
        &self,
        ctx: Context<State>,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<State, Self::Connector>, Self::Error>>
           + Send
           + '_ {
        std::future::ready(Ok(CreatedTcpStreamConnector {
            ctx,
            connector: self.0.clone(),
        }))
    }
}

impl<State, F> TcpStreamConnectorFactory<State> for Arc<F>
where
    F: TcpStreamConnectorFactory<State>,
    State: Send + Sync + 'static,
{
    type Connector = F::Connector;
    type Error = F::Error;

    fn make_connector(
        &self,
        ctx: Context<State>,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<State, Self::Connector>, Self::Error>>
           + Send
           + '_ {
        (**self).make_connector(ctx)
    }
}

macro_rules! impl_stream_connector_factory_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<State, $($param),+> TcpStreamConnectorFactory<State> for ::rama_core::combinators::$id<$($param),+>
        where
            State: Send + Sync + 'static,
            $(
                $param: TcpStreamConnectorFactory<State, Connector: TcpStreamConnector<Error: Into<BoxError>>, Error: Into<BoxError>>,
            )+
        {
            type Connector = ::rama_core::combinators::$id<$($param::Connector),+>;
            type Error = BoxError;

            async fn make_connector(
                &self,
                ctx: Context<State>,
            ) -> Result<CreatedTcpStreamConnector<State, Self::Connector>, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => match s.make_connector(ctx).await {
                            Err(e) => Err(e.into()),
                            Ok(CreatedTcpStreamConnector{ ctx, connector }) => Ok(CreatedTcpStreamConnector{
                                ctx,
                                connector: ::rama_core::combinators::$id::$param(connector),
                            }),
                        },
                    )+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_stream_connector_factory_either);
