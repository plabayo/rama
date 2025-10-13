use rama_core::error::BoxError;
use std::fmt;
use std::{convert::Infallible, sync::Arc};

use crate::client::TcpStreamConnector;

/// Contains a `Connector` created by a [`TcpStreamConnectorFactory`],
/// together with the [`Context`] used to create it in relation to.
pub struct CreatedTcpStreamConnector<Connector> {
    pub connector: Connector,
}

impl<Connector> fmt::Debug for CreatedTcpStreamConnector<Connector>
where
    Connector: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreatedTcpStreamConnector")
            .field("connector", &self.connector)
            .finish()
    }
}

impl<Connector> Clone for CreatedTcpStreamConnector<Connector>
where
    Connector: Clone,
{
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
        }
    }
}

/// Factory to create a [`TcpStreamConnector`]. This is used by the TCP
/// stream service to create a stream within a specific [`Context`].
///
/// In the most simplest case you use a [`TcpStreamConnectorCloneFactory`]
/// to use a [`Clone`]able [`TcpStreamConnectorCloneFactory`], but in more
/// advanced cases you can use variants of [`TcpStreamConnector`] specific
/// to the given contexts.
///
/// Examples why you might variants:
///
/// - you might have specific needs for your sockets (e.g. bind to a specific interface)
///   that you do not have for all your egress traffic. A crate such as [`socket2`]
///   can help you with this;
/// - it is possible that you have specific filter or firewall needs for some of your
///   egress traffic but not all of it.
///
/// [`socket`]: https://docs.rs/socket2
pub trait TcpStreamConnectorFactory: Send + Sync + 'static {
    /// `TcpStreamConnector` created by this [`TcpStreamConnectorFactory`]
    type Connector: TcpStreamConnector;
    /// Error returned in case [`TcpStreamConnectorFactory`] was
    /// not able to create a [`TcpStreamConnector`].
    type Error;

    /// Try to create a [`TcpStreamConnector`], and return an error or otherwise.
    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<Self::Connector>, Self::Error>> + Send + '_;
}

impl TcpStreamConnectorFactory for () {
    type Connector = ();
    type Error = Infallible;

    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<Self::Connector>, Self::Error>> + Send + '_
    {
        std::future::ready(Ok(CreatedTcpStreamConnector { connector: () }))
    }
}

/// Utility implementation of a [`TcpStreamConnectorFactory`] which is implemented
/// to allow one to use a [`Clone`]able [`TcpStreamConnector`] as a [`TcpStreamConnectorFactory`]
/// by cloning itself.
///
/// This struct cannot be created by third party crates
/// and instead is to be used via other API's provided by this crate.
pub struct TcpStreamConnectorCloneFactory<C>(pub(super) C);

impl<C> fmt::Debug for TcpStreamConnectorCloneFactory<C>
where
    C: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TcpStreamConnectorCloneFactory")
            .field(&self.0)
            .finish()
    }
}

impl<C> Clone for TcpStreamConnectorCloneFactory<C>
where
    C: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C> TcpStreamConnectorFactory for TcpStreamConnectorCloneFactory<C>
where
    C: TcpStreamConnector + Clone,
{
    type Connector = C;
    type Error = Infallible;

    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<Self::Connector>, Self::Error>> + Send + '_
    {
        std::future::ready(Ok(CreatedTcpStreamConnector {
            connector: self.0.clone(),
        }))
    }
}

impl<F> TcpStreamConnectorFactory for Arc<F>
where
    F: TcpStreamConnectorFactory,
{
    type Connector = F::Connector;
    type Error = F::Error;

    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedTcpStreamConnector<Self::Connector>, Self::Error>> + Send + '_
    {
        (**self).make_connector()
    }
}

macro_rules! impl_stream_connector_factory_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl< $($param),+> TcpStreamConnectorFactory for ::rama_core::combinators::$id<$($param),+>
        where

            $(
                $param: TcpStreamConnectorFactory< Connector: TcpStreamConnector<Error: Into<BoxError>>, Error: Into<BoxError>>,
            )+
        {
            type Connector = ::rama_core::combinators::$id<$($param::Connector),+>;
            type Error = BoxError;

            async fn make_connector(
                &self,

            ) -> Result<CreatedTcpStreamConnector< Self::Connector>, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => match s.make_connector().await {
                            Err(e) => Err(e.into()),
                            Ok(CreatedTcpStreamConnector{ connector }) => Ok(CreatedTcpStreamConnector{

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
