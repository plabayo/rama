//! Unix (domain) socket client module for Rama.

use rama_core::{
    Service,
    error::{BoxError, ErrorContext},
    extensions::ExtensionsMut,
    telemetry::tracing,
};
use rama_net::client::EstablishedClientConnection;

use crate::{ClientUnixSocketInfo, TokioUnixStream, UnixSocketInfo, UnixStream};
use std::{convert::Infallible, path::PathBuf, sync::Arc};

/// A connector which can be used to establish a Unix connection to a server.
pub struct UnixConnector<ConnectorFactory = (), T = UnixTarget> {
    connector_factory: ConnectorFactory,
    target: T,
}

impl<ConnectorFactory: std::fmt::Debug, UnixTarget: std::fmt::Debug> std::fmt::Debug
    for UnixConnector<ConnectorFactory, UnixTarget>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnixConnector")
            .field("connector_factory", &self.connector_factory)
            .field("target", &self.target)
            .finish()
    }
}

impl<ConnectorFactory: Clone, UnixTarget: Clone> Clone
    for UnixConnector<ConnectorFactory, UnixTarget>
{
    fn clone(&self) -> Self {
        Self {
            connector_factory: self.connector_factory.clone(),
            target: self.target.clone(),
        }
    }
}

#[derive(Debug, Clone)]
/// Type of [`UnixConnector`] which connects to a fixed [`Path`].
pub struct UnixTarget(PathBuf);

impl UnixConnector {
    /// Create a new [`UnixConnector`], which is used to establish a connection to a server
    /// at a fixed path.
    ///
    /// You can use middleware around the [`UnixConnector`]
    /// or add connection pools, retry logic and more.
    pub fn fixed(path: impl Into<PathBuf>) -> Self {
        Self {
            target: UnixTarget(path.into()),
            connector_factory: (),
        }
    }
}

impl<T> UnixConnector<(), T> {
    /// Consume `self` to attach the given `Connector` (a [`UnixStreamConnector`]) as a new [`UnixConnector`].
    pub fn with_connector<Connector>(
        self,
        connector: Connector,
    ) -> UnixConnector<UnixStreamConnectorCloneFactory<Connector>, T>
where {
        UnixConnector {
            connector_factory: UnixStreamConnectorCloneFactory(connector),
            target: self.target,
        }
    }

    /// Consume `self` to attach the given `Factory` (a [`UnixStreamConnectorFactory`]) as a new [`UnixConnector`].
    pub fn with_connector_factory<Factory>(self, factory: Factory) -> UnixConnector<Factory, T>
where {
        UnixConnector {
            connector_factory: factory,
            target: self.target,
        }
    }
}

impl<Request, ConnectorFactory> Service<Request> for UnixConnector<ConnectorFactory>
where
    Request: Send + 'static,
    ConnectorFactory: UnixStreamConnectorFactory<
            Connector: UnixStreamConnector<Error: Into<BoxError> + Send + 'static>,
            Error: Into<BoxError> + Send + 'static,
        > + Clone,
{
    type Response = EstablishedClientConnection<UnixStream, Request>;
    type Error = BoxError;

    async fn serve(&self, req: Request) -> Result<Self::Response, Self::Error> {
        let CreatedUnixStreamConnector { connector } = self
            .connector_factory
            .make_connector()
            .await
            .map_err(Into::into)?;

        let mut conn = connector
            .connect(self.target.0.clone())
            .await
            .map_err(Into::into)?;

        let info = ClientUnixSocketInfo(UnixSocketInfo::new(
            conn.stream
                .local_addr()
                .inspect_err(|err| {
                    tracing::debug!(
                        "failed to receive local addr of established connection: {err:?}"
                    )
                })
                .ok(),
            conn.stream
                .peer_addr()
                .context("failed to retrieve peer address of established connection")?,
        ));
        conn.extensions_mut().insert(info);

        Ok(EstablishedClientConnection { req, conn })
    }
}

/// Trait used by the `UnixConnector`
/// to actually establish the [`UnixStream`].
pub trait UnixStreamConnector: Send + Sync + 'static {
    /// Type of error that can occurr when establishing the connection failed.
    type Error;

    /// Connect to the path and return the established [`UnixStream`].
    fn connect(
        &self,
        path: PathBuf,
    ) -> impl Future<Output = Result<UnixStream, Self::Error>> + Send + '_;
}

impl UnixStreamConnector for () {
    type Error = std::io::Error;

    async fn connect(&self, path: PathBuf) -> Result<UnixStream, Self::Error> {
        Ok(TokioUnixStream::connect(path).await?.into())
    }
}

impl<T: UnixStreamConnector> UnixStreamConnector for Arc<T> {
    type Error = T::Error;

    fn connect(
        &self,
        path: PathBuf,
    ) -> impl Future<Output = Result<UnixStream, Self::Error>> + Send + '_ {
        (**self).connect(path)
    }
}

macro_rules! impl_stream_connector_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl<$($param),+> UnixStreamConnector for ::rama_core::combinators::$id<$($param),+>
        where
            $(
                $param: UnixStreamConnector<Error: Into<BoxError>>,
            )+
        {
            type Error = BoxError;

            async fn connect(
                &self,
                path: PathBuf,
            ) -> Result<UnixStream, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => s.connect(path).await.map_err(Into::into),
                    )+
                }
            }
        }
    };
}

::rama_core::combinators::impl_either!(impl_stream_connector_either);

/// Contains a `Connector` created by a [`UnixStreamConnectorFactory`],
/// together with the [`Context`] used to create it in relation to.
pub struct CreatedUnixStreamConnector<Connector> {
    pub connector: Connector,
}

impl<Connector> std::fmt::Debug for CreatedUnixStreamConnector<Connector>
where
    Connector: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedUnixStreamConnector")
            .field("connector", &self.connector)
            .finish()
    }
}

impl<Connector> Clone for CreatedUnixStreamConnector<Connector>
where
    Connector: Clone,
{
    fn clone(&self) -> Self {
        Self {
            connector: self.connector.clone(),
        }
    }
}

/// Factory to create a [`UnixStreamConnector`]. This is used by the Unix
/// stream service to create a stream within a specific [`Context`].
///
/// In the most simplest case you use a [`UnixStreamConnectorCloneFactory`]
/// to use a [`Clone`]able [`UnixStreamConnectorCloneFactory`], but in more
/// advanced cases you can use variants of [`UnixStreamConnector`] specific
/// to the given contexts.
pub trait UnixStreamConnectorFactory: Send + Sync + 'static {
    /// `UnixStreamConnector` created by this [`UnixStreamConnectorFactory`]
    type Connector: UnixStreamConnector;
    /// Error returned in case [`UnixStreamConnectorFactory`] was
    /// not able to create a [`UnixStreamConnector`].
    type Error;

    /// Try to create a [`UnixStreamConnector`], and return an error or otherwise.
    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedUnixStreamConnector<Self::Connector>, Self::Error>> + Send + '_;
}

impl UnixStreamConnectorFactory for () {
    type Connector = ();
    type Error = Infallible;

    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedUnixStreamConnector<Self::Connector>, Self::Error>> + Send + '_
    {
        std::future::ready(Ok(CreatedUnixStreamConnector { connector: () }))
    }
}

/// Utility implementation of a [`UnixStreamConnectorFactory`] which is implemented
/// to allow one to use a [`Clone`]able [`UnixStreamConnector`] as a [`UnixStreamConnectorFactory`]
/// by cloning itself.
///
/// This struct cannot be created by third party crates
/// and instead is to be used via other API's provided by this crate.
pub struct UnixStreamConnectorCloneFactory<C>(pub(super) C);

impl<C> std::fmt::Debug for UnixStreamConnectorCloneFactory<C>
where
    C: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UnixStreamConnectorCloneFactory")
            .field(&self.0)
            .finish()
    }
}

impl<C> Clone for UnixStreamConnectorCloneFactory<C>
where
    C: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<C> UnixStreamConnectorFactory for UnixStreamConnectorCloneFactory<C>
where
    C: UnixStreamConnector + Clone,
{
    type Connector = C;
    type Error = Infallible;

    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedUnixStreamConnector<Self::Connector>, Self::Error>> + Send + '_
    {
        std::future::ready(Ok(CreatedUnixStreamConnector {
            connector: self.0.clone(),
        }))
    }
}

impl<F> UnixStreamConnectorFactory for Arc<F>
where
    F: UnixStreamConnectorFactory,
{
    type Connector = F::Connector;
    type Error = F::Error;

    fn make_connector(
        &self,
    ) -> impl Future<Output = Result<CreatedUnixStreamConnector<Self::Connector>, Self::Error>> + Send + '_
    {
        (**self).make_connector()
    }
}

macro_rules! impl_stream_connector_factory_either {
    ($id:ident, $($param:ident),+ $(,)?) => {
        impl< $($param),+> UnixStreamConnectorFactory for ::rama_core::combinators::$id<$($param),+>
        where

            $(
                $param: UnixStreamConnectorFactory< Connector: UnixStreamConnector<Error: Into<BoxError>>, Error: Into<BoxError>>,
            )+
        {
            type Connector = ::rama_core::combinators::$id<$($param::Connector),+>;
            type Error = BoxError;

            async fn make_connector(
                &self,
            ) -> Result<CreatedUnixStreamConnector< Self::Connector>, Self::Error> {
                match self {
                    $(
                        ::rama_core::combinators::$id::$param(s) => match s.make_connector().await {
                            Err(e) => Err(e.into()),
                            Ok(CreatedUnixStreamConnector{ connector }) => Ok(CreatedUnixStreamConnector {
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
