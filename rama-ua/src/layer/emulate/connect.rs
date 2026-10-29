use rama_core::{
    Layer, Service,
    error::{BoxError, BoxErrorExt as _},
    extensions::ExtensionsRef,
    telemetry::tracing,
};
use rama_http::conn::TargetHttpVersion;
use rama_net::{
    HttpVersionInputExt, TargetHttpVersionInputExt,
    client::{ConnectionError, ConnectionErrorKind, ConnectorService, EstablishedClientConnection},
    http::FallbackHttpVersion,
};

use crate::profile::{
    replay::{
        connection::{
            compiler::{
                ConnectionProfileBindings as _, ConnectionProfileCompiler,
                InstalledConnectionProfile,
            },
            preparation::ConnectionPreparation,
        },
        request::{LoweredProfileItem, ProfilePreservationDifference, ProfilePreservationReport},
    },
    selection::variants::ProfileConnectionReuse,
};

use super::{preserve, profile::OptionalEmulation};

/// Connector that prepares and checks the connection variant of the profile
/// selected by [`ProfileEmulateLayer`](super::ProfileEmulateLayer).
///
/// Connections without a published emulation context pass through unchanged.
#[derive(Debug, Clone)]
pub struct ProfileEmulateHttpConnectModifier<S, C = ()> {
    inner: S,
    compiler: C,
}

impl<S: Default> Default for ProfileEmulateHttpConnectModifier<S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

impl<S> ProfileEmulateHttpConnectModifier<S> {
    /// Create a new [`ProfileEmulateHttpConnectModifier`].
    #[inline]
    #[must_use]
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            compiler: (),
        }
    }
}

impl<S, C> ProfileEmulateHttpConnectModifier<S, C> {
    /// Register a backend that prepares additional captured connection components.
    #[must_use]
    pub fn with_connection_compiler<D>(
        self,
        compiler: D,
    ) -> ProfileEmulateHttpConnectModifier<S, D> {
        ProfileEmulateHttpConnectModifier {
            inner: self.inner,
            compiler,
        }
    }
}

impl<S, C, Input> Service<Input> for ProfileEmulateHttpConnectModifier<S, C>
where
    S: ConnectorService<Input>,
    C: ConnectionProfileCompiler<Input>,
    C::Compiled: InstalledConnectionProfile<Input>,
    Input: ExtensionsRef + HttpVersionInputExt + TargetHttpVersionInputExt + Send + 'static,
{
    type Error = ConnectionError;
    type Output = EstablishedClientConnection<S::Connection, Input>;

    async fn serve(&self, req: Input) -> Result<Self::Output, Self::Error> {
        let mut skipped = false;
        let prepared = match ConnectionPreparation::prepare(&req, |selection, components| {
            // Without the captured offer the compiler leaves the caller's TLS configuration as is.
            #[cfg(feature = "tls")]
            if preserve::keeps_tls(req.extensions()) && components.tls.take().is_some() {
                tracing::trace!("captured TLS replay skipped: the caller keeps its own TLS");
                preserve::report_kept(
                    &mut components.preservation_report,
                    LoweredProfileItem::CallerTls,
                );
            }
            self.compiler.compile(&req, selection, components)
        }) {
            Ok(prepared) => prepared,
            Err(error) if req.extensions().contains::<OptionalEmulation>() => {
                tracing::debug!(
                    "profile connection emulation skipped, connecting natively: {error}"
                );
                skipped = true;
                None
            }
            Err(error) => {
                return Err(ConnectionError::local(
                    error,
                    ConnectionErrorKind::InvalidInput,
                ));
            }
        };
        let connection_admission = if let Some((mut prepared, compiled)) = prepared {
            let (admission, components) = if preserve::keeps_http(req.extensions()) {
                tracing::trace!("captured HTTP settings skipped: the caller keeps its own HTTP");
                let (admission, mut components) = prepared.into_parts();
                // Nothing later on this connection may replay the captured HTTP startup.
                components.h2_early_frames = None;
                components.h3_peer_settings = None;
                components.h3_settings_evidence = None;
                components.h3_sequence = None;
                components.h3_bootstrap = None;
                preserve::report_kept(
                    &mut components.preservation_report,
                    LoweredProfileItem::CallerHttp,
                );
                (admission, components)
            } else {
                prepared.apply_http(&req).map_err(|error| {
                    ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
                })?;
                prepared.into_parts()
            };
            req.extensions()
                .insert(components.preservation_report.clone());
            req.extensions().insert(components);
            req.extensions().insert(admission.selection().clone());
            let bindings = compiled.apply(req.extensions());
            Some((admission, bindings))
        } else {
            None
        };

        let EstablishedClientConnection { conn, input: req } = self.inner.connect(req).await?;

        if skipped {
            let mut report = conn
                .extensions()
                .get_ref::<ProfilePreservationReport>()
                .cloned()
                .unwrap_or_default();
            report.push(ProfilePreservationDifference::LoweredProfileItem {
                item: LoweredProfileItem::UnemulatedConnection,
            });
            conn.extensions().insert(report);
        }

        if let Some((admission, bindings)) = connection_admission {
            let context = admission.check_context(req.extensions()).map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
            })?;
            bindings.check(&req).map_err(|error| {
                ConnectionError::local(error, ConnectionErrorKind::InvalidInput)
            })?;
            let version = conn
                .extensions()
                .get_ref::<TargetHttpVersion>()
                .map(|target| target.0)
                .or_else(|| req.target_http_version())
                .or_else(|| {
                    req.extensions()
                        .get_ref::<FallbackHttpVersion>()
                        .map(|version| version.0)
                })
                .or_else(|| req.http_version())
                .ok_or_else(|| {
                    ConnectionError::local(
                        BoxError::from_static_str(
                            "captured profile connection has no negotiated HTTP version",
                        ),
                        ConnectionErrorKind::Protocol,
                    )
                })?;
            context
                .selected
                .validate_negotiated_protocol(version)
                .map_err(|error| {
                    ConnectionError::application(error, ConnectionErrorKind::Protocol)
                })?;
            // Every request using this connection inherits its wire differences.
            if let Some(report) = req.extensions().get_ref::<ProfilePreservationReport>() {
                let report = match conn.extensions().get_ref::<ProfilePreservationReport>() {
                    Some(inner) => report.clone().followed_by(inner.clone()),
                    None => report.clone(),
                };
                conn.extensions().insert(report);
            }
            conn.extensions().insert(admission.into_selection());
            ProfileConnectionReuse::new(context, version, req.extensions())
                .publish(conn.extensions());
        }

        Ok(EstablishedClientConnection { input: req, conn })
    }
}

/// Layer for [`ProfileEmulateHttpConnectModifier`].
#[derive(Debug, Clone)]
pub struct ProfileEmulateHttpConnectModifierLayer<C = ()> {
    compiler: C,
}

impl Default for ProfileEmulateHttpConnectModifierLayer {
    fn default() -> Self {
        Self { compiler: () }
    }
}

impl ProfileEmulateHttpConnectModifierLayer {
    /// Create a new [`ProfileEmulateHttpConnectModifierLayer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl<C> ProfileEmulateHttpConnectModifierLayer<C> {
    /// Register the backend compiler used before opening a captured connection.
    #[must_use]
    pub fn with_connection_compiler<D>(
        self,
        compiler: D,
    ) -> ProfileEmulateHttpConnectModifierLayer<D> {
        ProfileEmulateHttpConnectModifierLayer { compiler }
    }
}

impl<S, C: Clone> Layer<S> for ProfileEmulateHttpConnectModifierLayer<C> {
    type Service = ProfileEmulateHttpConnectModifier<S, C>;

    fn layer(&self, inner: S) -> Self::Service {
        ProfileEmulateHttpConnectModifier {
            inner,
            compiler: self.compiler.clone(),
        }
    }

    fn into_layer(self, inner: S) -> Self::Service {
        ProfileEmulateHttpConnectModifier {
            inner,
            compiler: self.compiler,
        }
    }
}
