//! Evaluate `FindProxyForURL` for a request uri.

use std::fmt;
use std::time::Duration;

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError};
use rama_core::graceful::ShutdownGuard;
use rama_core::telemetry::tracing;
use rama_core::{Service, service::BoxService};
use rama_js::{JsRuntime, JsRuntimeBuilder, JsWorker};
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::Mutex;

use crate::{PacDirectives, PacEnv, PacScript};

/// The classic entry point; `FindProxyForURLEx` wins when a script
/// defines it, mirroring what WinHTTP does.
const ENTRY_POINT: &str = "FindProxyForURL";
const ENTRY_POINT_EX: &str = "FindProxyForURLEx";

/// How much of the request uri a PAC script gets to see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PacUrlSanitize {
    /// Strip the path and query of `https` uris, as browsers do: a proxy
    /// decision needs the origin, not the page someone visited.
    #[default]
    HttpsOnly,
    /// Strip the path and query of every uri.
    All,
    /// Pass the uri through, path and query included.
    None,
}

/// Evaluates a PAC script to decide how a request should be proxied.
///
/// The script comes from a provider on every lookup, and the worker is
/// only rebuilt when the script actually changed — so an always-fetching
/// provider stays affordable and a swapped script takes effect at once.
pub struct PacResolver {
    provider: BoxService<Uri, PacScript, OpaqueError>,
    script_uri: Uri,
    blueprint: JsRuntimeBuilder,
    worker: WorkerConfig,
    sanitize: PacUrlSanitize,
    state: Mutex<Option<ScriptState>>,
}

/// What happened the last time a script was loaded.
enum ScriptState {
    Loaded(LoadedScript),
    /// This exact script cannot be loaded, so re-loading it would spawn a
    /// worker and re-parse it for nothing. Keyed by the script itself, so
    /// a changed script always gets a fresh attempt.
    Rejected {
        script: PacScript,
        error: ArcStr,
    },
}

#[derive(Debug, Clone, Default)]
struct WorkerConfig {
    timeout: Option<Duration>,
    queue_capacity: Option<usize>,
    graceful: Option<ShutdownGuard>,
}

struct LoadedScript {
    script: PacScript,
    worker: JsWorker,
    entry_point: &'static str,
}

impl ScriptState {
    fn script(&self) -> &PacScript {
        match self {
            Self::Loaded(loaded) => &loaded.script,
            Self::Rejected { script, .. } => script,
        }
    }
}

impl fmt::Debug for PacResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacResolver")
            .field("script_uri", &self.script_uri)
            .field("sanitize", &self.sanitize)
            .finish_non_exhaustive()
    }
}

impl PacResolver {
    /// Create a [`PacResolverBuilder`].
    #[must_use]
    pub fn builder() -> PacResolverBuilder {
        PacResolverBuilder::default()
    }

    /// Load `script`, remembering a script-caused rejection so the next
    /// lookup does not rebuild a worker that is going to fail again.
    async fn load(&self, script: PacScript) -> Result<ScriptState, BoxError> {
        match LoadedScript::spawn(&self.blueprint, &self.worker, script.clone()).await {
            Ok(loaded) => Ok(ScriptState::Loaded(loaded)),
            // only the script itself is cached as rejected: an
            // environmental failure (no thread available, ...) must stay
            // retryable, so it propagates without being remembered
            Err(LoadError::Script(error)) => {
                let error = ArcStr::from(error.to_string());
                tracing::debug!("pac script rejected, not retrying until it changes: {error}");
                Ok(ScriptState::Rejected { script, error })
            }
            Err(LoadError::Environment(error)) => Err(error),
        }
    }

    /// The proxies to try for `uri`, in order.
    pub async fn find_proxy(&self, uri: &Uri) -> Result<PacDirectives, BoxError> {
        let script = self
            .provider
            .serve(self.script_uri.clone())
            .await
            .context("obtain pac script")?;

        let (worker, entry_point, script) = {
            let mut state = self.state.lock().await;
            // a byte-identical script keeps its compiled worker, and a
            // byte-identical rejected script is not retried at all
            if state.as_ref().is_none_or(|state| *state.script() != script) {
                *state = Some(self.load(script).await?);
            }
            match state.as_ref() {
                Some(ScriptState::Loaded(loaded)) => (
                    loaded.worker.clone(),
                    loaded.entry_point,
                    loaded.script.clone(),
                ),
                Some(ScriptState::Rejected { error, .. }) => {
                    return Err(BoxError::from_static_str("pac script was rejected")
                        .context_str_field("reason", error.to_string()));
                }
                None => return Err(BoxError::from_static_str("pac script failed to load")),
            }
        };

        let (url, host) = self.sanitize.apply(uri)?;
        let result = worker.call(entry_point, [url.clone(), host.clone()]).await;

        let value = match result {
            Ok(value) => value,
            Err(err) if err.kind() == rama_js::JsErrorKind::Setup => {
                // the worker is gone (execution limit poisoned it, or a
                // host fn panicked): rebuild it once and retry
                tracing::debug!("pac worker gone, respawning: {err}");
                let (worker, entry_point) = {
                    let mut state = self.state.lock().await;
                    let reloaded = self.load(script).await?;
                    match state.insert(reloaded) {
                        ScriptState::Loaded(loaded) => (loaded.worker.clone(), loaded.entry_point),
                        ScriptState::Rejected { error, .. } => {
                            return Err(BoxError::from_static_str(
                                "pac script was rejected on respawn",
                            )
                            .context_str_field("reason", error.to_string()));
                        }
                    }
                };
                worker
                    .call(entry_point, [url, host])
                    .await
                    .context("call pac entry point after respawn")?
            }
            Err(err) => return Err(err).context("call pac entry point"),
        };

        let result = value
            .as_str()
            .context("pac entry point did not return a string")?;
        result.parse().context("parse pac result")
    }
}

/// Distinguishes a script rama will never load from a failure that may
/// well succeed next time.
enum LoadError {
    Script(BoxError),
    Environment(BoxError),
}

impl LoadedScript {
    async fn spawn(
        blueprint: &JsRuntimeBuilder,
        config: &WorkerConfig,
        script: PacScript,
    ) -> Result<Self, LoadError> {
        let mut builder = JsWorker::builder()
            .maybe_with_timeout(config.timeout)
            .maybe_with_graceful(config.graceful.clone());
        if let Some(capacity) = config.queue_capacity {
            builder.set_queue_capacity(capacity);
        }
        let worker = builder
            .spawn(blueprint.clone())
            .context("spawn pac worker")
            .map_err(LoadError::Environment)?;
        worker
            .exec(script.as_str().to_owned())
            .await
            .context("execute pac script")
            .map_err(LoadError::Script)?;

        let has_ex = worker
            .run(|runtime| Ok(runtime.has_global_fn(ENTRY_POINT_EX)))
            .await
            .context("probe pac entry point")
            .map_err(LoadError::Environment)?;
        let entry_point = if has_ex {
            ENTRY_POINT_EX
        } else {
            let has_classic = worker
                .run(|runtime| Ok(runtime.has_global_fn(ENTRY_POINT)))
                .await
                .context("probe pac entry point")
                .map_err(LoadError::Environment)?;
            if !has_classic {
                return Err(LoadError::Script(BoxError::from_static_str(
                    "pac script defines no FindProxyForURL(Ex) function",
                )));
            }
            ENTRY_POINT
        };

        Ok(Self {
            script,
            worker,
            entry_point,
        })
    }
}

impl PacUrlSanitize {
    /// The `(url, host)` pair to hand the script.
    fn apply(self, uri: &Uri) -> Result<(String, String), BoxError> {
        let host = uri
            .host_str()
            .context("request uri has no host")?
            .into_owned();

        let strip = match self {
            Self::All => true,
            Self::None => false,
            Self::HttpsOnly => uri.scheme().is_some_and(rama_net::Protocol::is_secure),
        };

        // credentials never belong in a script argument
        let uri = uri.clone().without_user_info();
        let url = if strip {
            // browsers strip to the origin but keep the root path, and
            // `shExpMatch(url, "https://*.corp/*")` relies on it
            let mut url = uri.without_query().without_fragment();
            url.path_mut().clear().ensure_trailing_slash();
            url
        } else {
            uri.without_fragment()
        };

        Ok((url.to_string(), host))
    }
}

/// Builds a [`PacResolver`].
pub struct PacResolverBuilder {
    env: PacEnv,
    runtime: JsRuntimeBuilder,
    sanitize: PacUrlSanitize,
    execution_time_limit: Option<Duration>,
    timeout: Option<Duration>,
    queue_capacity: Option<usize>,
    graceful: Option<ShutdownGuard>,
}

impl fmt::Debug for PacResolverBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacResolverBuilder")
            .field("env", &self.env)
            .field("sanitize", &self.sanitize)
            .field("execution_time_limit", &self.execution_time_limit)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl Default for PacResolverBuilder {
    fn default() -> Self {
        Self {
            env: PacEnv::default(),
            runtime: JsRuntime::builder(),
            sanitize: PacUrlSanitize::default(),
            execution_time_limit: Some(PacResolver::DEFAULT_EXECUTION_TIME_LIMIT),
            timeout: None,
            queue_capacity: None,
            graceful: None,
        }
    }
}

impl PacResolver {
    /// Wall-clock limit one `FindProxyForURL` call gets by default.
    pub const DEFAULT_EXECUTION_TIME_LIMIT: Duration = Duration::from_secs(10);
}

impl PacResolverBuilder {
    generate_set_and_with! {
        /// Configure the javascript environment the script runs in.
        pub fn env(mut self, env: PacEnv) -> Self {
            self.env = env;
            self
        }
    }

    generate_set_and_with! {
        /// Start from this runtime blueprint instead of the default one,
        /// e.g. to register extra globals or tighten the js limits.
        ///
        /// The resolver owns the execution time limit, so one set here is
        /// overridden.
        pub fn runtime(mut self, runtime: JsRuntimeBuilder) -> Self {
            self.runtime = runtime;
            self
        }
    }

    generate_set_and_with! {
        /// How much of the request uri the script sees
        /// (defaults to [`PacUrlSanitize::HttpsOnly`]).
        pub fn sanitize(mut self, sanitize: PacUrlSanitize) -> Self {
            self.sanitize = sanitize;
            self
        }
    }

    generate_set_and_with! {
        /// Wall-clock limit for one script call (defaults to
        /// [`PacResolver::DEFAULT_EXECUTION_TIME_LIMIT`]).
        ///
        /// Exceeding it poisons the runtime; the resolver rebuilds the
        /// worker on the next lookup. `None` removes the limit, at the
        /// risk of a script wedging its worker forever.
        pub fn execution_time_limit(mut self, execution_time_limit: Option<Duration>) -> Self {
            self.execution_time_limit = execution_time_limit;
            self
        }
    }

    generate_set_and_with! {
        /// Fail a lookup that did not complete within this duration,
        /// queue time included (defaults to `None`).
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// Capacity of the worker's job queue.
        pub fn queue_capacity(mut self, queue_capacity: Option<usize>) -> Self {
            self.queue_capacity = queue_capacity;
            self
        }
    }

    generate_set_and_with! {
        /// Tie the worker to a graceful shutdown guard.
        pub fn graceful(mut self, graceful: Option<ShutdownGuard>) -> Self {
            self.graceful = graceful;
            self
        }
    }

    /// Build a resolver serving the script the provider returns for
    /// `script_uri`.
    pub fn build<P>(self, provider: P, script_uri: Uri) -> Result<PacResolver, BoxError>
    where
        P: Service<Uri, Output = PacScript, Error: std::error::Error + Send + Sync + 'static>,
    {
        // blocking dns time counts against the execution limit, so a
        // script doing a couple of lookups can exhaust it during a dns
        // outage and poison its worker on every request
        if let Some(limit) = self.execution_time_limit
            && limit <= self.env.dns_timeout() * 2
        {
            tracing::debug!(
                "pac execution time limit ({limit:?}) leaves little room for dns lookups ({:?} each)",
                self.env.dns_timeout(),
            );
        }

        let runtime = self
            .runtime
            .maybe_with_execution_time_limit(self.execution_time_limit);
        let blueprint = self.env.register(runtime)?;

        Ok(PacResolver {
            provider: rama_core::layer::MapErr::into_opaque_error(provider).boxed(),
            script_uri,
            blueprint,
            worker: WorkerConfig {
                timeout: self.timeout,
                queue_capacity: self.queue_capacity,
                graceful: self.graceful,
            },
            sanitize: self.sanitize,
            state: Mutex::new(None),
        })
    }

    /// Build a resolver serving a fixed script.
    pub fn build_static(self, script: impl Into<PacScript>) -> Result<PacResolver, BoxError> {
        self.build(
            crate::StaticPacScript::new(script),
            Uri::from_static("pac:static"),
        )
    }
}
