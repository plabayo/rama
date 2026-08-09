//! Evaluate `FindProxyForURL` for a request uri.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rama_core::error::{BoxError, BoxErrorExt, ErrorContext, ErrorExt, extra::OpaqueError};
use rama_core::graceful::ShutdownGuard;
use rama_core::telemetry::tracing;
use rama_core::{Service, service::BoxService};
use rama_js::{JsErrorKind, JsRuntime, JsRuntimeBuilder, JsWorker};
use rama_net::uri::Uri;
use rama_utils::macros::generate_set_and_with;
use rama_utils::str::arcstr::ArcStr;
use tokio::sync::Mutex;

use crate::env::PacBudgetHandle;
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
    /// re-registered per worker, so each runtime gets its own budget state
    runtime: JsRuntimeBuilder,
    env: PacEnv,
    worker: WorkerConfig,
    sanitize: PacUrlSanitize,
    state: Mutex<ResolverState>,
    /// bumped per worker build, so a caller that waited for the state
    /// lock can tell a fresh worker is already installed
    generation: AtomicUsize,
    /// how long a spawn keeps counting against the budget below
    wedge_cooldown: Duration,
}

/// What the resolver remembers between lookups.
#[derive(Default)]
struct ResolverState {
    script: Option<ScriptState>,
    /// when each recent worker was built, newest last
    ///
    /// A worker wedged in native code leaks its thread, and the resolver
    /// cannot always learn that it did — a cancelled lookup drops the handle
    /// without a word. Counting the builds themselves therefore bounds the
    /// threads a script can cost, whatever becomes of them, and the window
    /// clears on its own so nothing is ever written off for good.
    spawns: Vec<Instant>,
}

impl ResolverState {
    /// Forget builds that have aged out, and report what is left.
    fn recent_spawns(&mut self, window: Duration) -> usize {
        let cutoff = Instant::now().checked_sub(window);
        self.spawns
            .retain(|at| cutoff.is_none_or(|cutoff| *at > cutoff));
        self.spawns.len()
    }
}

/// What happened the last time a script was loaded.
enum ScriptState {
    Loaded(LoadedScript),
    /// This exact script cannot be loaded — it does not parse, throws at
    /// load, or defines no entry point — so re-loading it would spawn a
    /// worker and re-parse it for nothing. Keyed by the script itself, so
    /// a changed script always gets a fresh attempt. A worker that died or
    /// never answered is never remembered here: that is a verdict about a
    /// worker, not about the script's bytes.
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
    generation: usize,
    /// what this worker's runtime may spend, armed per evaluation
    budget: PacBudgetHandle,
}

/// What a lookup needs to call into a loaded worker, held past the state
/// lock so no evaluation runs while it is taken.
struct CallTarget {
    worker: JsWorker,
    entry_point: &'static str,
    budget: PacBudgetHandle,
}

impl CallTarget {
    fn of(loaded: &LoadedScript) -> Self {
        Self {
            worker: loaded.worker.clone(),
            entry_point: loaded.entry_point,
            budget: loaded.budget.clone(),
        }
    }
}

impl ScriptState {
    fn script(&self) -> &PacScript {
        match self {
            Self::Loaded(loaded) => &loaded.script,
            Self::Rejected { script, .. } => script,
        }
    }

    /// Which worker build this state holds, if it holds one at all.
    fn generation(&self) -> Option<usize> {
        match self {
            Self::Loaded(loaded) => Some(loaded.generation),
            Self::Rejected { .. } => None,
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

    /// Load `script`, remembering only a verdict its own bytes earned, so
    /// the next lookup does not build a worker to hear the same one again.
    async fn load(
        &self,
        state: &mut ResolverState,
        script: PacScript,
        replacing_leaked: bool,
    ) -> Result<ScriptState, BoxError> {
        self.check_spawn_budget(state)?;
        // charged before the await, so a lookup cancelled mid-load still pays
        // for the thread it may have left stuck; a clean build refunds below
        state.spawns.push(Instant::now());

        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        match LoadedScript::spawn(
            &self.runtime,
            &self.env,
            &self.worker,
            script.clone(),
            generation,
        )
        .await
        {
            Ok(loaded) => {
                // this build finished, so it left nothing stuck; only the
                // worker it replaced can have, and that one was charged when
                // it was built
                if !replacing_leaked {
                    state.spawns.pop();
                }
                Ok(ScriptState::Loaded(loaded))
            }
            // only the script itself is cached as rejected: an
            // environmental failure (no thread available, ...) must stay
            // retryable, so it propagates without being remembered
            Err(LoadError::Script(error)) => {
                let error = ArcStr::from(error.to_string());
                tracing::debug!("pac script rejected, not retrying until it changes: {error}");
                Ok(ScriptState::Rejected { script, error })
            }
            // a load that failed leaves its charge standing: the worker was
            // built and then lost, so its thread may be stuck
            Err(LoadError::Environment(error)) => Err(error),
        }
    }

    /// Refuse to build another worker while too many recent ones leaked.
    ///
    /// A worker wedged in native code cannot be interrupted, so its thread
    /// lives on: those are what must be bounded. A worker that exits — the
    /// script threw, poisoned its runtime, or discarded its entry point —
    /// costs nothing to replace and is not counted, so ordinary misbehaviour
    /// keeps being served. The window slides, so the resolver always
    /// recovers on its own: a lost worker says nothing about the next
    /// request's host and must never write the script off.
    fn check_spawn_budget(&self, state: &mut ResolverState) -> Result<(), BoxError> {
        let spawns = state.recent_spawns(self.wedge_cooldown);
        if spawns < Self::MAX_WORKER_SPAWNS_PER_WINDOW {
            return Ok(());
        }

        tracing::warn!(
            "pac script cost {spawns} js workers within {:?}, building no more until that clears",
            self.wedge_cooldown,
        );
        Err(spawn_budget_error(spawns))
    }

    /// Evaluate the entry point, arming this evaluation's budgets on the
    /// worker thread first: nothing else stops a script from looping over
    /// `dnsResolve` and turning one request into a burst of queries.
    async fn call_entry_point(
        &self,
        target: &CallTarget,
        url: String,
        host: String,
    ) -> Result<rama_js::JsValue, rama_js::JsError> {
        let budget = target.budget.clone();
        let entry_point = target.entry_point;
        // armed inside the job, so it is this evaluation's budget that this
        // worker's own host functions spend
        target
            .worker
            .run(move |runtime| {
                budget.arm();
                runtime.call(entry_point, [url, host])
            })
            .await
    }

    /// The proxies to try for `uri`, in the order the script named them.
    ///
    /// The script is fetched from the provider, compiled once, and evaluated
    /// per call; it is recompiled only when the provider serves different
    /// bytes. What the script may spend while answering is bounded — see
    /// the [crate docs][crate].
    pub async fn find_proxy(&self, uri: &Uri) -> Result<PacDirectives, BoxError> {
        let script = self
            .provider
            .serve(self.script_uri.clone())
            .await
            .context("obtain pac script")?;

        let (target, script, generation) = {
            let mut state = self.state.lock().await;
            // a byte-identical script keeps its compiled worker, and a
            // byte-identical rejected script is not retried at all
            if state
                .script
                .as_ref()
                .is_none_or(|state| *state.script() != script)
            {
                let loaded = self.load(&mut state, script, false).await?;
                state.script = Some(loaded);
            }
            match state.script.as_ref() {
                Some(ScriptState::Loaded(loaded)) => (
                    CallTarget::of(loaded),
                    loaded.script.clone(),
                    loaded.generation,
                ),
                Some(ScriptState::Rejected { error, .. }) => {
                    return Err(BoxError::from_static_str("pac script was rejected")
                        .context_str_field("reason", error.to_string()));
                }
                None => return Err(BoxError::from_static_str("pac script failed to load")),
            }
        };

        let (url, host) = self.sanitize.apply(uri)?;
        let result = self
            .call_entry_point(&target, url.clone(), host.clone())
            .await;

        let value = match result {
            Ok(value) => value,
            // this lookup's own work wedged the worker: retrying it would
            // only wedge the replacement too, so install one for the next
            // caller and let this request fail
            Err(err) if err.kind() == JsErrorKind::Timeout && target.worker.is_abandoned() => {
                tracing::warn!("pac js worker wedged by this lookup, replacing it: {err}");
                let mut state = self.state.lock().await;
                if state.script.as_ref().and_then(ScriptState::generation) == Some(generation) {
                    state.script = None;
                    match self.load(&mut state, script, true).await {
                        Ok(loaded) => state.script = Some(loaded),
                        Err(err) => tracing::debug!("pac worker not replaced yet: {err}"),
                    }
                }
                return Err(err).context("call pac entry point");
            }
            Err(err) if was_already_unusable(&err) => {
                // the worker is gone or stuck (poisoned by the execution
                // limit, a panicking host fn, or native work no limit can
                // interrupt), or the script deleted its own entry point:
                // either way this runtime cannot serve, so rebuild and retry
                tracing::debug!("pac worker unusable for this lookup, respawning: {err}");
                let leaked = target.worker.is_abandoned();
                let target = {
                    let mut state = self.state.lock().await;
                    // another caller may have installed a fresh worker
                    // while this one waited for the state lock
                    if state.script.as_ref().and_then(ScriptState::generation) == Some(generation) {
                        tracing::warn!("pac js worker lost, building a new one: {err}");
                        // a dead worker is of no use to the next lookup either
                        state.script = None;
                    }
                    if state.script.is_none() {
                        let loaded = self.load(&mut state, script, leaked).await?;
                        state.script = Some(loaded);
                    }
                    match state.script.as_ref() {
                        Some(ScriptState::Loaded(loaded)) => CallTarget::of(loaded),
                        Some(ScriptState::Rejected { error, .. }) => {
                            return Err(BoxError::from_static_str(
                                "pac script was rejected on respawn",
                            )
                            .context_str_field("reason", error.to_string()));
                        }
                        None => {
                            return Err(BoxError::from_static_str("pac script failed to load"));
                        }
                    }
                };
                self.call_entry_point(&target, url, host)
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

/// Says what actually happened: workers were lost, which is no verdict on
/// the script parsing or defining an entry point.
/// Whether the worker was already unusable when this lookup reached it, so
/// a fresh one is worth building and the call worth retrying.
///
/// A wedge caused by this very lookup is handled apart: the same input on a
/// new worker would wedge that one too.
fn was_already_unusable(err: &rama_js::JsError) -> bool {
    matches!(
        err.kind(),
        // gone, or the script overwrote its own entry point — the bytes
        // still define it, so a fresh runtime has it back
        JsErrorKind::Setup | JsErrorKind::NotFound
    )
}

fn spawn_budget_error(spawns: usize) -> BoxError {
    BoxError::from_static_str(
        "pac script lost its js worker repeatedly; cooling down before building another one",
    )
    .context_field("spawns", spawns)
}

/// Distinguishes a script rama will never load from a failure that may
/// well succeed next time.
enum LoadError {
    Script(BoxError),
    Environment(BoxError),
}

impl LoadError {
    /// Only a verdict about the script itself may be remembered: a worker
    /// that timed out or went away says nothing about the script and must
    /// stay retryable — but the attempt still cost a worker.
    fn classify(kind: JsErrorKind, error: BoxError) -> Self {
        match kind {
            JsErrorKind::Setup | JsErrorKind::Timeout => Self::Environment(error),
            _ => Self::Script(error),
        }
    }
}

impl LoadedScript {
    async fn spawn(
        runtime: &JsRuntimeBuilder,
        env: &PacEnv,
        config: &WorkerConfig,
        script: PacScript,
        generation: usize,
    ) -> Result<Self, LoadError> {
        let mut builder = JsWorker::builder()
            .maybe_with_timeout(config.timeout)
            .maybe_with_graceful(config.graceful.clone());
        if let Some(capacity) = config.queue_capacity {
            builder.set_queue_capacity(capacity);
        }
        let (blueprint, budget) = env
            .clone()
            .register_bound(runtime.clone())
            .map_err(LoadError::Environment)?;
        let worker = builder
            .spawn(blueprint)
            .map_err(|err| LoadError::Environment(err.context("spawn pac worker")))?;
        // the script's top level is script code too: without a budget of its
        // own it could spend whatever the entry point is denied
        let source = script.as_str().to_owned();
        let load_budget = budget.clone();
        if let Err(err) = worker
            .run(move |runtime| {
                load_budget.arm();
                runtime.exec(source)
            })
            .await
        {
            let kind = err.kind();
            return Err(LoadError::classify(kind, err.context("execute pac script")));
        }

        // an environment without the ipv6-aware extensions has no `*Ex` half
        // to offer, so it must not pick that entry point either
        let has_ex = env.ipv6_extensions() && Self::probe(&worker, ENTRY_POINT_EX).await?;
        let entry_point = if has_ex {
            ENTRY_POINT_EX
        } else {
            let has_classic = Self::probe(&worker, ENTRY_POINT).await?;
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
            generation,
            budget,
        })
    }

    /// Whether the loaded script defines the global function `name`.
    async fn probe(worker: &JsWorker, name: &'static str) -> Result<bool, LoadError> {
        worker
            .run(move |runtime| Ok(runtime.has_global_fn(name)))
            .await
            .map_err(|err| {
                let kind = err.kind();
                LoadError::classify(kind, err.context("probe pac entry point"))
            })
    }
}

impl PacUrlSanitize {
    /// The `(url, host)` pair to hand the script.
    fn apply(self, uri: &Uri) -> Result<(String, String), BoxError> {
        // browsers ascii-lowercase the scheme and host before calling the
        // script, and `shExpMatch` is case-sensitive by spec: without this
        // a shouted host misses every rule written in lowercase
        let host = fold_ascii_case(&uri.host_str().context("request uri has no host")?);

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

        Ok((fold_url_scheme_and_host(&url), host))
    }
}

/// The url as the script sees it: scheme and host ascii-lowercased, every
/// other byte exactly as it arrived — an operator rule written against a
/// pct-escape, a dot segment or a trailing dot has to keep matching.
fn fold_url_scheme_and_host(uri: &Uri) -> String {
    let url = uri.to_string();
    // the rendered form starts with "scheme:", then "//host[:port]" when
    // there is an authority
    let scheme_end = uri.scheme_str().map_or(0, |scheme| scheme.len() + 1);
    let (scheme, rest) = match (url.get(..scheme_end), url.get(scheme_end..)) {
        (Some(scheme), Some(rest)) => (scheme, rest),
        _ => ("", url.as_str()),
    };

    let mut folded = fold_ascii_case(scheme);
    match rest.strip_prefix("//") {
        Some(authority) => {
            let host_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
            let (host, tail) = authority.split_at(host_end);
            folded.push_str("//");
            folded.push_str(&fold_ascii_case(host));
            folded.push_str(tail);
        }
        None => folded.push_str(rest),
    }
    folded
}

/// ASCII-lowercase `s`, leaving pct-escapes alone: their hex digits are not
/// case-insensitive the way a scheme or a host label is.
fn fold_ascii_case(s: &str) -> String {
    let mut folded = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        folded.push(c.to_ascii_lowercase());
        if c == '%' {
            folded.extend(chars.by_ref().take(2));
        }
    }
    folded
}

/// Builds a [`PacResolver`].
pub struct PacResolverBuilder {
    env: PacEnv,
    runtime: JsRuntimeBuilder,
    sanitize: PacUrlSanitize,
    execution_time_limit: Option<Duration>,
    timeout: Option<Duration>,
    wedge_cooldown: Duration,
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
            wedge_cooldown: PacResolver::DEFAULT_WEDGE_COOLDOWN,
            queue_capacity: None,
            graceful: None,
        }
    }
}

impl PacResolver {
    /// Wall-clock limit one `FindProxyForURL` call gets by default.
    pub const DEFAULT_EXECUTION_TIME_LIMIT: Duration = Duration::from_secs(10);

    /// How many js workers one script may cost within a
    /// [cooldown window][PacResolverBuilder::set_wedge_cooldown] before the
    /// resolver stops building them.
    ///
    /// A script can wedge its worker in native code no javascript limit can
    /// interrupt, which leaks that worker's thread. Bounding the builds
    /// bounds the threads: builds age out of the window on their own, so a
    /// script is never written off, and nothing a script does — answering
    /// some requests normally, or having its lookups cancelled — buys it
    /// more.
    pub const MAX_WORKER_SPAWNS_PER_WINDOW: usize = 3;

    /// How long a worker build keeps counting against
    /// [`MAX_WORKER_SPAWNS_PER_WINDOW`][Self::MAX_WORKER_SPAWNS_PER_WINDOW]
    /// by default.
    pub const DEFAULT_WEDGE_COOLDOWN: Duration = Duration::from_secs(30);

    /// The lookup timeout derived from `limit` when none was configured:
    /// strictly greater than the execution time limit, so a bounded
    /// runaway is still reported as such, with room for queue time.
    #[must_use]
    pub const fn default_timeout_for(limit: Duration) -> Duration {
        limit.saturating_mul(2)
    }
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
        /// worker on the next lookup.
        /// `None` removes the limit — and with it the derived lookup
        /// [timeout][Self::set_timeout] — at the risk of a script wedging
        /// its worker forever.
        pub fn execution_time_limit(mut self, execution_time_limit: Option<Duration>) -> Self {
            self.execution_time_limit = execution_time_limit;
            self
        }
    }

    generate_set_and_with! {
        /// Fail a lookup that did not complete within this duration,
        /// queue time included.
        ///
        /// `None` derives it from the
        /// [execution time limit][Self::set_execution_time_limit] — see
        /// [`PacResolver::default_timeout_for`] — because a script can
        /// wedge its worker in native code that limit cannot interrupt,
        /// and no caller may wait on that forever. Callers only wait
        /// indefinitely when the execution time limit is removed too.
        pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
            self.timeout = timeout;
            self
        }
    }

    generate_set_and_with! {
        /// How long a worker build keeps counting against
        /// [`PacResolver::MAX_WORKER_SPAWNS_PER_WINDOW`]
        /// (defaults to [`PacResolver::DEFAULT_WEDGE_COOLDOWN`]).
        ///
        /// Lookups fail once the window is full, so keep it long enough that
        /// a wedging script cannot leak a thread per lookup and short enough
        /// that a fixed script is picked up promptly.
        pub fn wedge_cooldown(mut self, wedge_cooldown: Duration) -> Self {
            self.wedge_cooldown = wedge_cooldown;
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

        // a wedged worker never answers, so a lookup gets a deadline of
        // its own unless the operator asked for none at all
        let timeout = self.timeout.or_else(|| {
            self.execution_time_limit
                .map(PacResolver::default_timeout_for)
        });

        let runtime = self
            .runtime
            .maybe_with_execution_time_limit(self.execution_time_limit);
        // the env is kept rather than pre-registered: registering per worker
        // build is what gives each runtime its own budget state
        let env = self.env;

        Ok(PacResolver {
            provider: rama_core::layer::MapErr::into_opaque_error(provider).boxed(),
            script_uri,
            runtime,
            env,
            worker: WorkerConfig {
                timeout,
                queue_capacity: self.queue_capacity,
                graceful: self.graceful,
            },
            sanitize: self.sanitize,
            state: Mutex::new(ResolverState::default()),
            generation: AtomicUsize::new(0),
            wedge_cooldown: self.wedge_cooldown,
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
