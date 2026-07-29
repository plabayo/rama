use std::fmt;

use crate::error::{JsError, JsErrorKind};
use crate::runtime::{JsRuntime, JsRuntimeBuilder};
use crate::value::JsValue;

type Job = Box<dyn FnOnce(&mut JsRuntime) + Send>;

/// Bounded so a stalled worker exerts backpressure on its
/// callers instead of accumulating queued jobs without limit.
const JOB_QUEUE_CAPACITY: usize = 128;

/// A [`JsRuntime`] owned by a dedicated OS thread: the
/// compile-once, call-many execution model.
///
/// State (globals, function definitions, ...) persists for the lifetime
/// of the worker: execute a script once, then [`call`][Self::call] into
/// its functions per request. This is the model browsers and proxies use
/// for long-lived configuration scripts, in contrast to the
/// fresh-runtime-per-run isolation of a [`JsEngine`][crate::JsEngine].
///
/// The handle is cheap to clone; all handles share the same runtime and
/// jobs run strictly in order. The thread exits once the last handle is
/// dropped. A caller which stops waiting (e.g. behind a timeout) does not
/// interrupt the job itself: it still runs to completion on the worker,
/// bounded by the runtime's [limits][JsRuntimeBuilder].
#[derive(Clone)]
pub struct JsWorker {
    jobs: flume::Sender<Job>,
}

impl fmt::Debug for JsWorker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsWorker").finish_non_exhaustive()
    }
}

impl JsWorker {
    /// Spawn a worker thread owning a fresh [`JsRuntime`]
    /// built from the given builder.
    pub fn spawn(builder: JsRuntimeBuilder) -> Result<Self, JsError> {
        let (jobs, inbox) = flume::bounded::<Job>(JOB_QUEUE_CAPACITY);
        let (ready, built) = flume::bounded(1);

        std::thread::Builder::new()
            .name("rama-js-worker".to_owned())
            .spawn(move || {
                let mut runtime = match builder.build() {
                    Ok(runtime) => {
                        let _sent = ready.send(Ok(()));
                        runtime
                    }
                    Err(err) => {
                        let _sent = ready.send(Err(err));
                        return;
                    }
                };
                while let Ok(job) = inbox.recv() {
                    job(&mut runtime);
                }
            })
            .map_err(|err| {
                JsError::new(
                    JsErrorKind::Setup,
                    format!("failed to spawn js worker thread: {err}"),
                )
            })?;

        built.recv().map_err(|_e| worker_gone())??;
        Ok(Self { jobs })
    }

    /// Execute the given closure with exclusive access
    /// to the worker's runtime.
    pub async fn run<T, F>(&self, f: F) -> Result<T, JsError>
    where
        F: FnOnce(&mut JsRuntime) -> Result<T, JsError> + Send + 'static,
        T: Send + 'static,
    {
        let (reply, output) = tokio::sync::oneshot::channel();
        self.jobs
            .send_async(Box::new(move |runtime| {
                let _sent = reply.send(f(runtime));
            }))
            .await
            .map_err(|_e| worker_gone())?;
        output.await.map_err(|_e| worker_gone())?
    }

    /// Evaluate a script on the worker's runtime,
    /// returning the value of its final expression.
    pub async fn eval<S>(&self, src: S) -> Result<JsValue, JsError>
    where
        S: AsRef<str> + Send + 'static,
    {
        self.run(move |runtime| runtime.eval(src)).await
    }

    /// Execute a script on the worker's runtime,
    /// discarding its final expression value.
    pub async fn exec<S>(&self, src: S) -> Result<(), JsError>
    where
        S: AsRef<str> + Send + 'static,
    {
        self.run(move |runtime| runtime.exec(src)).await
    }

    /// Call a global function (defined by a previously executed
    /// script, or registered as a host function) with the given arguments.
    pub async fn call<N, I, V>(&self, name: N, args: I) -> Result<JsValue, JsError>
    where
        N: AsRef<str> + Send + 'static,
        I: IntoIterator<Item = V>,
        V: Into<JsValue>,
    {
        let args: Vec<JsValue> = args.into_iter().map(Into::into).collect();
        self.run(move |runtime| runtime.call(name, args)).await
    }
}

fn worker_gone() -> JsError {
    JsError::new(JsErrorKind::Setup, "js worker is gone")
}
