//! Serve ordinary HTTP endpoints and generated gRPC services on one Rama web router.
//!
//! This models a common internal service: machines submit and watch background jobs over
//! gRPC, while operators and infrastructure use a small HTTP surface backed by the same
//! application state. Native gRPC uses HTTP/2; the HTTP endpoints remain available over
//! HTTP/1.1 or HTTP/2 on the same listener.
//!
//! # Run the example
//!
//! ```sh
//! cargo run -p rama-examples --bin http_grpc_job_server --features=grpc,http-full
//! ```
//!
//! In another terminal, run the complete HTTP and gRPC client demo, or use one of its
//! subcommands:
//!
//! ```sh
//! cargo run -p rama-examples --bin http_grpc_job_client --features=grpc,http-full
//! cargo run -p rama-examples --bin http_grpc_job_client --features=grpc,http-full -- http health
//! cargo run -p rama-examples --bin http_grpc_job_client --features=grpc,http-full -- grpc health
//! ```

use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use ahash::HashMap;
use rama::{
    Layer as _,
    error::BoxError,
    futures::{Stream, stream},
    http::{
        StatusCode,
        grpc::{
            Request as GrpcRequest, Response as GrpcResponse, Status,
            service::{LayerExt as _, health::server::health_reporter, web::RouterExt as _},
        },
        layer::{error_handling::ErrorHandlerLayer, trace::TraceLayer},
        protocols::html::{a, body, h1, head, html, li, p, title, ul},
        server::HttpServer,
        service::web::{
            Router,
            extract::{Path, State},
            response::{IntoResponse, Json},
        },
    },
    net::address::SocketAddress,
    rt::Executor,
    telemetry::tracing::{
        self,
        level_filters::LevelFilter,
        subscriber::{EnvFilter, fmt, layer::SubscriberExt as _, util::SubscriberInitExt as _},
    },
};
use serde::Deserialize;
use tokio::sync::{RwLock, watch};

use rama_examples::http_grpc_job::{
    common::{
        EXAMPLE_JOB_PATH, ErrorResponse, HEALTH_PATH, HealthResponse, HealthStatus, INDEX_PATH,
        JOB_PATH, JobResponse,
    },
    jobs::{
        GetJobRequest, Job, JobEvent, JobState, SubmitJobRequest, WatchJobRequest,
        job_service_server::{JobService, JobServiceServer},
    },
};

const ADDR: SocketAddress = SocketAddress::local_ipv4(62073);

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing::subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let jobs = JobStore::default();
    let job_service = JobServiceServer::new(JobApi { jobs: jobs.clone() });

    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<JobServiceServer<JobApi>>()
        .await;

    // gRPC errors are reported through `grpc-status`, often alongside HTTP 200. Trace each
    // gRPC branch with the gRPC classifier instead of wrapping the complete mixed router in
    // an HTTP status classifier. `named_layer` preserves `NamedService` for route discovery.
    let grpc_trace = TraceLayer::new_for_grpc();
    let job_service = grpc_trace.named_layer(job_service);
    let health_service = grpc_trace.named_layer(health_service);

    let router = Router::new_with_state(jobs)
        .with_get(INDEX_PATH, index)
        .with_get(HEALTH_PATH, healthz)
        .with_get(JOB_PATH, get_job_http)
        // Each service is moved directly into the route derived from its protobuf service name.
        .with_grpc_service(job_service)
        .with_grpc_service(health_service);

    tracing::info!(
        network.local.address = %ADDR.ip_addr,
        network.local.port = %ADDR.port,
        "HTTP and gRPC job service listening",
    );

    HttpServer::auto(Executor::default())
        .listen(ADDR, Arc::new(ErrorHandlerLayer::new().into_layer(router)))
        .await?;

    Ok(())
}

#[derive(Debug, Clone)]
struct JobStore {
    inner: Arc<JobStoreInner>,
}

#[derive(Debug)]
struct JobStoreInner {
    next_id: AtomicU64,
    jobs: RwLock<HashMap<u64, watch::Sender<Job>>>,
}

impl Default for JobStore {
    fn default() -> Self {
        Self {
            inner: Arc::new(JobStoreInner {
                next_id: AtomicU64::new(1),
                jobs: RwLock::new(HashMap::default()),
            }),
        }
    }
}

impl JobStore {
    async fn submit(&self, task: String) -> Job {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let job = Job {
            id,
            task,
            state: JobState::Queued as i32,
            progress_percent: 0,
        };
        let (updates, _initial_receiver) = watch::channel(job.clone());
        self.inner.jobs.write().await.insert(id, updates.clone());

        tokio::spawn(simulate_job(updates));
        job
    }

    async fn get(&self, id: u64) -> Option<Job> {
        self.inner
            .jobs
            .read()
            .await
            .get(&id)
            .map(|updates| updates.borrow().clone())
    }

    async fn subscribe(&self, id: u64) -> Option<watch::Receiver<Job>> {
        self.inner
            .jobs
            .read()
            .await
            .get(&id)
            .map(watch::Sender::subscribe)
    }
}

async fn simulate_job(updates: watch::Sender<Job>) {
    for (progress_percent, state) in [
        (10, JobState::Running),
        (35, JobState::Running),
        (70, JobState::Running),
        (100, JobState::Succeeded),
    ] {
        tokio::time::sleep(Duration::from_millis(350)).await;
        let mut job = updates.borrow().clone();
        job.progress_percent = progress_percent;
        job.state = state as i32;
        updates.send_replace(job);
    }
}

#[derive(Debug, Clone)]
struct JobApi {
    jobs: JobStore,
}

impl JobService for JobApi {
    type WatchJobStream =
        Pin<Box<dyn Stream<Item = Result<JobEvent, Status>> + Send + Sync + 'static>>;

    async fn submit_job(
        &self,
        request: GrpcRequest<SubmitJobRequest>,
    ) -> Result<GrpcResponse<Job>, Status> {
        let task = request.into_inner().task;
        if task.trim().is_empty() {
            return Err(Status::invalid_argument("task must not be empty"));
        }

        let job = self.jobs.submit(task).await;
        tracing::info!(job.id, job.task, "job submitted");
        Ok(GrpcResponse::new(job))
    }

    async fn get_job(
        &self,
        request: GrpcRequest<GetJobRequest>,
    ) -> Result<GrpcResponse<Job>, Status> {
        let id = request.into_inner().id;
        self.jobs
            .get(id)
            .await
            .map(GrpcResponse::new)
            .ok_or_else(|| Status::not_found(format!("job {id} was not found")))
    }

    async fn watch_job(
        &self,
        request: GrpcRequest<WatchJobRequest>,
    ) -> Result<GrpcResponse<Self::WatchJobStream>, Status> {
        let id = request.into_inner().id;
        let updates = self
            .jobs
            .subscribe(id)
            .await
            .ok_or_else(|| Status::not_found(format!("job {id} was not found")))?;

        let events = stream::unfold(Some((updates, true)), |state| async move {
            let (mut updates, first) = state?;
            if !first && updates.changed().await.is_err() {
                return None;
            }

            let job = updates.borrow_and_update().clone();
            let completed = job.state == JobState::Succeeded as i32;
            let event = Ok(JobEvent {
                message: job_event_message(&job),
                job: Some(job),
            });
            let next = (!completed).then_some((updates, false));
            Some((event, next))
        });

        Ok(GrpcResponse::new(Box::pin(events)))
    }
}

fn job_event_message(job: &Job) -> String {
    match JobState::try_from(job.state).unwrap_or(JobState::Unspecified) {
        JobState::Unspecified => "job state is unknown".to_owned(),
        JobState::Queued => "job queued".to_owned(),
        JobState::Running => format!("job is {}% complete", job.progress_percent),
        JobState::Succeeded => "job completed".to_owned(),
    }
}

async fn index() -> impl IntoResponse {
    html!(
        head!(title!("Rama HTTP + gRPC job service")),
        body!(
            h1!("Rama HTTP + gRPC job service"),
            p!("Machines submit and watch jobs over gRPC; operators use HTTP on the same port."),
            ul!(
                li!(a!(href = HEALTH_PATH, "GET ", HEALTH_PATH)),
                li!(a!(href = EXAMPLE_JOB_PATH, "GET ", EXAMPLE_JOB_PATH)),
                li!("gRPC rama.examples.jobs.v1.JobService"),
                li!("gRPC grpc.health.v1.Health"),
            ),
        ),
    )
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: HealthStatus::Ok,
    })
}

#[derive(Debug, Deserialize)]
struct JobPath {
    id: u64,
}

async fn get_job_http(
    State(jobs): State<JobStore>,
    Path(path): Path<JobPath>,
) -> impl IntoResponse {
    match jobs.get(path.id).await {
        Some(job) => Json(JobResponse::from(job)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("job {} was not found", path.id),
            }),
        )
            .into_response(),
    }
}
