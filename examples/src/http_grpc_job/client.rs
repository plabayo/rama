//! Explore the HTTP and gRPC job APIs from one small command-line client.
//!
//! Start `http_grpc_job_server`, then run the complete demo:
//!
//! ```sh
//! cargo run -p rama-examples --bin http_grpc_job_client --features=grpc,http-full
//! ```
//!
//! Use `--help` to discover the individual HTTP and gRPC commands.

#![expect(
    clippy::print_stdout,
    reason = "example: print-for-output is the standard pattern for demos"
)]

use std::io;

use clap::{Parser, Subcommand};
use rama::{
    error::BoxError,
    http::{
        BodyExtractExt as _, StatusCode,
        client::EasyHttpWebClient,
        grpc::{
            Request,
            service::health::pb::{
                HealthCheckRequest, health_check_response, health_client::HealthClient,
            },
        },
        service::client::HttpClientExt as _,
    },
    net::uri::Uri,
};

use rama_examples::http_grpc_job::{
    common::{ErrorResponse, HealthResponse, JobResponse, default_origin, health_uri, job_uri},
    jobs::{
        GetJobRequest, Job, JobState, SubmitJobRequest, WatchJobRequest,
        job_service_client::JobServiceClient, job_service_server,
    },
};

const DEFAULT_TASK: &str = "rebuild the product search index";

#[derive(Debug, Parser)]
#[command(about = "Call the example job service over HTTP and gRPC")]
struct Args {
    /// Base URI of the job service.
    #[arg(long, global = true, value_name = "URI")]
    origin: Option<Uri>,

    /// Run the full demo when no command is supplied.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check both protocols, submit and watch a job, then read it over HTTP.
    Demo {
        /// Work for the example job to perform.
        #[arg(long, default_value = DEFAULT_TASK)]
        task: String,
    },

    /// Call an ordinary JSON-over-HTTP endpoint.
    Http {
        #[command(subcommand)]
        command: HttpCommand,
    },

    /// Call a generated gRPC endpoint.
    Grpc {
        #[command(subcommand)]
        command: GrpcCommand,
    },
}

#[derive(Debug, Subcommand)]
enum HttpCommand {
    /// Check the HTTP health endpoint.
    Health,

    /// Fetch a job by id.
    Get { id: u64 },
}

#[derive(Debug, Subcommand)]
enum GrpcCommand {
    /// Check the standard gRPC health service.
    Health,

    /// Submit a new job.
    Submit { task: String },

    /// Fetch a job by id.
    Get { id: u64 },

    /// Stream the current and future states of a job until it succeeds.
    Watch { id: u64 },
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let origin = args.origin.unwrap_or_else(default_origin);
    let command = args.command.unwrap_or_else(|| Command::Demo {
        task: DEFAULT_TASK.to_owned(),
    });

    match command {
        Command::Demo { task } => demo(&origin, task).await?,
        Command::Http { command } => match command {
            HttpCommand::Health => print_http_health(&http_health(&origin).await?),
            HttpCommand::Get { id } => print_http_job(&http_get_job(&origin, id).await?),
        },
        Command::Grpc { command } => match command {
            GrpcCommand::Health => print_grpc_health(grpc_health(&origin).await?),
            GrpcCommand::Submit { task } => {
                print_submitted_job(&grpc_submit_job(&origin, task).await?)
            }
            GrpcCommand::Get { id } => print_grpc_job(&grpc_get_job(&origin, id).await?),
            GrpcCommand::Watch { id } => grpc_watch_job(&origin, id).await?,
        },
    }

    Ok(())
}

async fn demo(origin: &Uri, task: String) -> Result<(), BoxError> {
    print_http_health(&http_health(origin).await?);
    print_grpc_health(grpc_health(origin).await?);

    let job = grpc_submit_job(origin, task).await?;
    let id = job.id;
    print_submitted_job(&job);
    grpc_watch_job(origin, id).await?;
    print_http_job(&http_get_job(origin, id).await?);

    Ok(())
}

async fn http_health(origin: &Uri) -> Result<HealthResponse, BoxError> {
    let response = EasyHttpWebClient::default()
        .get(health_uri(origin))
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        return Err(http_error(response.status(), "health request failed"));
    }
    response.try_into_json().await
}

async fn http_get_job(origin: &Uri, id: u64) -> Result<JobResponse, BoxError> {
    let response = EasyHttpWebClient::default()
        .get(job_uri(origin, id))
        .send()
        .await?;
    let status = response.status();
    if status == StatusCode::OK {
        return response.try_into_json().await;
    }

    let error = response.try_into_json::<ErrorResponse>().await?;
    Err(http_error(status, error.error))
}

async fn grpc_health(origin: &Uri) -> Result<health_check_response::ServingStatus, BoxError> {
    let health = HealthClient::new(EasyHttpWebClient::default(), origin.clone());
    let response = health
        .check(Request::new(HealthCheckRequest {
            service: job_service_server::SERVICE_NAME.to_owned(),
        }))
        .await?
        .into_inner();
    Ok(health_check_response::ServingStatus::try_from(
        response.status,
    )?)
}

async fn grpc_submit_job(origin: &Uri, task: String) -> Result<Job, BoxError> {
    let jobs = JobServiceClient::new(EasyHttpWebClient::default(), origin.clone());
    Ok(jobs
        .submit_job(Request::new(SubmitJobRequest { task }))
        .await?
        .into_inner())
}

async fn grpc_get_job(origin: &Uri, id: u64) -> Result<Job, BoxError> {
    let jobs = JobServiceClient::new(EasyHttpWebClient::default(), origin.clone());
    Ok(jobs
        .get_job(Request::new(GetJobRequest { id }))
        .await?
        .into_inner())
}

async fn grpc_watch_job(origin: &Uri, id: u64) -> Result<(), BoxError> {
    let jobs = JobServiceClient::new(EasyHttpWebClient::default(), origin.clone());
    let mut events = jobs
        .watch_job(Request::new(WatchJobRequest { id }))
        .await?
        .into_inner();

    while let Some(event) = events.message().await? {
        if let Some(job) = event.job {
            let state = JobState::try_from(job.state).unwrap_or(JobState::Unspecified);
            println!(
                "gRPC job {}: {:>3}% {:<24} {}",
                job.id,
                job.progress_percent,
                state.as_str_name(),
                event.message,
            );
        }
    }

    Ok(())
}

fn print_http_health(response: &HealthResponse) {
    println!("HTTP health: {}", response.status);
}

fn print_grpc_health(status: health_check_response::ServingStatus) {
    println!("gRPC health: {}", status.as_str_name());
}

fn print_submitted_job(job: &Job) {
    println!("gRPC submitted job {}: {:?}", job.id, job.task);
}

fn print_grpc_job(job: &Job) {
    let state = JobState::try_from(job.state).unwrap_or(JobState::Unspecified);
    println!(
        "gRPC job {}: {}% {} {:?}",
        job.id,
        job.progress_percent,
        state.as_str_name(),
        job.task,
    );
}

fn print_http_job(job: &JobResponse) {
    println!(
        "HTTP job {}: {}% {} {:?}",
        job.id,
        job.progress_percent,
        job.state.as_str(),
        job.task,
    );
}

fn http_error(status: StatusCode, message: impl Into<String>) -> BoxError {
    io::Error::other(format!("HTTP {status}: {}", message.into())).into()
}
