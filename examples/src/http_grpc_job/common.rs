//! HTTP contracts, routes, and URI construction shared by the client and server.

use rama::net::uri::Uri;
use serde::{Deserialize, Serialize};

use super::jobs::{Job, JobState};

pub const INDEX_PATH: &str = "/";
pub const HEALTH_PATH: &str = "/healthz";
pub const JOBS_PATH: &str = "/jobs";
pub const JOB_PATH: &str = "/jobs/{id}";
pub const EXAMPLE_JOB_PATH: &str = "/jobs/1";

pub fn default_origin() -> Uri {
    Uri::from_static("http://127.0.0.1:62073")
}

pub fn health_uri(origin: &Uri) -> Uri {
    origin.clone().with_path(HEALTH_PATH)
}

pub fn job_uri(origin: &Uri, id: u64) -> Uri {
    origin
        .clone()
        .with_path(JOBS_PATH)
        .with_additional_path_segment(id)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Ok,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => f.write_str("ok"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: HealthStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobStateResponse {
    #[serde(rename = "JOB_STATE_UNSPECIFIED")]
    Unspecified,
    #[serde(rename = "JOB_STATE_QUEUED")]
    Queued,
    #[serde(rename = "JOB_STATE_RUNNING")]
    Running,
    #[serde(rename = "JOB_STATE_SUCCEEDED")]
    Succeeded,
}

impl JobStateResponse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unspecified => "JOB_STATE_UNSPECIFIED",
            Self::Queued => "JOB_STATE_QUEUED",
            Self::Running => "JOB_STATE_RUNNING",
            Self::Succeeded => "JOB_STATE_SUCCEEDED",
        }
    }
}

impl From<JobState> for JobStateResponse {
    fn from(state: JobState) -> Self {
        match state {
            JobState::Unspecified => Self::Unspecified,
            JobState::Queued => Self::Queued,
            JobState::Running => Self::Running,
            JobState::Succeeded => Self::Succeeded,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobResponse {
    pub id: u64,
    pub task: String,
    pub state: JobStateResponse,
    pub progress_percent: u32,
}

impl From<Job> for JobResponse {
    fn from(job: Job) -> Self {
        Self {
            id: job.id,
            task: job.task,
            state: JobState::try_from(job.state)
                .unwrap_or(JobState::Unspecified)
                .into(),
            progress_percent: job.progress_percent,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn builds_endpoint_uris_by_mutating_a_typed_origin() {
        let origin = Uri::from_static("http://example.test:8080/base");

        assert_eq!(
            health_uri(&origin).to_string(),
            "http://example.test:8080/healthz"
        );
        assert_eq!(
            job_uri(&origin, 42).to_string(),
            "http://example.test:8080/jobs/42"
        );
    }

    #[test]
    fn serializes_the_typed_http_job_contract() {
        let response = JobResponse::from(Job {
            id: 7,
            task: "index products".to_owned(),
            state: JobState::Succeeded as i32,
            progress_percent: 100,
        });

        assert_eq!(
            serde_json::to_value(response).expect("serialize job response"),
            json!({
                "id": 7,
                "task": "index products",
                "state": "JOB_STATE_SUCCEEDED",
                "progress_percent": 100,
            })
        );
    }
}
