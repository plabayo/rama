use rama::service::context::AsRef;
use std::sync::{atomic::AtomicUsize, Arc};

#[derive(Debug)]
struct AppMetrics {
    connections: AtomicUsize,
}

#[derive(Debug)]
struct ConnMetrics {
    requests: AtomicUsize,
}

#[derive(AsRef)]
struct AppState {
    app_metrics: Arc<AppMetrics>,
    #[as_ref(skip)]
    also_string: String,
}

#[derive(AsRef)]
struct ConnState {
    #[as_ref(wrap)]
    app: Arc<AppState>,
    conn_metrics: Arc<ConnMetrics>,
}

fn main() {}
