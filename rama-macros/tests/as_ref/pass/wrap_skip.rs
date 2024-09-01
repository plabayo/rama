use rama::context::AsRef;
use std::sync::Arc;

#[derive(AsRef)]
struct AppState {
    auth_token: String,
    #[as_ref(skip)]
    also_string: String,
}

#[derive(AsRef)]
struct ConnState {
    #[as_ref(skip, wrap)]
    app: Arc<AppState>,
    auth_token: String,
}

fn main() {}
