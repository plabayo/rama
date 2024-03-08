use rama_macros::AsRef;
use std::sync::Arc;

#[derive(AsRef)]
struct AppState {
    auth_token: String,
    #[as_ref(skip)]
    also_string: String,
}

#[derive(AsRef)]
struct ConnState {
    #[as_ref(wrap)]
    app: Arc<AppState>,
    exposed_u32: u32,
}

fn main() {}
