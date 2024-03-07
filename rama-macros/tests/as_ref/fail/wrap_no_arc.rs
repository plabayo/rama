use rama_macros::AsRef;

#[derive(AsRef)]
struct AppState {
    auth_token: String,
    #[as_ref(skip)]
    also_string: String,
}

#[derive(AsRef)]
struct ConnState {
    #[as_ref(wrap)]
    app: AppState,
    count: u32,
}

fn main() {}
