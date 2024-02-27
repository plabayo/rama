use rama_macros::AsRef;

#[derive(Clone, AsRef)]
struct AppState {
    auth_token: String,
    #[as_ref(skip)]
    also_string: String,
}

fn main() {}
