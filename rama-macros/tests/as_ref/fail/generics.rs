use rama::service::context::AsRef;

#[derive(Clone, AsRef)]
struct AppState<T> {
    foo: T,
}

fn main() {}
