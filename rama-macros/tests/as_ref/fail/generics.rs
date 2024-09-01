use rama::Context::AsRef;

#[derive(Clone, AsRef)]
struct AppState<T> {
    foo: T,
}

fn main() {}
