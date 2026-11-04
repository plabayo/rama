use rama_core::extensions::ExtensionsRef;

struct NotExtensions;

#[derive(ExtensionsRef)]
struct Svc<S> {
    inner: S,
}

fn store<T: ExtensionsRef>(_: &T) {}

fn main() {
    store(&Svc {
        inner: NotExtensions,
    });
}
