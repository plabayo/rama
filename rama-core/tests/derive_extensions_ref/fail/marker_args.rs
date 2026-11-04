use rama_core::extensions::ExtensionsRef;

#[derive(ExtensionsRef)]
struct Svc<S> {
    #[extensions_ref(skip)]
    inner: S,
}

fn main() {}
