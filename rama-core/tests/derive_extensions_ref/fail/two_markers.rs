use rama_core::extensions::ExtensionsRef;

#[derive(ExtensionsRef)]
struct Svc<A, B> {
    #[extensions_ref]
    a: A,
    #[extensions_ref]
    b: B,
}

fn main() {}
