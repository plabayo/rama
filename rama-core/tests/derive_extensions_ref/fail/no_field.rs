use rama_core::extensions::ExtensionsRef;

#[derive(ExtensionsRef)]
struct Ambiguous<A, B> {
    a: A,
    b: B,
}

#[derive(ExtensionsRef)]
struct Pair<A, B>(A, B);

#[derive(ExtensionsRef)]
struct Unit;

fn main() {}
