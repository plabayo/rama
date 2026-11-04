use rama_core::extensions::ExtensionsRef;

#[derive(ExtensionsRef)]
enum E<S> {
    A(S),
}

#[derive(ExtensionsRef)]
union U {
    a: u8,
}

fn main() {}
