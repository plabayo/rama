use rama_core::extensions::ExtensionsRef;

#[derive(ExtensionsRef)]
struct Posted<S> {
    #[cfg(any())]
    inner: std::mem::ManuallyDrop<S>,
    #[cfg(all())]
    inner: S,
}

fn main() {}
