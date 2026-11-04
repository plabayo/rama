use rama_core::extensions::ExtensionsRef;

#[derive(ExtensionsRef)]
struct Posted<S> {
    #[cfg(windows)]
    inner: std::mem::ManuallyDrop<S>,
    #[cfg(not(windows))]
    inner: S,
}

fn main() {}
