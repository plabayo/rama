#![deny(warnings)]

use std::{marker::PhantomData, sync::Arc};

use rama_core::extensions::{Extensions, ExtensionsRef};

struct Conn(Extensions);

impl ExtensionsRef for Conn {
    fn extensions(&self) -> &Extensions {
        &self.0
    }
}

// Private field type behind a public wrapper must not trip `private_bounds`.
struct Hidden<T>(T);

impl<T: ExtensionsRef> ExtensionsRef for Hidden<T> {
    fn extensions(&self) -> &Extensions {
        self.0.extensions()
    }
}

#[derive(ExtensionsRef)]
pub struct Composite<T> {
    inner: Hidden<T>,
}

#[derive(ExtensionsRef)]
struct Shared<S, F> {
    inner: Arc<S>,
    _f: PhantomData<F>,
}

#[derive(ExtensionsRef)]
struct Borrowed<'a, S: ?Sized, const N: usize>
where
    S: Send,
{
    inner: &'a S,
}

#[derive(ExtensionsRef)]
struct Boxed {
    inner: Box<dyn ExtensionsRef>,
}

fn store<T: ExtensionsRef>(value: &T) -> &Extensions {
    value.extensions()
}

fn main() {
    let composite = Composite {
        inner: Hidden(Conn(Extensions::new())),
    };
    assert!(core::ptr::eq(store(&composite), &raw const composite.inner.0.0));

    // `F` has no bound: a type that is not `ExtensionsRef` is fine.
    let shared: Shared<Conn, std::cell::Cell<u8>> = Shared {
        inner: Arc::new(Conn(Extensions::new())),
        _f: PhantomData,
    };
    assert!(core::ptr::eq(store(&shared), &raw const shared.inner.0));

    let conn = Conn(Extensions::new());
    let borrowed: Borrowed<'_, Conn, 3> = Borrowed { inner: &conn };
    assert!(core::ptr::eq(store(&borrowed), &raw const conn.0));

    let boxed = Boxed {
        inner: Box::new(Conn(Extensions::new())),
    };
    let expected: *const Extensions = boxed.inner.extensions();
    assert!(core::ptr::eq(store(&boxed), expected));
}
