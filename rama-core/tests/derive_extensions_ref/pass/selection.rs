#![deny(warnings)]

use rama_core::extensions::{Extensions, ExtensionsRef};

struct Conn(Extensions);

impl ExtensionsRef for Conn {
    fn extensions(&self) -> &Extensions {
        &self.0
    }
}

struct NotExtensions;

#[derive(ExtensionsRef)]
struct Marked<S> {
    #[extensions_ref]
    conn: S,
    inner: Conn,
}

#[derive(ExtensionsRef)]
struct Inner<S, W> {
    _writer: W,
    inner: S,
}

#[derive(ExtensionsRef)]
struct Store<B> {
    _body: B,
    extensions: Extensions,
}

#[derive(ExtensionsRef)]
struct TupleStore<B>(B, Extensions);

#[derive(ExtensionsRef)]
struct Single<S> {
    conn: S,
}

#[derive(ExtensionsRef)]
struct Newtype<S>(S);

fn store<T: ExtensionsRef>(value: &T) -> &Extensions {
    value.extensions()
}

fn main() {
    let marked = Marked {
        conn: Conn(Extensions::new()),
        inner: Conn(Extensions::new()),
    };
    assert!(core::ptr::eq(store(&marked), &raw const marked.conn.0));

    let inner = Inner {
        _writer: NotExtensions,
        inner: Conn(Extensions::new()),
    };
    assert!(core::ptr::eq(store(&inner), &raw const inner.inner.0));

    let owned = Store {
        _body: NotExtensions,
        extensions: Extensions::new(),
    };
    assert!(core::ptr::eq(store(&owned), &raw const owned.extensions));

    let tuple = TupleStore(NotExtensions, Extensions::new());
    assert!(core::ptr::eq(store(&tuple), &raw const tuple.1));

    let single = Single {
        conn: Conn(Extensions::new()),
    };
    assert!(core::ptr::eq(store(&single), &raw const single.conn.0));

    let newtype = Newtype(Conn(Extensions::new()));
    assert!(core::ptr::eq(store(&newtype), &raw const newtype.0.0));
}
