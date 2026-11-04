//! `#[derive(ExtensionsRef)]` resolves `rama-core` through a renamed dependency.

#![deny(warnings)]

use renamed_rama_core::extensions::{Extensions, ExtensionsRef};

struct Conn(Extensions);

impl ExtensionsRef for Conn {
    fn extensions(&self) -> &Extensions {
        &self.0
    }
}

#[derive(ExtensionsRef)]
struct Wrapper<S, W> {
    _writer: W,
    inner: S,
}

#[derive(ExtensionsRef)]
struct Store<B> {
    _body: B,
    extensions: Extensions,
}

#[test]
fn derive_resolves_renamed_rama_core() {
    let wrapper = Wrapper {
        _writer: (),
        inner: Conn(Extensions::new()),
    };
    assert!(core::ptr::eq(
        wrapper.extensions(),
        &raw const wrapper.inner.0
    ));

    let store = Store {
        _body: (),
        extensions: Extensions::new(),
    };
    assert!(core::ptr::eq(
        store.extensions(),
        &raw const store.extensions
    ));
}
