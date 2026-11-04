//! `#[derive(ExtensionsRef)]` through a renamed umbrella `rama` dependency, without `rama-core`.

#![deny(warnings)]

use renamed_rama::extensions::{Extensions, ExtensionsRef};

pub struct Conn(Extensions);

impl ExtensionsRef for Conn {
    fn extensions(&self) -> &Extensions {
        &self.0
    }
}

#[derive(ExtensionsRef)]
pub struct Wrapper<S, W> {
    pub writer: W,
    pub inner: S,
}

#[derive(ExtensionsRef)]
pub struct Store<B> {
    pub body: B,
    pub extensions: Extensions,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_resolves_renamed_umbrella() {
        let wrapper = Wrapper {
            writer: (),
            inner: Conn(Extensions::new()),
        };
        assert!(core::ptr::eq(
            wrapper.extensions(),
            &raw const wrapper.inner.0
        ));

        let store = Store {
            body: (),
            extensions: Extensions::new(),
        };
        assert!(core::ptr::eq(
            store.extensions(),
            &raw const store.extensions
        ));
    }
}
