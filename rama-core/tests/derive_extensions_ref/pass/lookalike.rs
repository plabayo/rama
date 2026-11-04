#![deny(warnings)]

use rama_core::extensions::{self, ExtensionsRef};

// A local type that only shares the store's name.
struct Extensions(extensions::Extensions);

impl ExtensionsRef for Extensions {
    fn extensions(&self) -> &extensions::Extensions {
        &self.0
    }
}

#[derive(ExtensionsRef)]
struct Local<B> {
    _body: B,
    store: Extensions,
}

// A type parameter named `Extensions`.
#[derive(ExtensionsRef)]
struct Generic<Extensions> {
    _id: u8,
    store: Extensions,
}

fn store<T: ExtensionsRef>(value: &T) -> &extensions::Extensions {
    value.extensions()
}

fn main() {
    let local = Local {
        _body: (),
        store: Extensions(extensions::Extensions::new()),
    };
    assert!(core::ptr::eq(store(&local), &raw const local.store.0));

    let generic = Generic {
        _id: 0,
        store: extensions::Extensions::new(),
    };
    assert!(core::ptr::eq(store(&generic), &raw const generic.store));
}
