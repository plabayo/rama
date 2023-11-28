pub use http::Extensions;

pub trait Extendable {
    fn extensions(&self) -> &Extensions;
    fn extensions_mut(&mut self) -> &mut Extensions;
}

impl Extendable for Extensions {
    fn extensions(&self) -> &Extensions {
        self
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        self
    }
}

impl<T> Extendable for crate::http::Request<T> {
    fn extensions(&self) -> &Extensions {
        self.extensions()
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        self.extensions_mut()
    }
}

impl<T> Extendable for crate::http::Response<T> {
    fn extensions(&self) -> &Extensions {
        self.extensions()
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        self.extensions_mut()
    }
}
