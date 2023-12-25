pub use http::Extensions;

pub trait Extendable {
    fn extensions(&self) -> &Extensions;
    fn extensions_mut(&mut self) -> &mut Extensions;
}

impl<T> Extendable for crate::http::Request<T> {
    fn extensions(&self) -> &Extensions {
        crate::http::Request::extensions(self)
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        crate::http::Request::extensions_mut(self)
    }
}

impl<T> Extendable for crate::http::Response<T> {
    fn extensions(&self) -> &Extensions {
        crate::http::Response::extensions(self)
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        crate::http::Response::extensions_mut(self)
    }
}

impl<S> Extendable for crate::tcp::TcpStream<S> {
    fn extensions(&self) -> &Extensions {
        crate::tcp::TcpStream::extensions(self)
    }

    fn extensions_mut(&mut self) -> &mut Extensions {
        crate::tcp::TcpStream::extensions_mut(self)
    }
}
