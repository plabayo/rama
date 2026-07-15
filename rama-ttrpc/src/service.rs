use std::marker::PhantomData;
use std::sync::Arc;

use crate::server::method_handlers::MethodHandler;

pub trait Service: Send + Sync {
    fn methods(&self) -> Vec<(&'static str, Arc<dyn MethodHandler + Send + Sync>)>;
}

pub struct UnaryMethod<Input, Output, Method> {
    pub(crate) method: Method,
    _phantom: PhantomData<fn() -> (Input, Output)>,
}

pub struct ServerStreamingMethod<Input, Output, Method> {
    pub(crate) method: Method,
    _phantom: PhantomData<fn() -> (Input, Output)>,
}

pub struct ClientStreamingMethod<Input, Output, Method> {
    pub(crate) method: Method,
    _phantom: PhantomData<fn() -> (Input, Output)>,
}

pub struct DuplexStreamingMethod<Input, Output, Method> {
    pub(crate) method: Method,
    _phantom: PhantomData<fn() -> (Input, Output)>,
}

impl<Input, Output, F> UnaryMethod<Input, Output, F> {
    pub fn new(method: F) -> Self {
        Self {
            method,
            _phantom: PhantomData,
        }
    }
}

impl<Input, Output, F> ServerStreamingMethod<Input, Output, F> {
    pub fn new(method: F) -> Self {
        Self {
            method,
            _phantom: PhantomData,
        }
    }
}

impl<Input, Output, F> ClientStreamingMethod<Input, Output, F> {
    pub fn new(method: F) -> Self {
        Self {
            method,
            _phantom: PhantomData,
        }
    }
}

impl<Input, Output, F> DuplexStreamingMethod<Input, Output, F> {
    pub fn new(method: F) -> Self {
        Self {
            method,
            _phantom: PhantomData,
        }
    }
}
