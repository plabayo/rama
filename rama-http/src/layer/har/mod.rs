use std::future::Future;

pub mod layer;
pub mod service;
pub mod spec;

pub trait Toggle {
    fn toggle(&self) -> impl Future<Output = bool> + Send + '_;
}

#[derive(Clone)]
pub struct Comment {
    pub author: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy)]
pub enum ExportMode {
    Override,
    SomeOther,
}

pub struct HARExport<S, T: Toggle> {
    toggle: T,
    data: Vec<spec::Log>,
    service: S,
}
