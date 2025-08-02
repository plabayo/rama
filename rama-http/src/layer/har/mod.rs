use crate::layer::har::spec::Log as HarLog;
use std::future::Future;

pub mod default;
pub mod layer;
pub mod service;
pub mod spec;
pub mod toggle;

#[derive(Clone)]
pub struct Comment {
    pub author: String,
    pub text: String,
}

pub trait Recorder: Clone + Send + Sync + 'static {
    fn record(&self, line: HarLog) -> impl Future<Output = ()> + Send + '_;
}
