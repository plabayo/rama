use crate::layer::har::spec::Log as HarLog;
use std::future::Future;

pub mod default;
pub mod layer;
pub mod service;
pub mod spec;

#[derive(Clone)]
pub struct Comment {
    pub author: String,
    pub text: String,
}

pub trait Toggle {
    fn toggle(&mut self) -> impl Future<Output = bool> + Send + '_;
    fn is_recording_on(&self) -> bool;
}

pub trait Recorder: Clone + Send + Sync + 'static {
    fn record(&self, line: HarLog) -> impl Future<Output = ()> + Send + '_;
    fn data(&self) -> Vec<HarLog>;
}
