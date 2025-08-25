use crate::layer::har::spec::Log as HarLog;

use std::future::Future;

pub mod default;
pub mod layer;
pub mod request_comment;
pub mod service;
pub mod spec;
pub mod toggle;

pub trait Recorder: Send + Sync + 'static {
    fn record(&self, line: HarLog) -> impl Future<Output = ()> + Send + '_;
}
