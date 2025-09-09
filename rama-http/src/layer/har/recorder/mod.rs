use super::spec;
use std::{borrow::Cow, sync::Arc};

mod fs;
pub use fs::{FileRecorder, HarFilePath};
use rama_core::context::Extensions;

#[derive(Debug, Clone)]
/// This object represents the root of exported data.
pub struct LogMetaInfo {
    /// Version number of the format. If empty, string "1.1" is assumed by default.
    pub version: Cow<'static, str>,
    /// Name and version info of the log creator application.
    pub creator: spec::Creator,
    /// Name and version info of used browser.
    pub browser: Option<spec::Browser>,
    /// A comment provided by the user or the application.
    pub comment: Option<Cow<'static, str>>,
}

pub trait Recorder: Send + Sync + 'static {
    fn record(&self, entry: spec::Log) -> impl Future<Output = Option<Extensions>> + Send + '_;

    // this function will be called even when no session is active,
    // a recorder has to handle this as a nop (ignore)
    fn stop_record(&self) -> impl Future<Output = ()> + Send;
}

impl<R: Recorder> Recorder for Arc<R> {
    fn record(&self, log: spec::Log) -> impl Future<Output = Option<Extensions>> + Send + '_ {
        (**self).record(log)
    }

    fn stop_record(&self) -> impl Future<Output = ()> + Send {
        (**self).stop_record()
    }
}
