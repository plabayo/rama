#![allow(clippy::disallowed_names)]

pub fn assert_send<T: Send>() {}
pub fn assert_sync<T: Sync>() {}
