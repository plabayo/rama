use std::future::{Future, ready};

pub mod layer;
pub mod service;
pub mod spec;

pub trait Toggle {
    fn toggle(&mut self) -> impl Future<Output = bool> + Send + '_;
    fn is_recording_on(&self) -> bool;
}

#[derive(Clone)]
pub struct Comment {
    pub author: String,
    pub text: String,
}

// example implementation
#[derive(Clone)]
pub struct StaticToggle {
    value: bool,
}

impl StaticToggle {
    pub fn new(value: bool) -> Self {
        Self { value }
    }
}

impl Toggle for StaticToggle {
    fn is_recording_on(&self) -> bool {
        self.value
    }

    fn toggle(&mut self) -> impl std::future::Future<Output = bool> + Send + '_ {
        self.value = !self.value;
        ready(self.value)
    }
}
