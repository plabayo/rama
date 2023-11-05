#![feature(async_fn_in_trait)]
#![feature(return_type_notation)]
#![allow(incomplete_features)]

pub mod graceful;
pub mod runtime;
pub mod server;
pub mod service;
pub mod state;
pub mod stream;

pub use tokio::main;
