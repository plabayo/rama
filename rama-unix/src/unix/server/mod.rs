//! Unix (domain) socket server module for Rama.
//!
//! The Unix server is used to create a [`UnixListener`] and accept incoming connections.
//!
//! # Example
//!
//! ```no_run
//! use rama_unix::{UnixStream, server::UnixListener};
//! use rama_core::service::service_fn;
//! use rama_core::rt::Executor;
//! use tokio::io::AsyncWriteExt;
//!
//! #[tokio::main]
//! async fn main() {
//!     UnixListener::bind_path("/tmp/example.socket", Executor::default())
//!         .await
//!         .expect("bind Unix Listener")
//!         .serve(service_fn(async |mut stream: UnixStream| {
//!             stream
//!                 .write_all(b"Hello, Unix!")
//!                 .await
//!                 .expect("write to stream");
//!             Ok::<_, std::convert::Infallible>(())
//!         }))
//!         .await;
//! }
//! ```

mod listener;
#[doc(inline)]
pub use listener::{UnixListener, UnixListenerBuilder};
