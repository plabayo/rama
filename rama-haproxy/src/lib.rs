//! rama HaProxy support
//!
//! <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>
//!
//! Crate used by the end-user `rama` crate and `rama` crate authors alike.
//!
//! Learn more about `rama`:
//!
//! - Github: <https://github.com/plabayo/rama>
//! - Book: <https://ramaproxy.org/book/>

pub mod client;
pub mod protocol;
pub mod server;
