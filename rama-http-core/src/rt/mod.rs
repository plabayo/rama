//! Runtime components
//!
//! The traits and types within this module are used to allow plugging in
//! runtime types. These include:
//!
//! - Timers
//! - IO transports

mod io;
mod timer;

pub use self::io::{Read, ReadBuf, ReadBufCursor, Write};
pub use self::timer::{Sleep, Timer};
