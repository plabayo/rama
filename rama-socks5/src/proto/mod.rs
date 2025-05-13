//! Implementation of the SOCKS5 Protocol [RFC 1928]
//!
//! [RFC 1928]: https://datatracker.ietf.org/doc/html/rfc1928

mod common;

pub mod client;
pub mod server;
pub mod udp;

mod enums;
pub use enums::{
    AddressType, Command, ProtocolVersion, ReplyKind, SocksMethod,
    UsernamePasswordSubnegotiationVersion,
};

mod error;
pub use error::ProtocolError;

#[cfg(test)]
macro_rules! test_write_read_eq {
    ($w:expr, $r:ty $(,)?) => {{
        let mut buf = Vec::new();
        let w = $w;
        w.write_to(&mut buf).await.unwrap();
        let encoded = format!("{buf:x?}");
        let mut r = std::io::Cursor::new(buf);
        let output = match <$r>::read_from(&mut r).await {
            Ok(output) => output,
            Err(err) => panic!("unexpected err {err:?} for reading encoded: {encoded}"),
        };
        assert_eq!(w, output, "encoded: {encoded}");
    }};
}

#[cfg(test)]
macro_rules! test_write_read_sync_eq {
    ($w:expr, $r:ty $(,)?) => {{
        let mut buf = Vec::new();
        let w = $w;
        w.write_to_sync(&mut buf).unwrap();
        let encoded = format!("{buf:x?}");
        let mut r = std::io::Cursor::new(buf);
        let output = match <$r>::read_from_sync(&mut r) {
            Ok(output) => output,
            Err(err) => panic!("unexpected err {err:?} for reading encoded: {encoded}"),
        };
        assert_eq!(w, output, "encoded: {encoded}");
    }};
}

#[cfg(test)]
use test_write_read_eq;

#[cfg(test)]
use test_write_read_sync_eq;
