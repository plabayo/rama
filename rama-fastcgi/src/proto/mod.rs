//! Implementation of the FastCGI Protocol.
//!
//! Reference: FastCGI spec 1.0
//! (embedded in repo crate dir at `specifications/fastcgi_spec.txt`)

pub mod params;
pub mod record;

pub(crate) mod io;

mod enums;
pub use enums::{ProtocolStatus, RecordType, Role};

mod error;
pub use error::ProtocolError;

pub use record::{
    BeginRequestBody, EndRequestBody, FCGI_KEEP_CONN, FCGI_MAX_CONTENT_LEN, FCGI_NULL_REQUEST_ID,
    FCGI_VERSION_1, RecordHeader, UnknownTypeBody,
};

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
use test_write_read_eq;
