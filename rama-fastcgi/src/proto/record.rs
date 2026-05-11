//! FastCGI record header and fixed-length record bodies.
//!
//! Every FastCGI message is framed as one or more records. All records share a
//! common 8-byte header described in [`RecordHeader`].

use rama_core::bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{ProtocolError, ProtocolStatus, RecordType, Role, error::ProtocolError as PE};

/// The 8-byte header that precedes every FastCGI record.
///
/// ```plain
/// +---------+---------+-----------+-----------+---------------+-----------+---------+
/// | version | type    | requestId             | contentLength | paddingLen| reserved|
/// +---------+---------+-----------+-----------+---------------+-----------+---------+
/// |    1    |    1    |     1     |     1     |      1    1   |     1     |    1    |
/// +---------+---------+-----------+-----------+---------------+-----------+---------+
/// ```
///
/// - `version` is always `FCGI_VERSION_1` (1).
/// - `type` identifies the record type.
/// - `requestId` identifies the request this record belongs to; 0 for management records.
/// - `contentLength` is the number of bytes of content following the header.
/// - `paddingLength` is the number of padding bytes following the content.
/// - `reserved` must be zero.
///
/// Reference: FastCGI Specification §3.3
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordHeader {
    pub record_type: RecordType,
    /// 0 for management records; 1–65535 for application records.
    pub request_id: u16,
    /// Number of content bytes following this header (0–65535).
    pub content_length: u16,
    /// Number of padding bytes following the content (0–255).
    pub padding_length: u8,
}

/// Protocol version as defined by the FastCGI specification.
///
/// The specification defines only version 1.
///
/// Reference: FastCGI Specification §3.3
pub const FCGI_VERSION_1: u8 = 1;

/// Request ID used for management records (GET_VALUES, GET_VALUES_RESULT, UNKNOWN_TYPE).
///
/// Reference: FastCGI Specification §3.3
pub const FCGI_NULL_REQUEST_ID: u16 = 0;

/// Maximum content length of a single FastCGI record (2 bytes unsigned).
pub const FCGI_MAX_CONTENT_LEN: usize = 65535;

impl RecordHeader {
    /// Create a new [`RecordHeader`] for an application record (non-zero requestId).
    #[must_use]
    pub fn new(record_type: RecordType, request_id: u16, content_length: u16) -> Self {
        Self {
            record_type,
            request_id,
            content_length,
            padding_length: 0,
        }
    }

    /// Create a new [`RecordHeader`] for a management record (requestId == 0).
    #[must_use]
    pub fn management(record_type: RecordType, content_length: u16) -> Self {
        Self::new(record_type, FCGI_NULL_REQUEST_ID, content_length)
    }

    /// Read a [`RecordHeader`] from the reader.
    ///
    /// Reads all 8 bytes in a single `read_exact` call so the header is parsed
    /// atomically: a future dropped mid-read either consumes the full header
    /// or none of it (modulo what `read_exact` itself buffers), preventing
    /// stream desync on a kept-alive connection.
    ///
    /// Reference: FastCGI Specification §3.3
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf).await?;

        let version = buf[0];
        if version != FCGI_VERSION_1 {
            return Err(PE::unexpected_byte(0, version));
        }
        let record_type = RecordType::from(buf[1]);
        let request_id = u16::from_be_bytes([buf[2], buf[3]]);
        let content_length = u16::from_be_bytes([buf[4], buf[5]]);
        let padding_length = buf[6];
        // buf[7] is reserved

        Ok(Self {
            record_type,
            request_id,
            content_length,
            padding_length,
        })
    }

    /// Write this [`RecordHeader`] to the writer.
    ///
    /// Reference: FastCGI Specification §3.3
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 8];
        self.write_to_buf(&mut buf.as_mut_slice());
        w.write_all(&buf).await
    }

    /// Write this [`RecordHeader`] into the buffer.
    ///
    /// Reference: FastCGI Specification §3.3
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(FCGI_VERSION_1);
        buf.put_u8(self.record_type.into());
        buf.put_u16(self.request_id);
        buf.put_u16(self.content_length);
        buf.put_u8(self.padding_length);
        buf.put_u8(0); // reserved
    }
}

/// Body of a `FCGI_BEGIN_REQUEST` record (8 bytes).
///
/// ```plain
/// +--------+--------+--------+------------------+
/// | roleB1 | roleB0 | flags  | reserved (5)     |
/// +--------+--------+--------+------------------+
/// |   1    |   1    |   1    |      5            |
/// +--------+--------+--------+------------------+
/// ```
///
/// The `flags` field carries `FCGI_KEEP_CONN` (bit 0): if set, the web server does
/// not close the transport connection after receiving `FCGI_END_REQUEST`.
///
/// Reference: FastCGI Specification §5.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginRequestBody {
    pub role: Role,
    /// If true, the web server will keep the connection open after this request completes.
    pub keep_conn: bool,
}

/// Flag bit: keep the transport connection open after the request ends.
///
/// Reference: FastCGI Specification §5.1
pub const FCGI_KEEP_CONN: u8 = 1;

impl BeginRequestBody {
    /// Read a [`BeginRequestBody`] (8 bytes) from the reader.
    ///
    /// Reference: FastCGI Specification §5.1
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf).await?;
        let role = Role::from(u16::from_be_bytes([buf[0], buf[1]]));
        let keep_conn = (buf[2] & FCGI_KEEP_CONN) != 0;
        // buf[3..8] are 5 reserved bytes
        Ok(Self { role, keep_conn })
    }

    /// Write this [`BeginRequestBody`] (8 bytes) to the writer.
    ///
    /// Reference: FastCGI Specification §5.1
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 8];
        self.write_to_buf(&mut buf.as_mut_slice());
        w.write_all(&buf).await
    }

    /// Write this [`BeginRequestBody`] into the buffer.
    ///
    /// Reference: FastCGI Specification §5.1
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u16(self.role.into());
        let flags: u8 = if self.keep_conn { FCGI_KEEP_CONN } else { 0 };
        buf.put_u8(flags);
        buf.put_bytes(0, 5); // reserved
    }
}

/// Body of a `FCGI_END_REQUEST` record (8 bytes).
///
/// ```plain
/// +----------+----------+----------+----------+----------------+----------+
/// | appStat3 | appStat2 | appStat1 | appStat0 | protocolStatus | rsv (3)  |
/// +----------+----------+----------+----------+----------------+----------+
/// |    1     |    1     |    1     |    1     |       1        |    3     |
/// +----------+----------+----------+----------+----------------+----------+
/// ```
///
/// `appStatus` is a 4-byte big-endian integer carrying the application exit code.
/// `protocolStatus` is one of the [`ProtocolStatus`] values.
///
/// Reference: FastCGI Specification §5.5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndRequestBody {
    /// Application-level exit status (analogous to a CGI process exit code).
    pub app_status: u32,
    pub protocol_status: ProtocolStatus,
}

impl EndRequestBody {
    /// Create a successful [`EndRequestBody`] with exit code 0.
    #[must_use]
    pub fn success() -> Self {
        Self {
            app_status: 0,
            protocol_status: ProtocolStatus::RequestComplete,
        }
    }

    /// Create an [`EndRequestBody`] indicating the application does not support multiplexing.
    #[must_use]
    pub fn cant_mpx_conn() -> Self {
        Self {
            app_status: 0,
            protocol_status: ProtocolStatus::CantMpxConn,
        }
    }

    /// Create an [`EndRequestBody`] indicating the application is overloaded.
    #[must_use]
    pub fn overloaded() -> Self {
        Self {
            app_status: 0,
            protocol_status: ProtocolStatus::Overloaded,
        }
    }

    /// Create an [`EndRequestBody`] indicating the role was not recognised.
    #[must_use]
    pub fn unknown_role() -> Self {
        Self {
            app_status: 0,
            protocol_status: ProtocolStatus::UnknownRole,
        }
    }

    /// Read an [`EndRequestBody`] (8 bytes) from the reader.
    ///
    /// Reference: FastCGI Specification §5.5
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf).await?;
        let app_status = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let protocol_status = ProtocolStatus::from(buf[4]);
        // buf[5..8] are 3 reserved bytes
        Ok(Self {
            app_status,
            protocol_status,
        })
    }

    /// Write this [`EndRequestBody`] (8 bytes) to the writer.
    ///
    /// Reference: FastCGI Specification §5.5
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 8];
        self.write_to_buf(&mut buf.as_mut_slice());
        w.write_all(&buf).await
    }

    /// Write this [`EndRequestBody`] into the buffer.
    ///
    /// Reference: FastCGI Specification §5.5
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32(self.app_status);
        buf.put_u8(self.protocol_status.into());
        buf.put_bytes(0, 3); // reserved
    }
}

/// Body of a `FCGI_UNKNOWN_TYPE` management record (8 bytes).
///
/// ```plain
/// +------+-----------+
/// | type | rsv (7)   |
/// +------+-----------+
/// |  1   |    7      |
/// +------+-----------+
/// ```
///
/// Sent in response to a management record whose type the application does not recognise.
///
/// Reference: FastCGI Specification §4.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTypeBody {
    /// The type byte from the unrecognised management record.
    pub unknown_type: u8,
}

impl UnknownTypeBody {
    /// Read an [`UnknownTypeBody`] (8 bytes) from the reader.
    ///
    /// Reference: FastCGI Specification §4.2
    pub async fn read_from<R>(r: &mut R) -> Result<Self, ProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 8];
        r.read_exact(&mut buf).await?;
        Ok(Self {
            unknown_type: buf[0],
        })
    }

    /// Write this [`UnknownTypeBody`] (8 bytes) to the writer.
    ///
    /// Reference: FastCGI Specification §4.2
    pub async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 8];
        self.write_to_buf(&mut buf.as_mut_slice());
        w.write_all(&buf).await
    }

    /// Write this [`UnknownTypeBody`] into the buffer.
    pub fn write_to_buf<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.unknown_type);
        buf.put_bytes(0, 7); // reserved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::test_write_read_eq;

    #[tokio::test]
    async fn test_record_header_write_read_eq() {
        test_write_read_eq!(
            RecordHeader::new(RecordType::BeginRequest, 1, 8),
            RecordHeader,
        );
        test_write_read_eq!(RecordHeader::new(RecordType::Params, 1, 42), RecordHeader,);
        test_write_read_eq!(
            RecordHeader::management(RecordType::GetValues, 16),
            RecordHeader,
        );
        test_write_read_eq!(
            RecordHeader {
                record_type: RecordType::Stdout,
                request_id: 5,
                content_length: 1000,
                padding_length: 7,
            },
            RecordHeader,
        );
    }

    #[tokio::test]
    async fn test_begin_request_body_write_read_eq() {
        test_write_read_eq!(
            BeginRequestBody {
                role: Role::Responder,
                keep_conn: false,
            },
            BeginRequestBody,
        );
        test_write_read_eq!(
            BeginRequestBody {
                role: Role::Authorizer,
                keep_conn: true,
            },
            BeginRequestBody,
        );
    }

    #[tokio::test]
    async fn test_end_request_body_write_read_eq() {
        test_write_read_eq!(EndRequestBody::success(), EndRequestBody);
        test_write_read_eq!(
            EndRequestBody {
                app_status: 1,
                protocol_status: ProtocolStatus::UnknownRole,
            },
            EndRequestBody,
        );
    }

    #[tokio::test]
    async fn test_unknown_type_body_write_read_eq() {
        test_write_read_eq!(UnknownTypeBody { unknown_type: 42 }, UnknownTypeBody);
    }
}
