#![expect(
    clippy::unreachable,
    reason = "gRPC-Web codec arms gated on caller-validated state that the type system can't enforce"
)]

use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use base64::Engine as _;
use pin_project_lite::pin_project;

use rama_core::{
    bytes::{Buf, BufMut, Bytes, BytesMut},
    futures::Stream,
};
use rama_http::headers::ContentType;
use rama_http_types::{
    HeaderMap, HeaderName, HeaderValue,
    body::{Frame, SizeHint, StreamingBody},
    header,
};
use rama_utils::octets::kib;

use crate::Status;

use self::content_types::*;

// A grpc header is u8 (flag) + u32 (msg len)
const GRPC_HEADER_SIZE: usize = 1 + 4;

pub(crate) mod content_types {
    use rama_http_types::{HeaderMap, header::CONTENT_TYPE};

    pub(crate) const GRPC_WEB: &str = "application/grpc-web";
    pub(crate) const GRPC_WEB_PROTO: &str = "application/grpc-web+proto";
    pub(crate) const GRPC_WEB_TEXT: &str = "application/grpc-web-text";
    pub(crate) const GRPC_WEB_TEXT_PROTO: &str = "application/grpc-web-text+proto";

    pub(crate) fn is_grpc_web(headers: &HeaderMap) -> bool {
        matches!(
            content_type(headers),
            Some(GRPC_WEB | GRPC_WEB_PROTO | GRPC_WEB_TEXT | GRPC_WEB_TEXT_PROTO)
        )
    }

    fn content_type(headers: &HeaderMap) -> Option<&str> {
        headers.get(CONTENT_TYPE).and_then(|val| val.to_str().ok())
    }
}

const BUFFER_SIZE: usize = kib(8);

const FRAME_HEADER_SIZE: usize = 5;

// 8th (MSB) bit of the 1st gRPC frame byte
// denotes an uncompressed trailer (as part of the body)
const GRPC_WEB_TRAILERS_BIT: u8 = 0b10000000;

#[derive(Copy, Clone, PartialEq, Debug)]
enum Direction {
    Decode,
    Encode,
    Empty,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub(crate) enum Encoding {
    Base64,
    None,
}

pin_project! {
    /// HttpBody adapter for the grpc web based services.
    #[derive(Debug)]
    pub struct GrpcWebCall<B> {
        #[pin]
        inner: B,
        buf: BytesMut,
        decoded: BytesMut,
        direction: Direction,
        encoding: Encoding,
        client: bool,
        client_done: bool,
        trailers: Option<HeaderMap>,
    }
}

impl<B: Default> Default for GrpcWebCall<B> {
    fn default() -> Self {
        Self {
            inner: Default::default(),
            buf: Default::default(),
            decoded: Default::default(),
            direction: Direction::Empty,
            encoding: Encoding::None,
            client: Default::default(),
            client_done: false,
            trailers: Default::default(),
        }
    }
}

impl<B> GrpcWebCall<B> {
    pub(crate) fn request(inner: B, encoding: Encoding) -> Self {
        Self::new(inner, Direction::Decode, encoding)
    }

    pub(crate) fn response(inner: B, encoding: Encoding) -> Self {
        Self::new(inner, Direction::Encode, encoding)
    }

    pub(crate) fn client_request(inner: B) -> Self {
        Self::new_client(inner, Direction::Encode, Encoding::None)
    }

    pub(crate) fn client_response(inner: B) -> Self {
        Self::new_client(inner, Direction::Decode, Encoding::None)
    }

    fn new_client(inner: B, direction: Direction, encoding: Encoding) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(match (direction, encoding) {
                (Direction::Encode, Encoding::Base64) => BUFFER_SIZE,
                _ => 0,
            }),
            decoded: BytesMut::with_capacity(match direction {
                Direction::Decode => BUFFER_SIZE,
                _ => 0,
            }),
            direction,
            encoding,
            client: true,
            client_done: false,
            trailers: None,
        }
    }

    fn new(inner: B, direction: Direction, encoding: Encoding) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(match (direction, encoding) {
                (Direction::Encode, Encoding::Base64) => BUFFER_SIZE,
                _ => 0,
            }),
            decoded: BytesMut::with_capacity(0),
            direction,
            encoding,
            client: false,
            client_done: false,
            trailers: None,
        }
    }

    // This is to avoid passing a slice of bytes with a length that the base64
    // decoder would consider invalid.
    #[inline]
    fn max_decodable(&self) -> usize {
        (self.buf.len() / 4) * 4
    }

    fn decode_chunk(mut self: Pin<&mut Self>) -> Result<Option<Bytes>, Status> {
        // not enough bytes to decode
        if self.buf.is_empty() || self.buf.len() < 4 {
            return Ok(None);
        }

        // Split `buf` at the largest index that is multiple of 4. Decode the
        // returned `Bytes`, keeping the rest for the next attempt to decode.
        let index = self.max_decodable();

        crate::util::base64::STANDARD
            .decode(self.as_mut().project().buf.split_to(index))
            .map(|decoded| Some(Bytes::from(decoded)))
            .map_err(internal_error)
    }
}

impl<B> GrpcWebCall<B>
where
    B: StreamingBody<Data: Buf, Error: fmt::Display>,
{
    // Poll body for data, decoding (e.g. via Base64 if necessary) and returning frames
    // to the caller. If the caller is a client, it should look for trailers before
    // returning these frames.
    fn poll_decode(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        match self.encoding {
            Encoding::Base64 => loop {
                if let Some(bytes) = self.as_mut().decode_chunk()? {
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }

                let this = self.as_mut().project();

                match ready!(this.inner.poll_frame(cx)) {
                    Some(Ok(frame)) if frame.is_data() => this
                        .buf
                        .put(frame.into_data().unwrap_or_else(|_| unreachable!())),
                    Some(Ok(frame)) if frame.is_trailers() => {
                        return Poll::Ready(Some(Err(internal_error(
                            "malformed base64 request has unencoded trailers",
                        ))));
                    }
                    Some(Ok(_)) => {
                        return Poll::Ready(Some(Err(internal_error("unexpected frame type"))));
                    }
                    Some(Err(e)) => return Poll::Ready(Some(Err(internal_error(e)))),
                    None => {
                        return if this.buf.has_remaining() {
                            Poll::Ready(Some(Err(internal_error("malformed base64 request"))))
                        } else if let Some(trailers) = this.trailers.take() {
                            Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                        } else {
                            Poll::Ready(None)
                        };
                    }
                }
            },

            Encoding::None => self
                .project()
                .inner
                .poll_frame(cx)
                .map_ok(|f| f.map_data(|mut d| d.copy_to_bytes(d.remaining())))
                .map_err(internal_error),
        }
    }

    fn poll_encode(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        let this = self.as_mut().project();

        match ready!(this.inner.poll_frame(cx)) {
            Some(Ok(frame)) if frame.is_data() => {
                let mut data = frame.into_data().unwrap_or_else(|_| unreachable!());
                let mut res = data.copy_to_bytes(data.remaining());

                if *this.encoding == Encoding::Base64 {
                    res = crate::util::base64::STANDARD.encode(res).into();
                }

                Poll::Ready(Some(Ok(Frame::data(res))))
            }
            Some(Ok(frame)) if frame.is_trailers() => {
                let trailers = frame.into_trailers().unwrap_or_else(|_| unreachable!());
                let mut res = make_trailers_frame(trailers);

                if *this.encoding == Encoding::Base64 {
                    res = crate::util::base64::STANDARD.encode(res).into();
                }

                Poll::Ready(Some(Ok(Frame::data(res))))
            }
            Some(Ok(_)) => Poll::Ready(Some(Err(internal_error("unexpected frame type")))),
            Some(Err(e)) => Poll::Ready(Some(Err(internal_error(e)))),
            None => Poll::Ready(None),
        }
    }
}

impl<B> StreamingBody for GrpcWebCall<B>
where
    B: StreamingBody<Error: fmt::Display>,
{
    type Data = Bytes;
    type Error = Status;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.client && self.direction == Direction::Decode {
            loop {
                if self.client_done {
                    return Poll::Ready(
                        self.as_mut()
                            .project()
                            .trailers
                            .take()
                            .map(|trailers| Ok(Frame::trailers(trailers))),
                    );
                }

                // Drain complete buffered frames before polling the transport again.
                match find_trailers(&self.decoded)? {
                    FindTrailers::Trailer(len) => {
                        let this = self.as_mut().project();
                        let messages = this.decoded.split_to(len).freeze();
                        *this.trailers = decode_trailers_frame(this.decoded.split().freeze())?;
                        *this.client_done = true;
                        if !messages.is_empty() {
                            return Poll::Ready(Some(Ok(Frame::data(messages))));
                        }
                        continue;
                    }
                    FindTrailers::Done(len) if len > 0 => {
                        let messages = self.as_mut().project().decoded.split_to(len).freeze();
                        return Poll::Ready(Some(Ok(Frame::data(messages))));
                    }
                    FindTrailers::IncompleteBuf | FindTrailers::Done(_) => {}
                }

                // Empty DATA and incomplete headers are not EOF; only the inner
                // body ending (or a complete trailers frame) ends this decoder.
                match ready!(self.as_mut().poll_decode(cx)) {
                    Some(Ok(frame)) => match frame.into_data() {
                        Ok(data) => self.as_mut().project().decoded.put(data),
                        Err(frame) => {
                            let trailers = frame
                                .into_trailers()
                                .map_err(|_frame| internal_error("unexpected frame type"))?;
                            let this = self.as_mut().project();
                            *this.client_done = true;
                            if !this.decoded.is_empty() {
                                return Poll::Ready(Some(Err(internal_error(
                                    "incomplete gRPC-Web frame before HTTP trailers",
                                ))));
                            }
                            *this.trailers = Some(trailers);
                        }
                    },
                    Some(Err(error)) => return Poll::Ready(Some(Err(error))),
                    None => {
                        *self.as_mut().project().client_done = true;
                        if !self.decoded.is_empty() {
                            return Poll::Ready(Some(Err(internal_error(
                                "unexpected EOF in gRPC-Web frame",
                            ))));
                        }
                    }
                }
            }
        }

        match self.direction {
            Direction::Decode => self.poll_decode(cx),
            Direction::Encode => self.poll_encode(cx),
            Direction::Empty => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        if self.client && self.direction == Direction::Decode {
            self.client_done && self.trailers.is_none()
        } else {
            self.inner.is_end_stream()
        }
    }

    fn size_hint(&self) -> SizeHint {
        if self.client && self.direction == Direction::Decode {
            // Encoded trailer bytes disappear and message bytes may be buffered.
            SizeHint::default()
        } else {
            self.inner.size_hint()
        }
    }
}

impl<B> Stream for GrpcWebCall<B>
where
    B: StreamingBody<Error: fmt::Display>,
{
    type Item = Result<Frame<Bytes>, Status>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.poll_frame(cx)
    }
}

impl Encoding {
    pub(crate) fn from_content_type(headers: &HeaderMap) -> Self {
        Self::from_header(headers.get(header::CONTENT_TYPE))
    }

    pub(crate) fn from_accept(headers: &HeaderMap) -> Self {
        Self::from_header(headers.get(header::ACCEPT))
    }

    pub(crate) fn to_content_type(self) -> ContentType {
        match self {
            Self::Base64 => ContentType::grpc_web_text_proto(),
            Self::None => ContentType::grpc_web_proto(),
        }
    }

    fn from_header(value: Option<&HeaderValue>) -> Self {
        match value.and_then(|val| val.to_str().ok()) {
            Some(GRPC_WEB_TEXT_PROTO | GRPC_WEB_TEXT) => Self::Base64,
            _ => Self::None,
        }
    }
}

fn internal_error(e: impl std::fmt::Display) -> Status {
    Status::internal(format!("rama-grpc-web: {e}"))
}

// Key-value pairs encoded as a HTTP/1 headers block (without the terminating newline)
#[expect(
    clippy::needless_pass_by_value,
    reason = "trailers is consumed by the iterator regardless; taking by value clarifies the move semantics"
)]
fn encode_trailers(trailers: HeaderMap) -> Vec<u8> {
    trailers.iter().fold(Vec::new(), |mut acc, (key, value)| {
        acc.put_slice(key.as_ref());
        acc.push(b':');
        acc.put_slice(value.as_bytes());
        acc.put_slice(b"\r\n");
        acc
    })
}

fn decode_trailers_frame(mut buf: Bytes) -> Result<Option<HeaderMap>, Status> {
    if buf.remaining() < GRPC_HEADER_SIZE {
        return Ok(None);
    }

    buf.get_u8();
    buf.get_u32();

    let mut map = HeaderMap::new();
    let mut temp_buf = buf.clone();

    let mut trailers = Vec::new();
    let mut cursor_pos = 0;

    for (i, b) in buf.iter().enumerate() {
        // if we are at a trailer delimiter (\r\n)
        if b == &b'\r' && buf.get(i + 1) == Some(&b'\n') {
            // read the bytes of the trailer passed so far
            let trailer = temp_buf.copy_to_bytes(i - cursor_pos);
            // increment cursor beyond the delimiter
            cursor_pos = i + 2;
            trailers.push(trailer);
            if temp_buf.has_remaining() {
                // advance buf beyond the delimiters
                temp_buf.get_u8();
                temp_buf.get_u8();
            }
        }
    }

    for trailer in trailers {
        let mut s = trailer.split(|b| b == &b':');
        let key = s
            .next()
            .ok_or_else(|| Status::internal("trailers couldn't parse key"))?;
        let value = s
            .next()
            .ok_or_else(|| Status::internal("trailers couldn't parse value"))?;

        let value = value
            .split(|b| b == &b'\r')
            .next()
            .ok_or_else(|| Status::internal("trailers was not escaped"))?
            .strip_prefix(b" ")
            .unwrap_or(value);

        let header_key = HeaderName::try_from(key)
            .map_err(|e| Status::internal(format!("Unable to parse HeaderName: {e}")))?;
        let header_value = HeaderValue::try_from(value)
            .map_err(|e| Status::internal(format!("Unable to parse HeaderValue: {e}")))?;
        map.insert(header_key, header_value);
    }

    Ok(Some(map))
}

fn make_trailers_frame(trailers: HeaderMap) -> Bytes {
    let trailers = encode_trailers(trailers);
    let len = trailers.len();
    assert!(len <= u32::MAX as usize);

    let mut frame = BytesMut::with_capacity(len + FRAME_HEADER_SIZE);
    frame.put_u8(GRPC_WEB_TRAILERS_BIT);
    frame.put_u32(len as u32);
    frame.put_slice(&trailers);

    frame.freeze()
}

/// Locate a complete trailer frame or a prefix of complete message frames.
fn find_trailers(buf: &[u8]) -> Result<FindTrailers, Status> {
    let mut len = 0;
    let mut remaining = buf;

    loop {
        if remaining.is_empty() {
            return Ok(FindTrailers::Done(len));
        }
        if remaining.len() < GRPC_HEADER_SIZE {
            break;
        }

        let flag = remaining.get_u8();
        if !matches!(flag, 0 | 1 | GRPC_WEB_TRAILERS_BIT) {
            return Err(internal_error(format!("invalid frame flag {flag}")));
        }
        let payload_len = remaining.get_u32() as usize;
        if payload_len > remaining.len() {
            break;
        }
        if flag == GRPC_WEB_TRAILERS_BIT {
            if payload_len != remaining.len() {
                return Err(internal_error("unexpected data after gRPC-Web trailers"));
            }
            return Ok(FindTrailers::Trailer(len));
        }

        len += GRPC_HEADER_SIZE + payload_len;
        remaining = &buf[len..];
    }

    if len == 0 {
        Ok(FindTrailers::IncompleteBuf)
    } else {
        Ok(FindTrailers::Done(len))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FindTrailers {
    Trailer(usize),
    IncompleteBuf,
    Done(usize),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::needless_pass_by_value)]

    use super::*;

    #[test]
    fn encoding_constructors() {
        let cases = &[
            (GRPC_WEB, Encoding::None),
            (GRPC_WEB_PROTO, Encoding::None),
            (GRPC_WEB_TEXT, Encoding::Base64),
            (GRPC_WEB_TEXT_PROTO, Encoding::Base64),
            ("foo", Encoding::None),
        ];

        let mut headers = HeaderMap::new();

        for case in cases {
            headers.insert(header::CONTENT_TYPE, case.0.parse().unwrap());
            headers.insert(header::ACCEPT, case.0.parse().unwrap());

            assert_eq!(Encoding::from_content_type(&headers), case.1, "{}", case.0);
            assert_eq!(Encoding::from_accept(&headers), case.1, "{}", case.0);
        }
    }

    #[test]
    fn decode_trailers() {
        let mut headers = HeaderMap::new();
        headers.insert(Status::GRPC_STATUS, 0.into());
        headers.insert(
            Status::GRPC_MESSAGE,
            "this is a message".try_into().unwrap(),
        );

        let trailers = make_trailers_frame(headers.clone());

        let map = decode_trailers_frame(trailers).unwrap().unwrap();

        assert_eq!(headers, map);
    }

    #[test]
    fn find_trailers_non_buffered() {
        // Byte version of this:
        // b"\x80\0\0\0\x0fgrpc-status:0\r\n"
        let buf = [
            128, 0, 0, 0, 15, 103, 114, 112, 99, 45, 115, 116, 97, 116, 117, 115, 58, 48, 13, 10,
        ];

        let out = find_trailers(&buf[..]).unwrap();

        assert_eq!(out, FindTrailers::Trailer(0));
    }

    #[test]
    fn find_trailers_buffered() {
        // Byte version of this:
        // b"\0\0\0\0L\n$975738af-1a17-4aea-b887-ed0bbced6093\x1a$da609e9b-f470-4cc0-a691-3fd6a005a436\x80\0\0\0\x0fgrpc-status:0\r\n"
        let buf = [
            0, 0, 0, 0, 76, 10, 36, 57, 55, 53, 55, 51, 56, 97, 102, 45, 49, 97, 49, 55, 45, 52,
            97, 101, 97, 45, 98, 56, 56, 55, 45, 101, 100, 48, 98, 98, 99, 101, 100, 54, 48, 57,
            51, 26, 36, 100, 97, 54, 48, 57, 101, 57, 98, 45, 102, 52, 55, 48, 45, 52, 99, 99, 48,
            45, 97, 54, 57, 49, 45, 51, 102, 100, 54, 97, 48, 48, 53, 97, 52, 51, 54, 128, 0, 0, 0,
            15, 103, 114, 112, 99, 45, 115, 116, 97, 116, 117, 115, 58, 48, 13, 10,
        ];

        let out = find_trailers(&buf[..]).unwrap();

        assert_eq!(out, FindTrailers::Trailer(81));

        let trailers = decode_trailers_frame(Bytes::copy_from_slice(&buf[81..]))
            .unwrap()
            .unwrap();
        let status = trailers.get(Status::GRPC_STATUS).unwrap();
        assert_eq!(status.to_str().unwrap(), "0")
    }

    #[test]
    fn find_trailers_buffered_incomplete_message() {
        let buf = vec![
            0, 0, 0, 9, 238, 10, 233, 19, 18, 230, 19, 10, 9, 10, 1, 120, 26, 4, 84, 69, 88, 84,
            18, 60, 10, 58, 10, 56, 3, 0, 0, 0, 44, 0, 0, 0, 0, 0, 0, 0, 116, 104, 105, 115, 32,
            118, 97, 108, 117, 101, 32, 119, 97, 115, 32, 119, 114, 105, 116, 116, 101, 110, 32,
            118, 105, 97, 32, 119, 114, 105, 116, 101, 32, 100, 101, 108, 101, 103, 97, 116, 105,
            111, 110, 33, 18, 62, 10, 60, 10, 58, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 116, 104,
            105, 115, 32, 118, 97, 108, 117, 101, 32, 119, 97, 115, 32, 119, 114, 105, 116, 116,
            101, 110, 32, 98, 121, 32, 97, 110, 32, 101, 109, 98, 101, 100, 100, 101, 100, 32, 114,
            101, 112, 108, 105, 99, 97, 33, 18, 62, 10, 60, 10, 58, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0,
            0, 0, 116, 104, 105, 115, 32, 118, 97, 108, 117, 101, 32, 119, 97, 115, 32, 119, 114,
            105, 116, 116, 101, 110, 32, 98, 121, 32, 97, 110, 32, 101, 109, 98, 101, 100, 100,
            101, 100, 32, 114, 101, 112, 108, 105, 99, 97, 33, 18, 62, 10, 60, 10, 58, 3, 0, 0, 0,
            46, 0, 0, 0, 0, 0, 0, 0, 116, 104, 105, 115, 32, 118, 97, 108, 117, 101, 32, 119, 97,
            115, 32, 119, 114, 105, 116, 116, 101, 110, 32, 98, 121, 32, 97, 110, 32, 101, 109, 98,
            101, 100, 100, 101, 100, 32, 114, 101, 112, 108, 105, 99, 97, 33, 18, 62, 10, 60, 10,
            58, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 116, 104, 105, 115, 32, 118, 97, 108, 117,
            101, 32, 119, 97, 115, 32, 119, 114, 105, 116, 116, 101, 110, 32, 98, 121, 32, 97, 110,
            32, 101, 109, 98, 101, 100, 100, 101, 100, 32, 114, 101, 112, 108, 105, 99, 97, 33, 18,
            62, 10, 60, 10, 58, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 116, 104, 105, 115, 32, 118,
            97, 108, 117, 101, 32, 119, 97, 115, 32, 119, 114, 105, 116, 116, 101, 110, 32, 98,
            121, 32, 97, 110, 32, 101, 109, 98, 101, 100, 100, 101, 100, 32, 114, 101, 112, 108,
            105, 99, 97, 33, 18, 62, 10, 60, 10, 58, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0, 0, 0, 116, 104,
            105, 115, 32, 118, 97, 108, 117, 101, 32, 119, 97, 115, 32, 119, 114, 105, 116, 116,
            101, 110, 32, 98, 121, 32, 97, 110, 32, 101, 109, 98, 101, 100, 100, 101, 100, 32, 114,
            101, 112, 108, 105, 99, 97, 33, 18, 62, 10, 60, 10, 58, 3, 0, 0, 0, 46, 0, 0, 0, 0, 0,
            0, 0, 116, 104, 105, 115, 32, 118, 97, 108, 117, 101, 32, 119, 97, 115, 32, 119, 114,
            105, 116, 116, 101, 110, 32, 98, 121, 32,
        ];

        let out = find_trailers(&buf[..]).unwrap();

        assert_eq!(out, FindTrailers::IncompleteBuf);
    }

    #[test]
    fn decode_multiple_trailers() {
        let buf = b"\x80\0\0\0\x0fgrpc-status:0\r\ngrpc-message:\r\na:1\r\nb:2\r\n";

        let trailers = decode_trailers_frame(Bytes::copy_from_slice(&buf[..]))
            .unwrap()
            .unwrap();

        let mut expected = HeaderMap::new();
        expected.insert(Status::GRPC_STATUS, "0".parse().unwrap());
        expected.insert(Status::GRPC_MESSAGE, "".parse().unwrap());
        expected.insert("a", "1".parse().unwrap());
        expected.insert("b", "2".parse().unwrap());

        assert_eq!(trailers, expected);
    }

    #[test]
    fn decode_trailers_with_space_after_colon() {
        let buf = b"\x80\0\0\0\x0fgrpc-status: 0\r\ngrpc-message: \r\n";

        let trailers = decode_trailers_frame(Bytes::copy_from_slice(&buf[..]))
            .unwrap()
            .unwrap();

        let mut expected = HeaderMap::new();
        expected.insert(Status::GRPC_STATUS, "0".parse().unwrap());
        expected.insert(Status::GRPC_MESSAGE, "".parse().unwrap());

        assert_eq!(trailers, expected);
    }
}

#[cfg(test)]
mod client_response_tests {
    use super::*;
    use std::collections::VecDeque;
    use std::convert::Infallible;

    struct Frames(VecDeque<Frame<Bytes>>);
    impl StreamingBody for Frames {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
            Poll::Ready(self.0.pop_front().map(Ok))
        }
        fn is_end_stream(&self) -> bool {
            self.0.is_empty()
        }
    }
    fn poll(body: &mut GrpcWebCall<Frames>) -> Option<Frame<Bytes>> {
        match Pin::new(body).poll_frame(&mut Context::from_waker(std::task::Waker::noop())) {
            Poll::Ready(value) => value.map(Result::unwrap),
            Poll::Pending => panic!("ready-only fixture unexpectedly pending"),
        }
    }
    fn message() -> Bytes {
        Bytes::from_static(&[0, 0, 0, 0, 1, b'a'])
    }
    fn trailers() -> HeaderMap {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers
    }
    fn combined() -> GrpcWebCall<Frames> {
        let mut data = BytesMut::new();
        data.extend_from_slice(&message());
        data.extend_from_slice(&make_trailers_frame(trailers()));
        GrpcWebCall::client_response(Frames(VecDeque::from([Frame::data(data.freeze())])))
    }
    #[test]
    fn empty_data_must_not_end_client_response() {
        let mut body = GrpcWebCall::client_response(Frames(VecDeque::from([
            Frame::data(Bytes::new()),
            Frame::data(message()),
            Frame::data(make_trailers_frame(trailers())),
        ])));
        let first = poll(&mut body);
        assert!(
            first.is_some(),
            "empty DATA became EOS although two frames remain"
        );
    }
    #[test]
    fn pending_trailers_must_prevent_eos_hint() {
        let mut body = combined();
        assert_eq!(poll(&mut body).unwrap().into_data().unwrap(), message());
        assert!(
            !body.is_end_stream(),
            "is_end_stream=true while grpc-status trailers remain buffered"
        );
    }
    #[test]
    fn pending_trailers_must_be_emitted_on_next_poll() {
        let mut body = combined();
        assert_eq!(poll(&mut body).unwrap().into_data().unwrap(), message());
        let next = poll(&mut body);
        assert!(
            next.is_some(),
            "stored grpc-status trailers were discarded at inner EOF"
        );
        assert_eq!(next.unwrap().into_trailers().unwrap(), trailers());
    }

    #[test]
    fn partial_message_header_must_not_end_client_response() {
        let mut body = GrpcWebCall::client_response(Frames(VecDeque::from([
            Frame::data(Bytes::from_static(&[0])),
            Frame::data(Bytes::from_static(&[0, 0, 0, 1, b'a'])),
            Frame::data(make_trailers_frame(trailers())),
        ])));
        assert!(
            poll(&mut body).is_some(),
            "a one-byte message header became EOS before the remaining header and payload"
        );
    }
    #[tokio::test]
    async fn collection_must_retain_coalesced_trailers() {
        use rama_http_types::body::util::BodyExt;
        let collected = combined().collect().await.unwrap();
        assert_eq!(collected.trailers(), Some(&trailers()));
    }

    #[tokio::test]
    async fn fused_decoder_preserves_every_split_and_empty_frame() {
        use rama_http_types::body::util::BodyExt;

        let mut messages = BytesMut::from(message().as_ref());
        messages.extend_from_slice(&[0, 0, 0, 0, 0]); // A valid zero-length gRPC message.
        messages.extend_from_slice(&message());
        let mut wire = messages.clone();
        wire.extend_from_slice(&make_trailers_frame(trailers()));
        let wire = wire.freeze();
        for split in 0..=wire.len() {
            let frames = Frames(VecDeque::from([
                Frame::data(Bytes::new()),
                Frame::data(wire.slice(..split)),
                Frame::data(Bytes::new()),
                Frame::data(wire.slice(split..)),
                Frame::data(Bytes::new()),
            ]));
            let mut body = GrpcWebCall::client_response(frames).fuse();
            let collected = (&mut body).collect().await.unwrap();
            assert_eq!(collected.trailers(), Some(&trailers()), "split={split}");
            assert_eq!(collected.to_bytes(), messages, "split={split}");
            assert!(body.is_end_stream());
            assert!(body.frame().await.is_none());
        }
    }

    struct Steps(VecDeque<Poll<Result<Frame<Bytes>, &'static str>>>);

    impl StreamingBody for Steps {
        type Data = Bytes;
        type Error = &'static str;

        fn poll_frame(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            match self.0.pop_front() {
                Some(Poll::Ready(frame)) => Poll::Ready(Some(frame)),
                Some(Poll::Pending) => Poll::Pending,
                None => Poll::Ready(None),
            }
        }
    }

    #[test]
    fn pending_between_fragments_preserves_decoder_state() {
        let mut wire = BytesMut::from(message().as_ref());
        wire.extend_from_slice(&make_trailers_frame(trailers()));
        let wire = wire.freeze();
        for split in 1..wire.len() {
            let source = Steps(VecDeque::from([
                Poll::Ready(Ok(Frame::data(wire.slice(..split)))),
                Poll::Pending,
                Poll::Ready(Ok(Frame::data(Bytes::new()))),
                Poll::Ready(Ok(Frame::data(wire.slice(split..)))),
            ]));
            let mut body = GrpcWebCall::client_response(source);
            let mut cx = Context::from_waker(std::task::Waker::noop());
            let mut data = BytesMut::new();
            let mut received_trailers = None;
            let mut pending_count = 0;
            loop {
                match Pin::new(&mut body).poll_frame(&mut cx) {
                    Poll::Pending => {
                        pending_count += 1;
                        assert_eq!(pending_count, 1, "fixture only pends once");
                        assert!(!body.is_end_stream());
                    }
                    Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                        Ok(bytes) => {
                            assert!(received_trailers.is_none());
                            data.extend_from_slice(&bytes);
                            assert!(!body.is_end_stream(), "trailers remain");
                        }
                        Err(frame) => received_trailers = Some(frame.into_trailers().unwrap()),
                    },
                    Poll::Ready(Some(Err(err))) => panic!("split={split}: {err}"),
                    Poll::Ready(None) => break,
                }
            }
            assert_eq!(pending_count, 1);
            assert_eq!(data, message());
            assert_eq!(received_trailers, Some(trailers()));
            assert!(body.is_end_stream());
        }
    }

    #[test]
    fn buffered_trailers_do_not_poll_the_transport_again() {
        let mut wire = BytesMut::from(message().as_ref());
        wire.extend_from_slice(&make_trailers_frame(trailers()));
        let mut body = GrpcWebCall::client_response(Steps(VecDeque::from([
            Poll::Ready(Ok(Frame::data(wire.freeze()))),
            Poll::Pending,
        ])));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let Poll::Ready(Some(Ok(first))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("buffered message not emitted");
        };
        assert_eq!(first.into_data().unwrap(), message());
        assert!(!body.is_end_stream());
        let Poll::Ready(Some(Ok(last))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("buffered trailers waited for the transport");
        };
        assert_eq!(last.into_trailers().unwrap(), trailers());
        assert!(body.is_end_stream());
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[tokio::test]
    async fn truncated_frames_and_source_errors_remain_errors() {
        use rama_http_types::body::util::BodyExt;

        for frame in [message(), make_trailers_frame(trailers())] {
            for end in 1..frame.len() {
                let mut body = GrpcWebCall::client_response(Frames(VecDeque::from([
                    Frame::data(frame.slice(..end)),
                    Frame::data(Bytes::new()),
                ])));
                let error = body.frame().await.unwrap().unwrap_err();
                assert!(error.message().contains("unexpected EOF"));
                assert!(body.is_end_stream());
                assert!(body.frame().await.is_none());
            }
        }
        for partial in [Bytes::new(), message().slice(..1)] {
            let mut body = GrpcWebCall::client_response(Steps(VecDeque::from([
                Poll::Ready(Ok(Frame::data(partial))),
                Poll::Ready(Err("upstream failed")),
            ])));
            let error = body.frame().await.unwrap().unwrap_err();
            assert!(error.message().contains("upstream failed"));
        }
    }

    #[tokio::test]
    async fn clean_eof_and_native_http_trailers() {
        use rama_http_types::body::util::BodyExt;

        let mut empty = GrpcWebCall::client_response(Frames(VecDeque::from([
            Frame::data(Bytes::new()),
            Frame::data(Bytes::new()),
        ])));
        assert!(empty.frame().await.is_none());
        assert!(empty.is_end_stream());
        assert!(empty.frame().await.is_none());
        let body = GrpcWebCall::client_response(Frames(VecDeque::from([
            Frame::data(message()),
            Frame::data(Bytes::new()),
        ])));
        assert_eq!(body.collect().await.unwrap().to_bytes(), message());
        let body = GrpcWebCall::client_response(Frames(VecDeque::from([
            Frame::data(message()),
            Frame::data(Bytes::new()),
            Frame::trailers(trailers()),
        ])));
        let collected = body.fuse().collect().await.unwrap();
        assert_eq!(collected.trailers(), Some(&trailers()));
        assert_eq!(collected.to_bytes(), message());
    }

    #[test]
    fn malformed_flags_and_trailers_remain_errors() {
        assert!(
            find_trailers(&[2, 0, 0, 0, 0])
                .unwrap_err()
                .message()
                .contains("invalid frame flag")
        );
        let mut wire = make_trailers_frame(trailers()).to_vec();
        wire.extend_from_slice(&message());
        assert!(
            find_trailers(&wire)
                .unwrap_err()
                .message()
                .contains("unexpected data after")
        );
        let mut body = GrpcWebCall::client_response(Frames(VecDeque::from([Frame::data(
            Bytes::from_static(b"\x80\0\0\0\x07bad\r\n\r\n"),
        )])));
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut Context::from_waker(std::task::Waker::noop())),
            Poll::Ready(Some(Err(_)))
        ));
    }

    #[test]
    fn size_hint_does_not_count_trailers_or_omit_buffered_messages() {
        use rama_http_types::body::util::Full;
        let mut wire = BytesMut::from(message().as_ref());
        wire.extend_from_slice(&message()[..1]);
        let mut body = GrpcWebCall::client_response(Full::new(wire.freeze()));
        assert_eq!(StreamingBody::size_hint(&body).lower(), 0);
        let Poll::Ready(Some(Ok(_))) =
            Pin::new(&mut body).poll_frame(&mut Context::from_waker(std::task::Waker::noop()))
        else {
            panic!("complete prefix not emitted");
        };
        assert!(
            !body.is_end_stream(),
            "partial next header must still error"
        );
        assert_eq!(StreamingBody::size_hint(&body).lower(), 0);
        assert_eq!(StreamingBody::size_hint(&body).upper(), None);
    }

    #[tokio::test]
    async fn grpc_streaming_receives_coalesced_status_and_metadata() {
        use crate::codec::{DecodeBuf, Decoder, Streaming};
        use rama_http_types::body::util::BodyExt;

        struct BytesDecoder;
        impl Decoder for BytesDecoder {
            type Item = Bytes;
            type Error = Status;

            fn decode(&mut self, buf: &mut DecodeBuf<'_>) -> Result<Option<Bytes>, Status> {
                Ok(Some(buf.copy_to_bytes(buf.remaining())))
            }
        }

        for status in ["0", "7"] {
            let mut trailers = trailers();
            trailers.insert("grpc-status", status.parse().unwrap());
            trailers.insert("x-checksum", "abc123".parse().unwrap());
            let mut wire = BytesMut::from(message().as_ref());
            wire.extend_from_slice(&make_trailers_frame(trailers));
            let body =
                GrpcWebCall::client_response(Frames(VecDeque::from([Frame::data(wire.freeze())])))
                    .fuse();
            let mut stream = Streaming::new_response(
                BytesDecoder,
                body,
                rama_http_types::StatusCode::OK,
                None,
                None,
            );
            assert_eq!(
                stream.message().await.unwrap(),
                Some(Bytes::from_static(b"a"))
            );
            if status == "0" {
                assert!(stream.message().await.unwrap().is_none());
                let metadata = stream.trailers().await.unwrap().unwrap();
                assert_eq!(metadata.get("x-checksum").unwrap(), "abc123");
            } else {
                let error = stream.message().await.unwrap_err();
                assert_eq!(error.code(), crate::Code::PermissionDenied);
            }
        }
    }
}
