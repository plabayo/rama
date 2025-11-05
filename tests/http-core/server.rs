#![allow(unused)]
// TODO ^ remove

use std::convert::Infallible;
use std::io::{self, Read, Write};
use std::net::TcpListener as StdTcpListener;
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use futures_channel::oneshot;
use rama::ServiceInput;
use rama::error::{BoxError, OpaqueError};
use rama::extensions::Extensions;
use rama::extensions::ExtensionsMut;
use rama::futures::future::{self, Either, FutureExt};
use rama::http::body::util::{BodyExt, Empty, Full, StreamBody, combinators::BoxBody};
use rama::http::core::h2::client::SendRequest;
use rama::http::core::h2::{RecvStream, SendStream};
use rama::http::core::service::RamaHttpService;
use rama::http::header::{HeaderMap, HeaderName, HeaderValue};
use rama::rt::Executor;
use rama_core::bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener as TkTcpListener, TcpListener, TcpStream as TkTcpStream};

use rama::http::core::body::{Body, Incoming as IncomingBody};
use rama::http::core::server::conn::{http1, http2};
use rama::http::{Method, Request, Response, StatusCode, Uri, Version};
use rama::service::{Service, service_fn};
use tokio::pin;

use super::support;

#[test]
fn get_should_ignore_body() {
    let server = serve();

    let mut req = connect(server.addr());
    // Connection: close = don't try to parse the body as a new request
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
        I shouldn't be read.\r\n\
    ",
    )
    .unwrap();
    let _ = req.read(&mut [0; 256]).unwrap();

    assert_eq!(server.body(), b"");
}

#[test]
fn get_with_body() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Content-Length: 19\r\n\
        \r\n\
        I'm a good request.\r\n\
    ",
    )
    .unwrap();
    let _ = req.read(&mut [0; 256]).unwrap();

    // note: doesn't include trailing \r\n, cause Content-Length wasn't 21
    assert_eq!(server.body(), b"I'm a good request.");
}

mod response_body_lengths {
    use rama_http::StreamingBody;

    use super::*;

    struct TestCase {
        version: usize,
        headers: &'static [(&'static str, &'static str)],
        body: Bd,
        expects_chunked: bool,
        expects_con_len: bool,
    }

    enum Bd {
        Known(&'static str),
        Unknown(&'static str),
    }

    #[allow(clippy::needless_pass_by_value)]
    fn run_test(case: TestCase) {
        assert!(
            case.version == 0 || case.version == 1,
            "TestCase.version must 0 or 1"
        );

        let server = serve();

        let mut reply = server.reply();
        for header in case.headers {
            reply = reply.header(header.0, header.1);
        }

        let body_str = match case.body {
            Bd::Known(b) => {
                reply.body(b);
                b
            }
            Bd::Unknown(b) => {
                let body = rama::futures::stream::once(async move { Ok(b.into()) });
                reply.body_stream(body);
                b
            }
        };

        let mut req = connect(server.addr());
        write!(
            req,
            "\
             GET / HTTP/1.{}\r\n\
             Host: example.domain\r\n\
             Connection: close\r\n\
             \r\n\
             ",
            case.version
        )
        .expect("request write");
        let mut body = String::new();
        req.read_to_string(&mut body).unwrap();

        assert_eq!(
            case.expects_chunked,
            has_header(&body, "transfer-encoding:"),
            "expects_chunked, headers = {body:?}",
        );

        assert_eq!(
            case.expects_chunked,
            has_header(&body, "chunked\r\n"),
            "expects_chunked, headers = {body:?}",
        );

        assert_eq!(
            case.expects_con_len,
            has_header(&body, "content-length:"),
            "expects_con_len, headers = {body:?}",
        );

        let n = body.find("\r\n\r\n").unwrap() + 4;

        if case.expects_chunked {
            if !body_str.is_empty() {
                let len = body.len();
                assert_eq!(
                    &body[n + 1..n + 3],
                    "\r\n",
                    "expected body chunk size header"
                );
                assert_eq!(&body[n + 3..len - 7], body_str, "expected body");
                assert_eq!(
                    &body[len - 7..],
                    "\r\n0\r\n\r\n",
                    "expected body final chunk size header"
                );
            } else {
                assert_eq!(&body[n..], "0\r\n\r\n");
            }
        } else {
            assert_eq!(&body[n..], body_str, "expected body");
        }
    }

    #[test]
    fn fixed_response_known() {
        run_test(TestCase {
            version: 1,
            headers: &[("content-length", "11")],
            body: Bd::Known("foo bar baz"),
            expects_chunked: false,
            expects_con_len: true,
        });
    }

    #[test]
    fn fixed_response_unknown() {
        run_test(TestCase {
            version: 1,
            headers: &[("content-length", "11")],
            body: Bd::Unknown("foo bar baz"),
            expects_chunked: false,
            expects_con_len: true,
        });
    }

    #[test]
    fn fixed_response_known_empty() {
        run_test(TestCase {
            version: 1,
            headers: &[("content-length", "0")],
            body: Bd::Known(""),
            expects_chunked: false,
            expects_con_len: true,
        });
    }

    #[test]
    fn chunked_response_known() {
        run_test(TestCase {
            version: 1,
            headers: &[("transfer-encoding", "chunked")],
            // even though we know the length, don't strip user's TE header
            body: Bd::Known("foo bar baz"),
            expects_chunked: true,
            expects_con_len: false,
        });
    }

    #[test]
    fn chunked_response_known_empty() {
        run_test(TestCase {
            version: 1,
            headers: &[("transfer-encoding", "chunked")],
            body: Bd::Known(""),
            expects_chunked: true, // should still send chunked, and 0\r\n\r\n
            expects_con_len: false,
        });
    }

    #[test]
    fn chunked_response_unknown() {
        run_test(TestCase {
            version: 1,
            headers: &[("transfer-encoding", "chunked")],
            body: Bd::Unknown("foo bar baz"),
            expects_chunked: true,
            expects_con_len: false,
        });
    }

    #[test]
    fn te_response_adds_chunked() {
        run_test(TestCase {
            version: 1,
            headers: &[("transfer-encoding", "gzip")],
            body: Bd::Unknown("foo bar baz"),
            expects_chunked: true,
            expects_con_len: false,
        });
    }

    #[test]
    fn auto_response_with_unknown_length() {
        run_test(TestCase {
            version: 1,
            // no headers means trying to guess from Body
            headers: &[],
            body: Bd::Unknown("foo bar baz"),
            expects_chunked: true,
            expects_con_len: false,
        });
    }

    #[test]
    fn auto_response_with_known_length() {
        run_test(TestCase {
            version: 1,
            // no headers means trying to guess from Body
            headers: &[],
            body: Bd::Known("foo bar baz"),
            expects_chunked: false,
            expects_con_len: true,
        });
    }

    #[test]
    fn auto_response_known_empty() {
        run_test(TestCase {
            version: 1,
            // no headers means trying to guess from Body
            headers: &[],
            body: Bd::Known(""),
            expects_chunked: false,
            expects_con_len: true,
        });
    }

    #[test]
    fn http10_auto_response_with_unknown_length() {
        run_test(TestCase {
            version: 0,
            // no headers means trying to guess from Body
            headers: &[],
            body: Bd::Unknown("foo bar baz"),
            expects_chunked: false,
            expects_con_len: false,
        });
    }

    #[test]
    fn http10_chunked_response() {
        run_test(TestCase {
            version: 0,
            // http/1.0 should strip this header
            headers: &[("transfer-encoding", "chunked")],
            // even when we don't know the length
            body: Bd::Unknown("foo bar baz"),
            expects_chunked: false,
            expects_con_len: false,
        });
    }

    #[tokio::test]
    async fn http2_auto_response_with_known_length() {
        let server = serve_opts().http2().serve();
        let addr_str = format!("http://{}", server.addr());
        server.reply().body("Hello, World!");

        let client = TestClient::new().http2_only();
        let uri = addr_str
            .parse::<rama::http::Uri>()
            .expect("server addr should parse");

        let res = client.get(uri).await.unwrap();
        assert_eq!(res.headers().get("content-length").unwrap(), "13");
        assert_eq!(res.body().size_hint().exact(), Some(13));
    }

    #[tokio::test]
    async fn http2_auto_response_with_conflicting_lengths() {
        let server = serve_opts().http2().serve();
        let addr_str = format!("http://{}", server.addr());
        server
            .reply()
            .header("content-length", "10")
            .body("Hello, World!");

        let client = TestClient::new().http2_only();
        let uri = addr_str
            .parse::<rama::http::Uri>()
            .expect("server addr should parse");

        let res = client.get(uri).await.unwrap();
        assert_eq!(res.headers().get("content-length").unwrap(), "10");
        assert_eq!(res.body().size_hint().exact(), Some(10));
    }

    #[tokio::test]
    async fn http2_implicit_empty_size_hint() {
        let server = serve_opts().http2().serve();
        let addr_str = format!("http://{}", server.addr());
        server.reply();

        let client = TestClient::new().http2_only();
        let uri = addr_str
            .parse::<rama::http::Uri>()
            .expect("server addr should parse");

        let res = client.get(uri).await.unwrap();
        assert_eq!(res.headers().get("content-length"), None);
        assert_eq!(res.body().size_hint().exact(), Some(0));
    }
}

#[test]
fn get_response_custom_reason_phrase() {
    let server = serve();
    server.reply().reason_phrase("Cool");
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();

    let mut lines = response.lines();
    assert_eq!(lines.next(), Some("HTTP/1.1 200 Cool"));

    let mut lines = lines.skip_while(|line| !line.is_empty());
    assert_eq!(lines.next(), Some(""));
    assert_eq!(lines.next(), None);
}

#[test]
fn get_chunked_response_with_ka() {
    let foo_bar = b"foo bar baz";
    let foo_bar_chunk = b"\r\nfoo bar baz\r\n0\r\n\r\n";
    let server = serve();
    server
        .reply()
        .header("transfer-encoding", "chunked")
        .body(foo_bar);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        \r\n\
    ",
    )
    .expect("writing 1");

    read_until(&mut req, |buf| buf.ends_with(foo_bar_chunk)).expect("reading 1");

    // try again!

    let quux = b"zar quux";
    server
        .reply()
        .header("content-length", quux.len().to_string())
        .body(quux);
    req.write_all(
        b"\
        GET /quux HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .expect("writing 2");

    read_until(&mut req, |buf| buf.ends_with(quux)).expect("reading 2");
}

#[test]
fn post_with_content_length_body() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        Content-Length: 5\r\n\
        \r\n\
        hello\
    ",
    )
    .unwrap();
    let _ = req.read(&mut [0; 256]).unwrap();

    assert_eq!(server.body(), b"hello");
}

#[test]
fn post_with_invalid_prefix_content_length() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        Content-Length: +5\r\n\
        \r\n\
        hello\
    ",
    )
    .unwrap();

    let mut buf = [0; 256];
    let _n = req.read(&mut buf).unwrap();
    let expected = "HTTP/1.1 400 Bad Request\r\n";
    assert_eq!(s(&buf[..expected.len()]), expected);
}

#[test]
fn post_with_chunked_body() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Transfer-Encoding: chunked\r\n\
        \r\n\
        1\r\n\
        q\r\n\
        2\r\n\
        we\r\n\
        2\r\n\
        rt\r\n\
        0\r\n\
        \r\n\
    ",
    )
    .unwrap();
    let _ = req.read(&mut [0; 256]).unwrap();

    assert_eq!(server.body(), b"qwert");
}

#[test]
fn post_with_chunked_overflow() {
    use std::error::Error as _;
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Transfer-Encoding: chunked\r\n\
        \r\n\
        f0000000000000003\r\n\
        abc\r\n\
        0\r\n\
        \r\n\
        GET /sneaky HTTP/1.1\r\n\
        \r\n\
    ",
    )
    .unwrap();
    let _ = req.read(&mut [0; 256]).unwrap();

    let err = server.body_err().source().unwrap().to_string();
    assert!(
        err.contains("overflow"),
        "error should be overflow: {err:?}",
    );
}

#[test]
fn post_with_incomplete_body() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Content-Length: 10\r\n\
        \r\n\
        12345\
    ",
    )
    .expect("write");
    req.shutdown(Shutdown::Write).expect("shutdown write");

    server.body_err();

    let _ = req.read(&mut [0; 256]).expect("read");
}

#[test]
fn post_with_chunked_missing_final_digit() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        transfer-encoding: chunked\r\n\
        \r\n\
        1\r\n\
        Z\r\n\
        \r\n\r\n\
    ",
    )
    .expect("write");

    server.body_err();

    let _ = req.read(&mut [0; 256]).expect("read");
}

#[test]
fn head_response_can_send_content_length() {
    let server = serve();
    server.reply().header("content-length", "1024");
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        HEAD / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();

    assert!(response.contains("content-length: 1024\r\n"));

    let mut lines = response.lines();
    assert_eq!(lines.next(), Some("HTTP/1.1 200 OK"));

    let mut lines = lines.skip_while(|line| !line.is_empty());
    assert_eq!(lines.next(), Some(""));
    assert_eq!(lines.next(), None);
}

#[test]
fn head_response_doesnt_send_body() {
    let foo_bar = b"foo bar baz";
    let server = serve();
    server.reply().body(foo_bar);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        HEAD / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();

    assert!(response.contains("content-length: 11\r\n"));

    let mut lines = response.lines();
    assert_eq!(lines.next(), Some("HTTP/1.1 200 OK"));

    let mut lines = lines.skip_while(|line| !line.is_empty());
    assert_eq!(lines.next(), Some(""));
    assert_eq!(lines.next(), None);
}

#[test]
fn response_does_not_set_chunked_if_body_not_allowed() {
    let server = serve();
    server
        .reply()
        .status(rama::http::StatusCode::NOT_MODIFIED)
        .header("transfer-encoding", "chunked");
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();

    assert!(!response.contains("transfer-encoding"));

    let mut lines = response.lines();
    assert_eq!(lines.next(), Some("HTTP/1.1 304 Not Modified"));

    // no body or 0\r\n\r\n
    let mut lines = lines.skip_while(|line| !line.is_empty());
    assert_eq!(lines.next(), Some(""));
    assert_eq!(lines.next(), None);
}

#[test]
fn keep_alive() {
    let foo_bar = b"foo bar baz";
    let server = serve();
    server
        .reply()
        .header("content-length", foo_bar.len().to_string())
        .body(foo_bar);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        \r\n\
    ",
    )
    .expect("writing 1");

    read_until(&mut req, |buf| buf.ends_with(foo_bar)).expect("reading 1");

    // try again!

    let quux = b"zar quux";
    server
        .reply()
        .header("content-length", quux.len().to_string())
        .body(quux);
    req.write_all(
        b"\
        GET /quux HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .expect("writing 2");

    read_until(&mut req, |buf| buf.ends_with(quux)).expect("reading 2");
}

#[test]
fn http_10_keep_alive() {
    let foo_bar = b"foo bar baz";
    let server = serve();
    // Response version 1.1 with no keep-alive header will downgrade to 1.0 when served
    server
        .reply()
        .header("content-length", foo_bar.len().to_string())
        .body(foo_bar);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.0\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        \r\n\
    ",
    )
    .expect("writing 1");

    // Connection: keep-alive header should be added when downgrading to a 1.0 response
    let res = read_until(&mut req, |buf| buf.ends_with(foo_bar)).expect("reading 1");

    let sres = s(&res);
    assert!(
        sres.contains("connection: keep-alive\r\n"),
        "HTTP/1.0 response should have sent keep-alive: {sres:?}",
    );

    // try again!

    let quux = b"zar quux";
    server
        .reply()
        .header("content-length", quux.len().to_string())
        .body(quux);
    req.write_all(
        b"\
        GET /quux HTTP/1.0\r\n\
        Host: example.domain\r\n\
        \r\n\
    ",
    )
    .expect("writing 2");

    read_until(&mut req, |buf| buf.ends_with(quux)).expect("reading 2");
}

#[test]
fn http_10_close_on_no_ka() {
    let foo_bar = b"foo bar baz";
    let server = serve();

    // A server response with version 1.0 but no keep-alive header
    server
        .reply()
        .version(Version::HTTP_10)
        .header("content-length", foo_bar.len().to_string())
        .body(foo_bar);
    let mut req = connect(server.addr());

    // The client request with version 1.0 that may have the keep-alive header
    req.write_all(
        b"\
        GET / HTTP/1.0\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        \r\n\
    ",
    )
    .expect("writing 1");

    // server isn't keeping-alive, so the socket should be closed after
    // writing the response. thus, read_to_end should succeed.
    let mut buf = Vec::new();
    req.read_to_end(&mut buf).expect("reading 1");

    assert!(buf.ends_with(foo_bar));
    let sbuf = s(&buf);
    assert!(
        !sbuf.contains("connection: keep-alive\r\n"),
        "HTTP/1.0 response shouldn't have sent keep-alive: {sbuf:?}",
    );
}

#[test]
fn disable_keep_alive() {
    let foo_bar = b"foo bar baz";
    let server = serve_opts().keep_alive(false).serve();
    server
        .reply()
        .header("content-length", foo_bar.len().to_string())
        .body(foo_bar);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        \r\n\
    ",
    )
    .expect("writing 1");

    // server isn't keeping-alive, so the socket should be closed after
    // writing the response. thus, read_to_end should succeed.
    let mut buf = Vec::new();
    req.read_to_end(&mut buf).expect("reading 1");
    assert!(buf.ends_with(foo_bar));
}

#[test]
fn header_connection_close() {
    let foo_bar = b"foo bar baz";
    let server = serve();
    server
        .reply()
        .header("content-length", foo_bar.len().to_string())
        .header("connection", "close")
        .body(foo_bar);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        \r\n\
    ",
    )
    .expect("writing 1");

    // server isn't keeping-alive, so the socket should be closed after
    // writing the response. thus, read_to_end should succeed.
    let mut buf = Vec::new();
    req.read_to_end(&mut buf).expect("reading 1");
    assert!(buf.ends_with(foo_bar));
    let sbuf = s(&buf);
    assert!(
        sbuf.contains("connection: close\r\n"),
        "response should have sent close: {sbuf:?}",
    );
}

#[test]
fn expect_continue_sends_100() {
    let server = serve();
    let mut req = connect(server.addr());
    server.reply();

    req.write_all(
        b"\
        POST /foo HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Expect: 100-continue\r\n\
        Content-Length: 5\r\n\
        Connection: Close\r\n\
        \r\n\
    ",
    )
    .expect("write 1");

    let msg = b"HTTP/1.1 100 Continue\r\n\r\n";
    let mut buf = vec![0; msg.len()];
    req.read_exact(&mut buf).expect("read 1");
    assert_eq!(buf, msg);

    let msg = b"hello";
    req.write_all(msg).expect("write 2");

    let mut body = String::new();
    req.read_to_string(&mut body).expect("read 2");

    let body = server.body();
    assert_eq!(body, msg);
}

#[test]
fn expect_continue_accepts_upper_cased_expectation() {
    let server = serve();
    let mut req = connect(server.addr());
    server.reply();

    req.write_all(
        b"\
        POST /foo HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Expect: 100-Continue\r\n\
        Content-Length: 5\r\n\
        Connection: Close\r\n\
        \r\n\
    ",
    )
    .expect("write 1");

    let msg = b"HTTP/1.1 100 Continue\r\n\r\n";
    let mut buf = vec![0; msg.len()];
    req.read_exact(&mut buf).expect("read 1");
    assert_eq!(buf, msg);

    let msg = b"hello";
    req.write_all(msg).expect("write 2");

    let mut body = String::new();
    req.read_to_string(&mut body).expect("read 2");

    let body = server.body();
    assert_eq!(body, msg);
}

#[test]
fn expect_continue_but_http_10_is_ignored() {
    let server = serve();
    let mut req = connect(server.addr());
    server.reply();

    req.write_all(
        b"\
        POST /foo HTTP/1.0\r\n\
        Host: example.domain\r\n\
        Expect: 100-Continue\r\n\
        Content-Length: 5\r\n\
        Connection: Close\r\n\
        \r\n\
    ",
    )
    .expect("write 1");

    let msg = b"hello";
    req.write_all(msg).expect("write 2");

    let s_line = b"HTTP/1.0 200 OK\r\n";
    let mut buf = vec![0; s_line.len()];
    req.read_exact(&mut buf).expect("read 1");
    assert_eq!(buf, s_line);

    let mut body = String::new();
    req.read_to_string(&mut body).expect("read 2");

    let body = server.body();
    assert_eq!(body, msg);
}

#[test]
fn expect_continue_but_no_body_is_ignored() {
    let server = serve();
    let mut req = connect(server.addr());
    server.reply();

    // no content-length or transfer-encoding means no body!
    req.write_all(
        b"\
        POST /foo HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Expect: 100-continue\r\n\
        Connection: Close\r\n\
        \r\n\
    ",
    )
    .expect("write");

    let expected = "HTTP/1.1 200 OK\r\n";
    let mut resp = String::new();
    req.read_to_string(&mut resp).expect("read");

    assert_eq!(&resp[..expected.len()], expected);
}

fn setup_tcp_listener() -> (TcpListener, SocketAddr) {
    let listener = tcp_bind(&"127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    (listener, addr)
}

#[tokio::test]
async fn expect_continue_waits_for_body_poll() {
    let (listener, addr) = setup_tcp_listener();

    let child = thread::spawn(move || {
        let mut tcp = connect(&addr);

        tcp.write_all(
            b"\
            POST /foo HTTP/1.1\r\n\
            Host: example.domain\r\n\
            Expect: 100-continue\r\n\
            Content-Length: 100\r\n\
            Connection: Close\r\n\
            \r\n\
        ",
        )
        .expect("write");

        let expected = "HTTP/1.1 400 Bad Request\r\n";
        let mut resp = String::new();
        tcp.read_to_string(&mut resp).expect("read");

        assert_eq!(&resp[..expected.len()], expected);
    });

    let (socket, _) = listener.accept().await.expect("accept");
    let socket = ServiceInput::new(socket);

    http1::Builder::new()
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(async |req: Request| {
                assert_eq!(req.headers()["expect"], "100-continue");
                // But! We're never going to poll the body!
                drop(req);
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(rama::http::Body::empty())
                        .unwrap(),
                )
            })),
        )
        .await
        .expect("serve_connection");

    child.join().expect("client thread");
}

#[test]
fn pipeline_disabled() {
    let server = serve();
    let mut req = connect(server.addr());
    server
        .reply()
        .header("content-length", "12")
        .body("Hello World!");
    server
        .reply()
        .header("content-length", "12")
        .body("Hello World!");

    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        \r\n\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        \r\n\
    ",
    )
    .expect("write 1");

    let mut buf = vec![0; 4096];
    let n = req.read(&mut buf).expect("read 1");
    assert_ne!(n, 0);
    // Woah there. What?
    //
    // This test is wishy-washy because of race conditions in access of the
    // socket. The test is still useful, since it allows for the responses
    // to be received in 2 reads. But it might sometimes come in 1 read.
    //
    // TODO: add in a delay to the `ServeReply` interface, to allow this
    // delay to prevent the 2 writes from happening before this test thread
    // can read from the socket.
    if let Ok(n) = req.read(&mut buf) {
        // won't be 0, because we didn't say to close, and so socket
        // will be open until `server` drops
        assert_ne!(n, 0);
    }
}

#[test]
fn pipeline_enabled() {
    let server = serve_opts().pipeline(true).serve();
    let mut req = connect(server.addr());
    server
        .reply()
        .header("content-length", "12")
        .body("Hello World\n");
    server
        .reply()
        .header("content-length", "12")
        .body("Hello World\n");

    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        \r\n\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .expect("write 1");

    let mut buf = vec![0; 4096];
    let n = req.read(&mut buf).expect("read 1");
    assert_ne!(n, 0);

    {
        let mut lines = buf.split(|&b| b == b'\n');
        assert_eq!(s(lines.next().unwrap()), "HTTP/1.1 200 OK\r");
        assert_eq!(s(lines.next().unwrap()), "content-length: 12\r");
        lines.next().unwrap(); // Date
        assert_eq!(s(lines.next().unwrap()), "\r");
        assert_eq!(s(lines.next().unwrap()), "Hello World");

        assert_eq!(s(lines.next().unwrap()), "HTTP/1.1 200 OK\r");
        assert_eq!(s(lines.next().unwrap()), "content-length: 12\r");
        // close because the last request said to close
        assert_eq!(s(lines.next().unwrap()), "connection: close\r");
        lines.next().unwrap(); // Date
        assert_eq!(s(lines.next().unwrap()), "\r");
        assert_eq!(s(lines.next().unwrap()), "Hello World");
    }

    // with pipeline enabled, both responses should have been in the first read
    // so a second read should be EOF
    let n = req.read(&mut buf).expect("read 2");
    assert_eq!(n, 0);
}

#[test]
fn http_10_request_receives_http_10_response() {
    let server = serve();

    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.0\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let expected = "HTTP/1.0 200 OK\r\ncontent-length: 0\r\n";
    let mut buf = [0; 256];
    let n = req.read(&mut buf).unwrap();
    assert!(n >= expected.len(), "read: {:?} >= {:?}", n, expected.len());
    assert_eq!(s(&buf[..expected.len()]), expected);
}

#[test]
fn http_11_uri_too_long() {
    let server = serve();

    let long_path = "a".repeat(65534);
    let request_line = format!("GET /{long_path} HTTP/1.1\r\n\r\n");

    let mut req = connect(server.addr());
    req.write_all(request_line.as_bytes()).unwrap();

    let expected = "HTTP/1.1 414 URI Too Long\r\nconnection: close\r\ncontent-length: 0\r\n";
    let mut buf = [0; 256];
    let n = req.read(&mut buf).unwrap();
    assert!(n >= expected.len(), "read: {n:?} >= {:?}", expected.len());
    assert_eq!(s(&buf[..expected.len()]), expected);
}

#[tokio::test]
async fn disable_keep_alive_mid_request() {
    let (listener, addr) = setup_tcp_listener();
    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = mpsc::channel();

    let child = thread::spawn(move || {
        let mut req = connect(&addr);
        req.write_all(b"GET / HTTP/1.1\r\n").unwrap();
        thread::sleep(Duration::from_millis(10));
        tx1.send(()).unwrap();
        rx2.recv().unwrap();
        req.write_all(b"Host: localhost\r\n\r\n").unwrap();
        let mut buf = vec![];
        req.read_to_end(&mut buf).unwrap();
        assert!(
            buf.starts_with(b"HTTP/1.1 200 OK\r\n"),
            "should receive OK response, but buf: {buf:?}",
        );
        let sbuf = s(&buf);
        assert!(
            sbuf.contains("connection: close\r\n"),
            "response should have sent close: {sbuf:?}",
        );
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let srv = http1::Builder::new().serve_connection(socket, RamaHttpService::new(HelloWorld));
    future::try_select(srv, rx1)
        .then(|r| match r {
            Ok(Either::Left(_)) => panic!("expected rx first"),
            Ok(Either::Right(((), mut conn))) => {
                Pin::new(&mut conn).graceful_shutdown();
                tx2.send(()).unwrap();
                conn
            }
            Err(Either::Left((e, _))) => panic!("unexpected error {e}"),
            Err(Either::Right((e, _))) => panic!("unexpected error {e}"),
        })
        .await
        .unwrap();

    child.join().unwrap();
}

#[tokio::test]
async fn disable_keep_alive_post_request() {
    let (listener, addr) = setup_tcp_listener();
    let (tx1, rx1) = oneshot::channel();

    let child = thread::spawn(move || {
        let mut req = connect(&addr);
        req.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            Host: localhost\r\n\
            \r\n\
        ",
        )
        .unwrap();

        read_until(&mut req, |buf| buf.ends_with(HELLO.as_bytes())).expect("reading 1");

        // Connection should get closed *after* tx is sent on
        tx1.send(()).unwrap();

        let nread = req.read(&mut [0u8; 1024]).expect("keep-alive reading");
        assert_eq!(nread, 0);
    });

    let dropped = Dropped::new();
    let dropped2 = dropped.clone();
    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let transport = DebugStream {
        stream: socket,
        _debug: dropped2,
    };
    let transport = ServiceInput::new(transport);
    let server =
        http1::Builder::new().serve_connection(transport, RamaHttpService::new(HelloWorld));
    let fut = future::try_select(server, rx1).then(|r| match r {
        Ok(Either::Left(_)) => panic!("expected rx first"),
        Ok(Either::Right(((), mut conn))) => {
            Pin::new(&mut conn).graceful_shutdown();
            conn
        }
        Err(Either::Left((e, _))) => panic!("unexpected error {e}"),
        Err(Either::Right((e, _))) => panic!("unexpected error {e}"),
    });

    assert!(!dropped.load());
    fut.await.unwrap();
    assert!(dropped.load());
    child.join().unwrap();
}

#[tokio::test]
async fn http1_graceful_shutdown_after_upgrade() {
    let (listener, addr) = setup_tcp_listener();
    let (read_101_tx, read_101_rx) = oneshot::channel();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            Upgrade: foobar\r\n\
            Connection: upgrade\r\n\
            \r\n\
            eagerly optimistic\
        ",
        )
        .expect("write 1");
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).expect("read 1");

        let response = s(&buf);
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(!has_header(response, "content-length"));
        let _ = read_101_tx.send(());
    });

    let (upgrades_tx, upgrades_rx) = mpsc::channel();
    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);
        let _ = upgrades_tx.send(on_upgrade);
        future::ok::<_, Infallible>(
            Response::builder()
                .status(101)
                .header("upgrade", "foobar")
                .body(rama::http::Body::empty())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);

    let mut conn = http1::Builder::new()
        .serve_connection(socket, svc)
        .with_upgrades();
    (&mut conn).await.unwrap();

    let on_upgrade = upgrades_rx.recv().unwrap();

    // wait so that we don't write until other side saw 101 response
    read_101_rx.await.unwrap();

    let upgraded = on_upgrade.await.expect("on_upgrade");
    let parts = upgraded.downcast::<ServiceInput<TkTcpStream>>().unwrap();
    assert_eq!(parts.read_buf, "eagerly optimistic");

    pin!(conn);
    // graceful shutdown doesn't cause issues or panic. It should be ignored after upgrade
    conn.as_mut().graceful_shutdown();
}

#[tokio::test]
async fn empty_parse_eof_does_not_return_error() {
    let (listener, addr) = setup_tcp_listener();
    thread::spawn(move || {
        let _tcp = connect(&addr);
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(socket, RamaHttpService::new(HelloWorld))
        .await
        .expect("empty parse eof is ok");
}

#[tokio::test]
async fn nonempty_parse_eof_returns_error() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"GET / HTTP/1.1").unwrap();
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(socket, RamaHttpService::new(HelloWorld))
        .await
        .expect_err("partial parse eof is error");
}

#[tokio::test]
async fn http1_allow_half_close() {
    let (listener, addr) = setup_tcp_listener();

    let t1 = thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        tcp.shutdown(::std::net::Shutdown::Write).expect("SHDN_WR");

        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).unwrap();
        let expected = "HTTP/1.1 200 OK\r\n";
        assert_eq!(s(&buf[..expected.len()]), expected);
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .half_close(true)
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(|_| {
                tokio::time::sleep(Duration::from_millis(500))
                    .map(|_| Ok::<_, Infallible>(Response::new(rama::http::Body::empty())))
            })),
        )
        .await
        .unwrap();

    t1.join().expect("client thread");
}

#[tokio::test]
async fn disconnect_after_reading_request_before_responding() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .half_close(false)
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(|_| {
                tokio::time::sleep(Duration::from_secs(2)).map(
                    |_| -> Result<Response<IncomingBody>, Infallible> {
                        panic!("response future should have been dropped");
                    },
                )
            })),
        )
        .await
        .expect_err("socket disconnected");
}

#[tokio::test]
async fn returning_1xx_response_is_error() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).unwrap();

        let expected = "HTTP/1.1 500 ";
        assert_eq!(s(&buf[..expected.len()]), expected);
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(async |_| {
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::CONTINUE)
                        .body(rama::http::Body::empty())
                        .unwrap(),
                )
            })),
        )
        .await
        .expect_err("1xx status code should error");
}

#[test]
fn header_name_too_long() {
    let server = serve();

    let mut req = connect(server.addr());
    let mut write = Vec::with_capacity(1024 * 66);
    write.extend_from_slice(b"GET / HTTP/1.1\r\n");
    write.extend_from_slice(vec![b'x'; 1024 * 64].as_slice());
    write.extend_from_slice(b": foo\r\n\r\n");
    req.write_all(&write).unwrap();

    let mut buf = [0; 1024];
    let n = req.read(&mut buf).unwrap();
    assert!(s(&buf[..n]).starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"));
}

#[tokio::test]
async fn header_read_timeout_slow_writes() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
        ",
        )
        .expect("write 1");
        thread::sleep(Duration::from_secs(3));
        tcp.write_all(
            b"\
            Something: 1\r\n\
        ",
        )
        .expect("write 2");
        thread::sleep(Duration::from_secs(6));
        tcp.write_all(
            b"\
            Works: 0\r\n\
            \r\n
        ",
        )
        .expect_err("write 3");
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let conn = http1::Builder::new()
        .header_read_timeout(Duration::from_secs(5))
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(|_| {
                let res = Response::builder()
                    .status(StatusCode::OK)
                    .body(rama::http::Body::empty())
                    .unwrap();
                future::ready(Ok::<_, Infallible>(res))
            })),
        );
    conn.without_shutdown().await.expect_err("header timeout");
}

#[tokio::test]
async fn header_read_timeout_starts_immediately() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        thread::sleep(Duration::from_secs(3));
        let mut buf = [0u8; 256];
        let n = tcp.read(&mut buf).expect("read 1");
        assert_eq!(n, 0); //eof
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let conn = http1::Builder::new()
        .header_read_timeout(Duration::from_secs(2))
        .serve_connection(socket, RamaHttpService::new(unreachable_service()));
    assert!(conn.await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn header_read_timeout_slow_writes_multiple_requests() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);

        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
        ",
        )
        .expect("write 1");
        thread::sleep(Duration::from_secs(3));
        tcp.write_all(
            b"\
            Something: 1\r\n\
            \r\n\
        ",
        )
        .expect("write 2");

        thread::sleep(Duration::from_secs(3));

        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
        ",
        )
        .expect("write 3");
        thread::sleep(Duration::from_secs(3));
        tcp.write_all(
            b"\
            Something: 1\r\n\
            \r\n\
        ",
        )
        .expect("write 4");

        thread::sleep(Duration::from_secs(6));

        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            Something: 1\r\n\
        ",
        )
        .expect("write 5");
        thread::sleep(Duration::from_secs(6));
        tcp.write_all(
            b"\
            Works: 0\r\n\
            \r\n\
        ",
        )
        .expect_err("write 6");
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let conn = http1::Builder::new()
        .header_read_timeout(Duration::from_secs(5))
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(|_| {
                let res = Response::builder()
                    .status(200)
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                future::ready(Ok::<_, Infallible>(res))
            })),
        );
    assert!(conn.without_shutdown().await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn header_read_timeout_as_idle_timeout() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);

        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            \r\n\
        ",
        )
        .expect("request 1");

        thread::sleep(Duration::from_secs(6));

        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            \r\n\
        ",
        )
        .expect_err("request 2");
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let conn = http1::Builder::new()
        .header_read_timeout(Duration::from_secs(3))
        .serve_connection(
            socket,
            RamaHttpService::new(service_fn(|_| {
                let res = Response::builder()
                    .status(200)
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                future::ready(Ok::<_, Infallible>(res))
            })),
        );
    assert!(conn.without_shutdown().await.unwrap_err().is_timeout());
}

#[tokio::test]
async fn upgrades() {
    let (listener, addr) = setup_tcp_listener();
    let (tx, rx) = oneshot::channel();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            Upgrade: foobar\r\n\
            Connection: upgrade\r\n\
            \r\n\
            eagerly optimistic\
        ",
        )
        .expect("write 1");
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).expect("read 1");

        let expected = "HTTP/1.1 101 Switching Protocols\r\n";
        assert_eq!(s(&buf[..expected.len()]), expected);
        let _ = tx.send(());

        let n = tcp.read(&mut buf).expect("read 2");
        assert_eq!(s(&buf[..n]), "foo=bar");
        tcp.write_all(b"bar=foo").expect("write 2");
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let conn = http1::Builder::new().serve_connection(
        socket,
        RamaHttpService::new(service_fn(|_| {
            let res = Response::builder()
                .status(101)
                .header("upgrade", "foobar")
                .body(Empty::<Bytes>::new())
                .unwrap();
            future::ready(Ok::<_, Infallible>(res))
        })),
    );

    let parts = conn.without_shutdown().await.unwrap();
    assert_eq!(parts.read_buf, "eagerly optimistic");

    // wait so that we don't write until other side saw 101 response
    rx.await.unwrap();

    let mut io = parts.io;
    io.write_all(b"foo=bar").await.unwrap();
    let mut vec = vec![];
    io.read_to_end(&mut vec).await.unwrap();
    assert_eq!(vec, b"bar=foo");
}

#[tokio::test]
async fn http_connect() {
    let (listener, addr) = setup_tcp_listener();
    let (tx, rx) = oneshot::channel();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(
            b"\
            CONNECT localhost:80 HTTP/1.1\r\n\
            \r\n\
            eagerly optimistic\
        ",
        )
        .expect("write 1");
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).expect("read 1");

        let expected = "HTTP/1.1 200 OK\r\n";
        assert_eq!(s(&buf[..expected.len()]), expected);
        let _ = tx.send(());

        let n = tcp.read(&mut buf).expect("read 2");
        assert_eq!(s(&buf[..n]), "foo=bar");
        tcp.write_all(b"bar=foo").expect("write 2");
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    let conn = http1::Builder::new().serve_connection(
        socket,
        RamaHttpService::new(service_fn(|_| {
            let res = Response::builder()
                .status(200)
                .body(Empty::<Bytes>::new())
                .unwrap();
            future::ready(Ok::<_, Infallible>(res))
        })),
    );

    let parts = conn.without_shutdown().await.unwrap();
    assert_eq!(parts.read_buf, "eagerly optimistic");

    // wait so that we don't write until other side saw 101 response
    rx.await.unwrap();

    let mut io = parts.io;
    io.write_all(b"foo=bar").await.unwrap();
    let mut vec = vec![];
    io.read_to_end(&mut vec).await.unwrap();
    assert_eq!(vec, b"bar=foo");
}

#[tokio::test]
async fn upgrades_new() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (listener, addr) = setup_tcp_listener();
    let (read_101_tx, read_101_rx) = oneshot::channel();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(
            b"\
            GET / HTTP/1.1\r\n\
            Upgrade: foobar\r\n\
            Connection: upgrade\r\n\
            \r\n\
            eagerly optimistic\
        ",
        )
        .expect("write 1");
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).expect("read 1");

        let response = s(&buf);
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(!has_header(response, "content-length"));
        let _ = read_101_tx.send(());

        let n = tcp.read(&mut buf).expect("read 2");
        assert_eq!(s(&buf[..n]), "foo=bar");
        tcp.write_all(b"bar=foo").expect("write 2");
    });

    let (upgrades_tx, upgrades_rx) = mpsc::channel();
    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);
        let _ = upgrades_tx.send(on_upgrade);
        future::ok::<_, Infallible>(
            Response::builder()
                .status(101)
                .header("upgrade", "foobar")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(socket, svc)
        .with_upgrades()
        .await
        .unwrap();

    let on_upgrade = upgrades_rx.recv().unwrap();

    // wait so that we don't write until other side saw 101 response
    read_101_rx.await.unwrap();

    let upgraded = on_upgrade.await.expect("on_upgrade");
    let parts = upgraded.downcast::<ServiceInput<TkTcpStream>>().unwrap();
    assert_eq!(parts.read_buf, "eagerly optimistic");

    let mut io = parts.io;
    io.write_all(b"foo=bar").await.unwrap();
    let mut vec = vec![];
    io.read_to_end(&mut vec).await.unwrap();
    assert_eq!(s(&vec), "bar=foo");
}

#[tokio::test]
async fn upgrades_ignored() {
    let (listener, addr) = setup_tcp_listener();

    tokio::spawn(async move {
        loop {
            let svc = RamaHttpService::new(service_fn(move |req: Request| {
                assert_eq!(req.headers()["upgrade"], "yolo");
                future::ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
            }));
            let (socket, _) = listener.accept().await.unwrap();
            let socket = ServiceInput::new(socket);
            tokio::task::spawn(async move {
                http1::Builder::new()
                    .serve_connection(socket, svc)
                    .with_upgrades()
                    .await
                    .expect("server task");
            });
        }
    });

    let client = TestClient::new();
    let url = format!("http://{addr}/");

    let make_req = || {
        rama::http::Request::builder()
            .uri(&*url)
            .header("upgrade", "yolo")
            .header("connection", "upgrade")
            .body(Empty::<Bytes>::new())
            .expect("make_req")
    };

    let res1 = client.request(make_req()).await.expect("req 1");
    assert_eq!(res1.status(), 200);
    drop(res1);

    let res2 = client.request(make_req()).await.expect("req 2");
    assert_eq!(res2.status(), 200);
}

#[tokio::test]
async fn http_connect_new() {
    let (listener, addr) = setup_tcp_listener();
    let (read_200_tx, read_200_rx) = oneshot::channel();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(
            b"\
            CONNECT localhost HTTP/1.1\r\n\
            \r\n\
            eagerly optimistic\
        ",
        )
        .expect("write 1");
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).expect("read 1");

        let expected = "HTTP/1.1 200 OK\r\n";
        assert_eq!(s(&buf[..expected.len()]), expected);
        let _ = read_200_tx.send(());

        let n = tcp.read(&mut buf).expect("read 2");
        assert_eq!(s(&buf[..n]), "foo=bar");
        tcp.write_all(b"bar=foo").expect("write 2");
    });

    let (upgrades_tx, upgrades_rx) = mpsc::channel();
    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);
        let _ = upgrades_tx.send(on_upgrade);
        future::ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(socket, svc)
        .with_upgrades()
        .await
        .unwrap();

    let on_upgrade = upgrades_rx.recv().unwrap();

    // wait so that we don't write until other side saw 200
    read_200_rx.await.unwrap();

    let upgraded = on_upgrade.await.expect("on_upgrade");
    let parts = upgraded.downcast::<ServiceInput<TkTcpStream>>().unwrap();
    assert_eq!(parts.read_buf, "eagerly optimistic");

    let mut io = parts.io;
    io.write_all(b"foo=bar").await.unwrap();
    let mut vec = vec![];
    io.read_to_end(&mut vec).await.unwrap();
    assert_eq!(s(&vec), "bar=foo");
}

#[tokio::test]
async fn h2_connect() {
    let (listener, addr) = setup_tcp_listener();
    let conn = connect_async(addr).await;
    let conn = ServiceInput::new(conn);

    let (h2, connection) = rama::http::core::h2::client::handshake(conn).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut h2 = h2.ready().await.unwrap();

    async fn connect_and_recv_bread(
        h2: &mut SendRequest<Bytes>,
    ) -> (RecvStream, SendStream<Bytes>) {
        let request = Request::connect("localhost").body(()).unwrap();
        let (response, send_stream) = h2.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let bytes = body.data().await.unwrap().unwrap();
        assert_eq!(&bytes[..], b"Bread?");
        let _ = body.flow_control().release_capacity(bytes.len());

        (body, send_stream)
    }

    tokio::spawn(async move {
        let (mut recv_stream, mut send_stream) = connect_and_recv_bread(&mut h2).await;

        send_stream.send_data("Baguette!".into(), true).unwrap();

        assert!(recv_stream.data().await.unwrap().unwrap().is_empty());
    });

    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);

        tokio::spawn(async move {
            let mut upgraded = on_upgrade.await.expect("on_upgrade");
            upgraded.write_all(b"Bread?").await.unwrap();

            let mut vec = vec![];
            upgraded.read_to_end(&mut vec).await.unwrap();
            assert_eq!(s(&vec), "Baguette!");

            upgraded.shutdown().await.unwrap();
        });

        future::ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http2::Builder::new(Executor::new())
        .serve_connection(socket, svc)
        //.with_upgrades()
        .await
        .unwrap();
}

#[tokio::test]
async fn h2_connect_multiplex() {
    use rama::futures::StreamExt;
    use rama::futures::stream::FuturesUnordered;

    let (listener, addr) = setup_tcp_listener();
    let conn = connect_async(addr).await;
    let conn = ServiceInput::new(conn);

    let (h2, connection) = rama::http::core::h2::client::handshake(conn).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut h2 = h2.ready().await.unwrap();

    tokio::spawn(async move {
        let mut streams = vec![];
        for i in 0..80 {
            let request = Request::connect(format!("localhost_{}", i % 4))
                .body(())
                .unwrap();
            let (response, send_stream) = h2.send_request(request, false).unwrap();
            streams.push((i, response, send_stream));
        }

        let futures = streams
            .into_iter()
            .map(async |(i, response, mut send_stream)| {
                if i % 4 == 0 {
                    return;
                }

                let response = response.await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);

                if i % 4 == 1 {
                    return;
                }

                let mut body = response.into_body();
                let bytes = body.data().await.unwrap().unwrap();
                assert_eq!(&bytes[..], b"Bread?");
                let _ = body.flow_control().release_capacity(bytes.len());

                if i % 4 == 2 {
                    return;
                }

                send_stream.send_data("Baguette!".into(), true).unwrap();

                assert!(body.data().await.unwrap().unwrap().is_empty());
            })
            .collect::<FuturesUnordered<_>>();

        futures.for_each(future::ready).await;
    });

    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let authority = req.uri().authority().unwrap().to_string();
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);

        tokio::spawn(async move {
            let upgrade_res = on_upgrade.await;
            if authority == "localhost_0" {
                upgrade_res.expect_err("upgrade cancelled");
                return;
            }
            let mut upgraded = upgrade_res.expect("upgrade successful");

            upgraded.write_all(b"Bread?").await.unwrap();

            let mut vec = vec![];
            let read_res = upgraded.read_to_end(&mut vec).await;

            if authority == "localhost_1" || authority == "localhost_2" {
                let err = read_res.expect_err("read failed");
                assert_eq!(err.kind(), io::ErrorKind::Other);
                assert_eq!(
                    err.get_ref()
                        .unwrap()
                        .downcast_ref::<rama::http::core::h2::Error>()
                        .unwrap()
                        .reason(),
                    Some(rama::http::core::h2::Reason::CANCEL),
                );
                return;
            }

            read_res.unwrap();
            assert_eq!(s(&vec), "Baguette!");

            upgraded.shutdown().await.unwrap();
        });

        future::ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http2::Builder::new(Executor::new())
        .serve_connection(socket, svc)
        //.with_upgrades()
        .await
        .unwrap();
}

#[tokio::test]
async fn h2_connect_large_body() {
    let (listener, addr) = setup_tcp_listener();
    let conn = connect_async(addr).await;
    let conn = ServiceInput::new(conn);

    let (h2, connection) = rama::http::core::h2::client::handshake(conn).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut h2 = h2.ready().await.unwrap();

    const NO_BREAD: &str = "All work and no bread makes nox a dull boy.\n";

    async fn connect_and_recv_bread(
        h2: &mut SendRequest<Bytes>,
    ) -> (RecvStream, SendStream<Bytes>) {
        let request = Request::connect("localhost").body(()).unwrap();
        let (response, send_stream) = h2.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let bytes = body.data().await.unwrap().unwrap();
        assert_eq!(&bytes[..], b"Bread?");
        let _ = body.flow_control().release_capacity(bytes.len());

        (body, send_stream)
    }

    tokio::spawn(async move {
        let (mut recv_stream, mut send_stream) = connect_and_recv_bread(&mut h2).await;

        let large_body = Bytes::from(NO_BREAD.repeat(9000));

        send_stream.send_data(large_body.clone(), false).unwrap();
        send_stream.send_data(large_body, true).unwrap();

        assert!(recv_stream.data().await.unwrap().unwrap().is_empty());
    });

    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);

        tokio::spawn(async move {
            let mut upgraded = on_upgrade.await.expect("on_upgrade");
            upgraded.write_all(b"Bread?").await.unwrap();

            let mut vec = vec![];
            if upgraded.read_to_end(&mut vec).await.is_err() {
                return;
            }
            assert_eq!(vec.len(), NO_BREAD.len() * 9000 * 2);

            upgraded.shutdown().await.unwrap();
        });

        future::ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http2::Builder::new(Executor::new())
        .serve_connection(socket, svc)
        //.with_upgrades()
        .await
        .unwrap();
}

#[tokio::test]
async fn h2_connect_empty_frames() {
    let (listener, addr) = setup_tcp_listener();
    let conn = connect_async(addr).await;
    let conn = ServiceInput::new(conn);

    let (h2, connection) = rama::http::core::h2::client::handshake(conn).await.unwrap();
    tokio::spawn(async move {
        connection.await.unwrap();
    });
    let mut h2 = h2.ready().await.unwrap();

    async fn connect_and_recv_bread(
        h2: &mut SendRequest<Bytes>,
    ) -> (RecvStream, SendStream<Bytes>) {
        let request = Request::connect("localhost").body(()).unwrap();
        let (response, send_stream) = h2.send_request(request, false).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let mut body = response.into_body();
        let bytes = body.data().await.unwrap().unwrap();
        assert_eq!(&bytes[..], b"Bread?");
        let _ = body.flow_control().release_capacity(bytes.len());

        (body, send_stream)
    }

    tokio::spawn(async move {
        let (mut recv_stream, mut send_stream) = connect_and_recv_bread(&mut h2).await;

        send_stream.send_data("".into(), false).unwrap();
        send_stream.send_data("".into(), false).unwrap();
        send_stream.send_data("".into(), false).unwrap();
        send_stream.send_data("Baguette!".into(), false).unwrap();
        send_stream.send_data("".into(), true).unwrap();

        assert!(recv_stream.data().await.unwrap().unwrap().is_empty());
    });

    let svc = RamaHttpService::new(service_fn(move |req: Request| {
        let on_upgrade = rama::http::io::upgrade::handle_upgrade(req);

        tokio::spawn(async move {
            let mut upgraded = on_upgrade.await.expect("on_upgrade");
            upgraded.write_all(b"Bread?").await.unwrap();

            let mut vec = vec![];
            upgraded.read_to_end(&mut vec).await.unwrap();
            assert_eq!(s(&vec), "Baguette!");

            upgraded.shutdown().await.unwrap();
        });

        future::ok::<_, Infallible>(
            Response::builder()
                .status(200)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
    }));

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http2::Builder::new(Executor::new())
        .serve_connection(socket, svc)
        //.with_upgrades()
        .await
        .unwrap();
}

#[tokio::test]
async fn parse_errors_send_4xx_response() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"GE T / HTTP/1.1\r\n\r\n").unwrap();
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).unwrap();

        let expected = "HTTP/1.1 400 ";
        assert_eq!(s(&buf[..expected.len()]), expected);
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(socket, RamaHttpService::new(HelloWorld))
        .await
        .expect_err("HTTP parse error");
}

#[tokio::test]
async fn illegal_request_length_returns_400_response() {
    let (listener, addr) = setup_tcp_listener();

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"POST / HTTP/1.1\r\nContent-Length: foo\r\n\r\n")
            .unwrap();
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).unwrap();

        let expected = "HTTP/1.1 400 ";
        assert_eq!(s(&buf[..expected.len()]), expected);
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .serve_connection(socket, RamaHttpService::new(HelloWorld))
        .await
        .expect_err("illegal Content-Length should error");
}

#[test]
#[should_panic]
fn max_buf_size_panic_too_small() {
    const MAX: usize = 8191;
    http1::Builder::new().max_buf_size(MAX);
}

#[test]
fn max_buf_size_no_panic() {
    const MAX: usize = 8193;
    http1::Builder::new().max_buf_size(MAX);
}

#[tokio::test]
async fn max_buf_size() {
    let (listener, addr) = setup_tcp_listener();

    const MAX: usize = 16_000;

    thread::spawn(move || {
        let mut tcp = connect(&addr);
        tcp.write_all(b"POST /").expect("write 1");
        tcp.write_all(&[b'a'; MAX]).expect("write 2");
        let mut buf = [0; 256];
        let _ = tcp.read(&mut buf).expect("read 1");

        let expected = "HTTP/1.1 431 ";
        assert_eq!(s(&buf[..expected.len()]), expected);
    });

    let (socket, _) = listener.accept().await.unwrap();
    let socket = ServiceInput::new(socket);
    http1::Builder::new()
        .max_buf_size(MAX)
        .serve_connection(socket, RamaHttpService::new(HelloWorld))
        .await
        .expect_err("should TooLarge error");
}

#[tokio::test]
async fn graceful_shutdown_before_first_request_no_block() {
    let (listener, addr) = setup_tcp_listener();

    tokio::spawn(async move {
        let socket = listener.accept().await.unwrap().0;
        let socket = ServiceInput::new(socket);

        let future =
            http1::Builder::new().serve_connection(socket, RamaHttpService::new(HelloWorld));
        pin!(future);
        future.as_mut().graceful_shutdown();

        future.await.unwrap();
    });

    let mut stream = TkTcpStream::connect(addr).await.unwrap();

    let mut buf = vec![];

    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .expect("timed out waiting for graceful shutdown")
        .expect("error receiving response");
}

#[test]
fn streaming_body() {
    use rama::futures::StreamExt;

    // disable keep-alive so we can use read_to_end
    let server = serve_opts().keep_alive(false).serve();

    static S: &[&[u8]] = &[&[b'x'; 1_000] as &[u8]; 100] as _;
    let b = rama::futures::stream::iter(S.iter())
        .map(|&s| Ok::<_, BoxError>(Bytes::copy_from_slice(s)));
    server.reply().body_stream(b);

    let mut tcp = connect(server.addr());
    tcp.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut buf = Vec::new();
    tcp.read_to_end(&mut buf).expect("read 1");

    assert!(
        buf.starts_with(b"HTTP/1.1 200 OK\r\n"),
        "response is 200 OK"
    );
    assert_eq!(buf.len(), 100_808, "full streamed body read");
}

#[test]
fn http1_response_with_http2_version() {
    let server = serve();
    let addr_str = format!("http://{}", server.addr());

    let rt = support::runtime();

    server.reply().version(rama::http::Version::HTTP_2);

    let client = TestClient::new();
    rt.block_on({
        let uri = addr_str.parse().expect("server addr should parse");
        client.get(uri)
    })
    .unwrap();
}

#[test]
fn http1_only() {
    let server = serve_opts().serve();
    let addr_str = format!("http://{}", server.addr());

    let rt = support::runtime();

    let client = TestClient::new().http2_only();
    rt.block_on({
        let uri = addr_str.parse().expect("server addr should parse");
        client.get(uri)
    })
    .unwrap_err();
}

// NOTE: this was a test in hyper,
// but in rama-http-core we always return infallible results
// NOTE^2: can probably refactor this at some point to just work with responses instead of results..
// . .... probably would make things simpler
// #[tokio::test]
// async fn http2_service_error_sends_reset_reason() {
//     use std::error::Error;

//     let server = serve_opts().http2().serve();
//     let addr_str = format!("http://{}", server.addr());

//     server.reply().error(rama::http::core::h2::Error::from(
//         rama::http::core::h2::Reason::INADEQUATE_SECURITY,
//     ));

//     let uri = addr_str.parse().expect("server addr should parse");
//     dbg!("start");
//     let err = dbg!(TestClient::new()
//         .http2_only()
//         .get(uri)
//         .await
//         .expect_err("client.get"));

//     let h2_err = err
//         .source()
//         .expect("err.source")
//         .downcast_ref::<rama::http::core::h2::Error>()
//         .expect("downcast");

//     assert_eq!(
//         h2_err.reason(),
//         Some(rama::http::core::h2::Reason::INADEQUATE_SECURITY)
//     );
// }

#[test]
fn http2_body_user_error_sends_reset_reason() {
    use std::error::Error;
    let server = serve_opts().http2().serve();
    let addr_str = format!("http://{}", server.addr());

    let b = rama::futures::stream::once(future::err::<Bytes, BoxError>(Box::new(
        rama::http::core::h2::Error::from(rama::http::core::h2::Reason::INADEQUATE_SECURITY),
    )));
    server.reply().body_stream(b);

    let rt = support::runtime();

    let err: rama::http::core::Error = rt
        .block_on(async move {
            let client = TestClient::new().http2_only();

            let uri = addr_str.parse().expect("server addr should parse");

            let mut res = client.get(uri).await?;

            while let Some(item) = res.body_mut().frame().await {
                item?;
            }
            Ok(())
        })
        .unwrap_err();

    let h2_err = err
        .source()
        .unwrap()
        .downcast_ref::<rama::http::core::h2::Error>()
        .unwrap();

    assert_eq!(
        h2_err.reason(),
        Some(rama::http::core::h2::Reason::INADEQUATE_SECURITY)
    );
}

#[test]
fn skips_content_length_for_304_responses() {
    let server = serve();
    server
        .reply()
        .status(rama::http::StatusCode::NOT_MODIFIED)
        .body("foo");
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();
    assert!(!response.contains("content-length:"));
}

#[test]
fn skips_content_length_and_body_for_304_responses() {
    let server = serve();
    server
        .reply()
        .status(rama::http::StatusCode::NOT_MODIFIED)
        .body("foo");
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();
    assert!(!response.contains("content-length:"));
    let mut lines = response.lines();
    assert_eq!(lines.next(), Some("HTTP/1.1 304 Not Modified"));

    let mut lines = lines.skip_while(|line| !line.is_empty());
    assert_eq!(lines.next(), Some(""));
    assert_eq!(lines.next(), None);
}

#[test]
fn no_implicit_zero_content_length_for_head_responses() {
    let server = serve();
    server.reply().status(rama::http::StatusCode::OK).body([]);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        HEAD / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: close\r\n\
        \r\n\
    ",
    )
    .unwrap();

    let mut response = String::new();
    req.read_to_string(&mut response).unwrap();
    assert!(!response.contains("content-length:"));
}

#[tokio::test]
async fn http2_keep_alive_detects_unresponsive_client() {
    let (listener, addr) = setup_tcp_listener();

    // Spawn a "client" conn that only reads until EOF
    tokio::spawn(async move {
        let mut conn = connect_async(addr).await;

        // write h2 magic preface and settings frame
        conn.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("client preface");
        conn.write_all(&[
            0, 0, 0, // len
            4, // kind
            0, // flag
            0, 0, 0, // stream id
        ])
        .await
        .expect("client settings");

        // read until eof
        let mut buf = [0u8; 1024];
        loop {
            let n = conn.read(&mut buf).await.expect("client.read");
            if n == 0 {
                // eof
                break;
            }
        }
    });

    let (socket, _) = listener.accept().await.expect("accept");
    let socket = ServiceInput::new(socket);

    let err = http2::Builder::new(Executor::new())
        .keep_alive_interval(Duration::from_secs(1))
        .keep_alive_timeout(Duration::from_secs(1))
        .auto_date_header(true)
        .serve_connection(socket, RamaHttpService::new(unreachable_service()))
        .await
        .expect_err("serve_connection should error");

    assert!(err.is_timeout());
}

#[tokio::test]
async fn http2_keep_alive_with_responsive_client() {
    let (listener, addr) = setup_tcp_listener();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let socket = ServiceInput::new(socket);

        http2::Builder::new(Executor::new())
            .keep_alive_interval(Duration::from_secs(1))
            .keep_alive_timeout(Duration::from_secs(1))
            .serve_connection(socket, RamaHttpService::new(HelloWorld))
            .await
            .expect("serve_connection");
    });

    let tcp = connect_async(addr).await;
    let tcp = ServiceInput::new(tcp);
    let (mut client, conn) = rama::http::core::client::conn::http2::Builder::new(Executor::new())
        .handshake(tcp)
        .await
        .expect("http handshake");

    tokio::spawn(async move {
        conn.await.expect("client conn");
    });

    tokio::time::sleep(Duration::from_secs(4)).await;

    let req = rama::http::Request::new(Empty::<Bytes>::new());
    client.send_request(req).await.expect("client.send_request");
}

#[tokio::test]
async fn http2_check_date_header_disabled() {
    let (listener, addr) = setup_tcp_listener();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let socket = ServiceInput::new(socket);

        http2::Builder::new(Executor::new())
            .keep_alive_interval(Duration::from_secs(1))
            .auto_date_header(false)
            .keep_alive_timeout(Duration::from_secs(1))
            .serve_connection(socket, RamaHttpService::new(HelloWorld))
            .await
            .expect("serve_connection");
    });

    let tcp = connect_async(addr).await;
    let tcp = ServiceInput::new(tcp);
    let (mut client, conn) = rama::http::core::client::conn::http2::Builder::new(Executor::new())
        .handshake(tcp)
        .await
        .expect("http handshake");

    tokio::spawn(async move {
        conn.await.expect("client conn");
    });

    tokio::time::sleep(Duration::from_secs(4)).await;

    let req = rama::http::Request::new(Empty::<Bytes>::new());
    let resp = client.send_request(req).await.expect("client.send_request");

    assert!(resp.headers().get("Date").is_none());
}

fn is_ping_frame(buf: &[u8]) -> bool {
    buf[3] == 6
}

fn assert_ping_frame(buf: &[u8], len: usize) {
    // Assert the StreamId is zero
    let mut ubuf = [0; 4];
    ubuf.copy_from_slice(&buf[5..9]);
    let unpacked = u32::from_be_bytes(ubuf);
    assert_eq!(unpacked & !(1 << 31), 0);

    // Assert ACK flag is unset (only set for PONG).
    let flags = buf[4];
    assert_eq!(flags & 0x1, 0);

    // Assert total frame size
    assert_eq!(len, 17);
}

async fn write_pong_frame(conn: &mut TkTcpStream) {
    conn.write_all(&[
        0, 0, 8,   // len
        6,   // kind
        0x1, // flag
        0, 0, 0, 0, // stream id
        0x3b, 0x7c, 0xdb, 0x7a, 0x0b, 0x87, 0x16, 0xb4, // payload
    ])
    .await
    .expect("client pong");
}

#[tokio::test]
async fn http2_keep_alive_count_server_pings() {
    let (listener, addr) = setup_tcp_listener();

    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept");
        let socket = ServiceInput::new(socket);

        http2::Builder::new(Executor::new())
            .keep_alive_interval(Duration::from_secs(1))
            .keep_alive_timeout(Duration::from_secs(1))
            .serve_connection(socket, RamaHttpService::new(unreachable_service()))
            .await
            .expect("serve_connection");
    });

    // Spawn a "client" conn that only reads until EOF
    let mut conn = connect_async(addr).await;

    // write h2 magic preface and settings frame
    conn.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .expect("client preface");
    conn.write_all(&[
        0, 0, 0, // len
        4, // kind
        0, // flag
        0, 0, 0, 0, // stream id
    ])
    .await
    .expect("client settings");

    let read_pings = async {
        // read until 3 pings are received
        let mut pings = 0;
        let mut buf = [0u8; 1024];
        while pings < 3 {
            let n = conn.read(&mut buf).await.expect("client.read");
            assert!(n != 0);

            if is_ping_frame(&buf) {
                assert_ping_frame(&buf, n);
                write_pong_frame(&mut conn).await;
                pings += 1;
            }
        }
    };

    // Expect all pings to occurs under 5 seconds
    tokio::time::timeout(Duration::from_secs(5), read_pings)
        .await
        .expect("timed out waiting for pings");
}

#[test]
fn http1_trailer_send_fields() {
    let body = rama::futures::stream::once(async move { Ok("hello".into()) });
    let mut headers = HeaderMap::new();
    headers.insert("chunky-trailer", "header data".parse().unwrap());
    // Invalid trailer field that should not be sent
    headers.insert("Host", "www.example.com".parse().unwrap());
    // Not specified in Trailer header, so should not be sent
    headers.insert("foo", "bar".parse().unwrap());

    let server = serve();
    server
        .reply()
        .header("transfer-encoding", "chunked")
        .header("trailer", "chunky-trailer")
        .body_stream_with_trailers(body, headers);
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        TE: trailers\r\n\
        \r\n\
    ",
    )
    .expect("writing");

    let chunky_trailer_chunk = b"\r\nchunky-trailer: header data\r\n\r\n";
    let res = read_until(&mut req, |buf| buf.ends_with(chunky_trailer_chunk)).expect("reading");
    let sres = s(&res);

    let expected_head =
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: chunky-trailer\r\n";
    assert_eq!(&sres[..expected_head.len()], expected_head);

    // skip the date header
    let date_fragment = "GMT\r\n\r\n";
    let pos = sres.find(date_fragment).expect("find GMT");
    let body = &sres[pos + date_fragment.len()..];

    let expected_body = "5\r\nhello\r\n0\r\nchunky-trailer: header data\r\n\r\n";
    assert_eq!(body, expected_body);
}

#[test]
fn http1_trailer_fields_not_allowed() {
    let body = rama::futures::stream::once(async move { Ok("hello".into()) });
    let mut headers = HeaderMap::new();
    headers.insert("chunky-trailer", "header data".parse().unwrap());

    let server = serve();
    server
        .reply()
        .header("transfer-encoding", "chunked")
        .header("trailer", "chunky-trailer")
        .body_stream_with_trailers(body, headers);
    let mut req = connect(server.addr());

    // TE: trailers is not specified in request headers
    req.write_all(
        b"\
        GET / HTTP/1.1\r\n\
        Host: example.domain\r\n\
        Connection: keep-alive\r\n\
        \r\n\
    ",
    )
    .expect("writing");

    let last_chunk = b"\r\n0\r\n\r\n";
    let res = read_until(&mut req, |buf| buf.ends_with(last_chunk)).expect("reading");
    let sres = s(&res);

    let expected_head =
        "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\ntrailer: chunky-trailer\r\n";
    assert_eq!(&sres[..expected_head.len()], expected_head);

    // skip the date header
    let date_fragment = "GMT\r\n\r\n";
    let pos = sres.find(date_fragment).expect("find GMT");
    let body = &sres[pos + date_fragment.len()..];

    // no trailer fields should be sent because TE: trailers was not in request headers
    let expected_body = "5\r\nhello\r\n0\r\n\r\n";
    assert_eq!(body, expected_body);
}

#[test]
fn http1_trailer_recv_fields() {
    let server = serve();
    let mut req = connect(server.addr());
    req.write_all(
        b"\
        POST / HTTP/1.1\r\n\
        trailer: chunky-trailer\r\n\
        host: example.domain\r\n\
        transfer-encoding: chunked\r\n\
        \r\n\
        5\r\n\
        hello\r\n\
        0\r\n\
        chunky-trailer: header data\r\n\
        \r\n\
    ",
    )
    .expect("writing");

    assert_eq!(server.body(), b"hello");

    let trailers = server.trailers();
    assert_eq!(
        trailers.get("chunky-trailer"),
        Some(&"header data".parse().unwrap())
    );
}

// -------------------------------------------------
// the Server that is used to run all the tests with
// -------------------------------------------------

struct Serve {
    addr: SocketAddr,
    msg_rx: mpsc::Receiver<Msg>,
    trailers_rx: mpsc::Receiver<HeaderMap>,
    reply_tx: Mutex<spmc::Sender<Reply>>,
    shutdown_signal: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Serve {
    fn addr(&self) -> &SocketAddr {
        &self.addr
    }

    fn body(&self) -> Vec<u8> {
        self.try_body().expect("body")
    }

    fn body_err(&self) -> OpaqueError {
        self.try_body().expect_err("body_err")
    }

    fn try_body(&self) -> Result<Vec<u8>, OpaqueError> {
        let mut buf = vec![];
        loop {
            match self.msg_rx.recv() {
                Ok(Msg::Chunk(msg)) => {
                    buf.extend(&msg);
                }
                Ok(Msg::Error(e)) => return Err(e),
                Ok(Msg::End) => break,
                Err(e) => panic!("expected body, found: {e:?}"),
            }
        }
        Ok(buf)
    }

    fn trailers(&self) -> HeaderMap {
        self.trailers_rx.recv().expect("trailers")
    }

    fn reply(&self) -> ReplyBuilder<'_> {
        ReplyBuilder { tx: &self.reply_tx }
    }
}

struct ReplyBuilder<'a> {
    tx: &'a Mutex<spmc::Sender<Reply>>,
}

impl ReplyBuilder<'_> {
    fn status(self, status: rama::http::StatusCode) -> Self {
        self.tx.lock().unwrap().send(Reply::Status(status)).unwrap();
        self
    }

    fn reason_phrase(self, reason: &str) -> Self {
        self.tx
            .lock()
            .unwrap()
            .send(Reply::ReasonPhrase(
                reason.as_bytes().try_into().expect("reason phrase"),
            ))
            .unwrap();
        self
    }

    fn version(self, version: rama::http::Version) -> Self {
        self.tx
            .lock()
            .unwrap()
            .send(Reply::Version(version))
            .unwrap();
        self
    }

    fn header<V: AsRef<str>>(self, name: &str, value: V) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("header name");
        let value = HeaderValue::from_str(value.as_ref()).expect("header value");
        self.tx
            .lock()
            .unwrap()
            .send(Reply::Header(name, value))
            .unwrap();
        self
    }

    fn body<T: AsRef<[u8]>>(self, body: T) {
        let chunk = Bytes::copy_from_slice(body.as_ref());
        let body = BodyExt::boxed(rama::http::body::util::Full::new(chunk).map_err(|e| match e {}));
        self.tx.lock().unwrap().send(Reply::Body(body)).unwrap();
    }

    fn body_stream<S>(self, stream: S)
    where
        S: rama::futures::Stream<Item = Result<Bytes, BoxError>> + Send + Sync + 'static,
    {
        use rama::futures::TryStreamExt;
        use rama::http::core::body::Frame;
        let body = BodyExt::boxed(StreamBody::new(stream.map_ok(Frame::data)));
        self.tx.lock().unwrap().send(Reply::Body(body)).unwrap();
    }

    fn body_stream_with_trailers<S>(self, stream: S, trailers: HeaderMap)
    where
        S: rama::futures::Stream<Item = Result<Bytes, BoxError>> + Send + Sync + 'static,
    {
        use rama::futures::TryStreamExt;
        use rama::http::core::body::Frame;
        use support::trailers::StreamBodyWithTrailers;
        let mut stream_body = StreamBodyWithTrailers::new(stream.map_ok(Frame::data));
        stream_body.set_trailers(trailers);
        let body = BodyExt::boxed(stream_body);
        self.tx.lock().unwrap().send(Reply::Body(body)).unwrap();
    }
}

impl Drop for ReplyBuilder<'_> {
    fn drop(&mut self) {
        if let Ok(mut tx) = self.tx.lock() {
            let _ = tx.send(Reply::End);
        }
    }
}

impl Drop for Serve {
    fn drop(&mut self) {
        drop(self.shutdown_signal.take());
        drop(self.thread.take());
        /*
        let r = self.thread.take().unwrap().join();
        if let Err(ref e) = r {
            println!("{:?}", e);
        }
        r.unwrap();
        */
    }
}

#[derive(Clone)]
struct TestService {
    tx: mpsc::Sender<Msg>,
    trailers_tx: mpsc::Sender<HeaderMap>,
    reply: spmc::Receiver<Reply>,
}

type ReplyBody = BoxBody<Bytes, BoxError>;

#[derive(Debug)]
enum Reply {
    Status(rama::http::StatusCode),
    ReasonPhrase(rama::http::core::ext::ReasonPhrase),
    Version(rama::http::Version),
    Header(HeaderName, HeaderValue),
    Body(ReplyBody),
    End,
}

#[derive(Debug)]
enum Msg {
    Chunk(Vec<u8>),
    Error(OpaqueError),
    End,
}

impl Service<Request> for TestService {
    type Response = Response;
    type Error = Infallible;

    fn serve(
        &self,

        mut req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let tx = self.tx.clone();
        let trailers_tx = self.trailers_tx.clone();

        Box::pin(async move {
            while let Some(item) = req.frame().await {
                match item {
                    Ok(frame) => {
                        if frame.is_data() {
                            tx.send(Msg::Chunk(frame.into_data().unwrap().to_vec()))
                                .unwrap();
                        } else if frame.is_trailers() {
                            let trailers = frame.into_trailers().unwrap();
                            trailers_tx.send(trailers).unwrap();
                        }
                    }
                    Err(err) => {
                        tx.send(Msg::Error(err)).unwrap();
                        return Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .body(rama::http::Body::empty())
                            .unwrap());
                    }
                }
            }

            tx.send(Msg::End).unwrap();

            Self::build_reply(&self.reply)
        })
    }
}

impl TestService {
    #[allow(clippy::needless_pass_by_value)]
    fn build_reply(replies: &spmc::Receiver<Reply>) -> Result<Response, Infallible> {
        let mut res = Response::new(rama::http::Body::empty());
        while let Ok(reply) = replies.try_recv() {
            match reply {
                Reply::Status(s) => {
                    *res.status_mut() = s;
                }
                Reply::ReasonPhrase(reason) => {
                    res.extensions_mut().insert(reason);
                }
                Reply::Version(v) => {
                    *res.version_mut() = v;
                }
                Reply::Header(name, value) => {
                    res.headers_mut().insert(name, value);
                }
                Reply::Body(body) => {
                    *res.body_mut() = rama::http::Body::new(body);
                }
                Reply::End => break,
            }
        }
        Ok(res)
    }
}

const HELLO: &str = "hello";

#[derive(Debug, Clone)]
struct HelloWorld;

impl Service<Request> for HelloWorld {
    type Response = Response;
    type Error = Infallible;

    fn serve(
        &self,

        _req: Request,
    ) -> impl Future<Output = Result<Self::Response, Self::Error>> + Send + '_ {
        let response = Response::new(rama::http::Body::from(HELLO));
        future::ok(response)
    }
}

fn unreachable_service()
-> impl Service<rama::http::Request, Response = rama::http::Response, Error = Infallible> + Clone {
    service_fn(async |_req| unreachable!())
}

fn connect(addr: &SocketAddr) -> TcpStream {
    let req = TcpStream::connect(addr).unwrap();
    req.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    req.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    req
}

async fn connect_async(addr: SocketAddr) -> TkTcpStream {
    TkTcpStream::connect(addr).await.expect("connect_async")
}

fn serve() -> Serve {
    serve_opts().serve()
}

fn serve_opts() -> ServeOptions {
    ServeOptions::default()
}

#[derive(Clone, Copy)]
struct ServeOptions {
    http2: bool,
    keep_alive: bool,
    pipeline: bool,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            http2: false,
            keep_alive: true,
            pipeline: false,
        }
    }
}

impl ServeOptions {
    fn http2(mut self) -> Self {
        self.http2 = true;
        self
    }

    fn keep_alive(mut self, enabled: bool) -> Self {
        self.keep_alive = enabled;
        self
    }

    fn pipeline(mut self, enabled: bool) -> Self {
        self.pipeline = enabled;
        self
    }

    fn serve(self) -> Serve {
        let _options = self;

        let (addr_tx, addr_rx) = mpsc::channel();
        let (msg_tx, msg_rx) = mpsc::channel();
        let (trailers_tx, trailers_rx) = mpsc::channel();
        let (reply_tx, reply_rx) = spmc::channel();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let addr: SocketAddr = ([127, 0, 0, 1], 0).into();

        let thread_name = format!(
            "test-server-{}",
            thread::current()
                .name()
                .unwrap_or("<unknown test case name>")
        );
        let thread = thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                support::runtime().block_on(async move {
                    let listener = TkTcpListener::bind(addr).await.unwrap();

                    addr_tx
                        .send(listener.local_addr().unwrap())
                        .expect("server addr tx");

                    loop {
                        let msg_tx = msg_tx.clone();
                        let trailers_tx = trailers_tx.clone();
                        let reply_rx = reply_rx.clone();

                        tokio::select! {
                            res = listener.accept() => {
                                let (stream, _) = res.unwrap();
                                let stream = ServiceInput::new(stream);

                                tokio::task::spawn(async move {
                                    let msg_tx = msg_tx.clone();
                                    let reply_rx = reply_rx.clone();
                                    let service = RamaHttpService::new(  TestService {
                                        tx: msg_tx,
                                        trailers_tx,
                                        reply: reply_rx,
                                    });

                                    if _options.http2 {
                                        http2::Builder::new(Executor::new())
                                            .serve_connection(stream, service).await.unwrap();
                                    } else {
                                        http1::Builder::new()
                                            .keep_alive(_options.keep_alive)
                                            .pipeline_flush(_options.pipeline)
                                            .serve_connection(stream, service).await.unwrap();
                                    }
                                });
                            }
                            _ = &mut shutdown_rx => {
                                break;
                            }
                        }
                    }
                })
            })
            .expect("thread spawn");

        let addr = addr_rx.recv().expect("server addr rx");

        Serve {
            msg_rx,
            trailers_rx,
            reply_tx: Mutex::new(reply_tx),
            addr,
            shutdown_signal: Some(shutdown_tx),
            thread: Some(thread),
        }
    }
}

fn s(buf: &[u8]) -> &str {
    std::str::from_utf8(buf).unwrap()
}

fn has_header(msg: &str, name: &str) -> bool {
    let n = msg.find("\r\n\r\n").unwrap_or(msg.len());

    msg[..n].contains(name)
}

fn tcp_bind(addr: &SocketAddr) -> std::io::Result<TcpListener> {
    let std_listener = StdTcpListener::bind(addr).unwrap();
    std_listener.set_nonblocking(true).unwrap();
    TcpListener::from_std(std_listener)
}

fn read_until<R, F>(io: &mut R, func: F) -> io::Result<Vec<u8>>
where
    R: Read,
    F: Fn(&[u8]) -> bool,
{
    let mut buf = vec![0; 8192];
    let mut pos = 0;
    loop {
        let n = io.read(&mut buf[pos..])?;
        pos += n;
        if func(&buf[..pos]) {
            break;
        }

        if pos == buf.len() {
            return Err(io::Error::other("read_until buffer filled"));
        }
    }
    buf.truncate(pos);
    Ok(buf)
}

struct DebugStream<T, D> {
    stream: T,
    _debug: D,
}

impl<T: Unpin, D> Unpin for DebugStream<T, D> {}

impl<T: Read, D> Read for DebugStream<T, D> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.stream.read_exact(buf)
    }

    fn read_to_end(&mut self, buf: &mut Vec<u8>) -> io::Result<usize> {
        self.stream.read_to_end(buf)
    }

    fn read_to_string(&mut self, buf: &mut String) -> io::Result<usize> {
        self.stream.read_to_string(buf)
    }

    fn read_vectored(&mut self, bufs: &mut [io::IoSliceMut<'_>]) -> io::Result<usize> {
        self.stream.read_vectored(bufs)
    }
}

impl<T: Write, D> Write for DebugStream<T, D> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    fn write_all(&mut self, mut buf: &[u8]) -> io::Result<()> {
        self.stream.write_all(buf)
    }

    fn write_fmt(&mut self, args: std::fmt::Arguments<'_>) -> io::Result<()> {
        self.stream.write_fmt(args)
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.stream.write_vectored(bufs)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<T: AsyncWrite + Unpin, D> AsyncWrite for DebugStream<T, D> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }
}

#[warn(clippy::missing_trait_methods)]
impl<T: AsyncRead + Unpin, D: Unpin> AsyncRead for DebugStream<T, D> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

#[derive(Clone)]
struct Dropped(Arc<AtomicBool>);

impl Dropped {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub(crate) fn load(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Drop for Dropped {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

struct TestClient {
    http2_only: bool,
}

impl TestClient {
    fn new() -> Self {
        Self { http2_only: false }
    }

    fn http2_only(mut self) -> Self {
        self.http2_only = true;
        self
    }

    async fn get(&self, uri: Uri) -> Result<Response<IncomingBody>, rama::http::core::Error> {
        self.request(
            Request::builder()
                .uri(uri)
                .method(Method::GET)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
    }

    async fn request(
        &self,
        req: Request<Empty<Bytes>>,
    ) -> Result<Response<IncomingBody>, rama::http::core::Error> {
        let host = req.uri().host().expect("uri has no host");
        let port = req.uri().port_u16().expect("uri has no port");

        let stream = TkTcpStream::connect(format!("{host}:{port}"))
            .await
            .unwrap();
        let stream = ServiceInput::new(stream);

        if self.http2_only {
            let (mut sender, conn) =
                rama::http::core::client::conn::http2::Builder::new(Executor::new())
                    .handshake(stream)
                    .await
                    .unwrap();
            tokio::task::spawn(async move {
                conn.await.unwrap();
            });

            sender.send_request(req).await
        } else {
            let (mut sender, conn) = rama::http::core::client::conn::http1::Builder::new()
                .handshake(stream)
                .await
                .unwrap();
            tokio::task::spawn(async move {
                conn.await.unwrap();
            });

            sender.send_request(req).await
        }
    }
}
