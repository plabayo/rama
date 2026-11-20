// An HTTP/1 client connection must not report ready while a request is in flight
// on it: pools that hand out ready connections would queue the next request
// behind the whole response.

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rama::ServiceInput;
use rama::bytes::Bytes;
use rama::http::Request;
use rama::http::body::util::Empty;
use rama::http::core::client::conn::http1::{self, Connection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::{coop, yield_now};

/// Accepts every write and never answers, so a sent request stays in flight.
struct SilentIo;

impl AsyncRead for SilentIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for SilentIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

type SilentConnection = Connection<ServiceInput<SilentIo>, Empty<Bytes>>;

/// Runs the connection task once; it never finishes, as the peer never answers.
fn poll_conn(conn: &mut SilentConnection, cx: &mut Context<'_>) -> Poll<()> {
    assert!(Pin::new(conn).poll(cx).is_pending());
    Poll::Ready(())
}

#[tokio::test]
async fn h1_connection_is_not_ready_while_a_request_is_in_flight() {
    let (mut sender, mut conn) = http1::handshake(ServiceInput::new(SilentIo)).await.unwrap();

    // The initial permit is available before the driver runs.
    assert!(sender.is_ready());
    poll_fn(|cx| poll_conn(&mut conn, cx)).await;
    assert!(sender.is_ready());

    // Kept alive: dropping the response future cancels the request.
    let _response = sender.send_request(Request::new(Empty::new()));
    assert!(!sender.is_ready());

    // Pending with a queued request must not grant a second permit.
    poll_fn(|cx| {
        while let Poll::Ready(restore) = coop::poll_proceed(cx) {
            restore.made_progress();
        }
        poll_conn(&mut conn, cx)
    })
    .await;
    assert!(!sender.is_ready());
    yield_now().await;

    // With a fresh budget it takes and writes the request, which then waits
    // for a response that never comes.
    poll_fn(|cx| poll_conn(&mut conn, cx)).await;
    assert!(
        !sender.is_ready(),
        "connection reports ready with a request in flight"
    );
}
