//! What a connection does with an unreliable datagram it has no room for.

use super::*;

/// A datagram the peer was told it could send does not end the connection when there is no
/// room to hold it. A stream transfer succeeds after the datagram is dropped.
#[test]
fn a_datagram_with_no_room_is_dropped_and_the_connection_carries_on() {
    let _guard = subscribe();
    // Room for the frame on the wire, not for the payload plus a queue entry.
    const WINDOW: usize = 256;
    let server = ServerConfig {
        transport: Arc::new(TransportConfig {
            datagram_receive_buffer_size: Some(WINDOW),
            ..TransportConfig::default()
        }),
        ..server_config()
    };
    let mut pair = Pair::new(
        Arc::new(EndpointConfig::try_with_rand_key().unwrap()),
        server,
    );
    let (client_ch, server_ch) = pair.connect();

    let limit = pair
        .client_conn_mut(client_ch)
        .datagrams()
        .max_size()
        .expect("the peer offered the extension");
    let sent = vec![0xd1; limit];
    pair.client_datagrams(client_ch)
        .send(sent.into(), true)
        .expect("the sending side admits what it says it may send");
    pair.drive();

    assert!(
        !pair.server_conn_mut(server_ch).is_closed(),
        "the server ended the connection over a datagram it told the client it could send"
    );

    // A stream transfer succeeds after the datagram is dropped.
    let stream = pair
        .client_streams(client_ch)
        .open(Dir::Uni)
        .expect("a stream opens");
    const AFTER: &[u8] = b"the connection still carries traffic";
    pair.client_send(client_ch, stream)
        .write(AFTER)
        .expect("the stream takes it");
    pair.client_send(client_ch, stream)
        .finish()
        .expect("the stream ends");
    pair.drive();
    assert!(matches!(
        pair.server_conn_mut(server_ch).poll(),
        Some(Event::Stream(StreamEvent::Opened { dir: Dir::Uni }))
    ));
    let mut recv = pair.server_recv(server_ch, stream);
    let mut chunks = recv.read(true).expect("the stream is readable");
    let chunk = chunks
        .next(usize::MAX)
        .expect("a chunk arrives")
        .expect("it carries the payload");
    assert_eq!(&chunk.bytes[..], AFTER, "and it is what was written");
    let _transmit = chunks.finalize();
}
