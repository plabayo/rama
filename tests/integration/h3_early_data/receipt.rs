//! STREAM receipt provenance survives delayed accepts, reordering and draining.

use super::*;

#[derive(Clone, Copy)]
enum LowerStream {
    Early,
    Confirmed,
}

#[tokio::test]
async fn early_receipt_tracks_packets_instead_of_accept_time_or_stream_watermarks() {
    for provider in Provider::enabled() {
        for lower in [LowerStream::Early, LowerStream::Confirmed] {
            timeout(LIMIT, receipt(provider, lower)).await.unwrap();
        }
    }
}

async fn receipt(provider: Provider, lower: LowerStream) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;
    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let (mut low_send, _low_reply) = client.open_bi().await.unwrap();
    let (mut high_send, _high_reply) = client.open_bi().await.unwrap();
    high_send
        .write_all(b"higher stream arrived early")
        .await
        .unwrap();
    high_send.finish().unwrap();
    // QUIC implicitly opens lower numbered streams. Their IDs are not evidence
    // that an early packet actually carried their contents.
    let (_low_response, mut low_recv) = server.accept_bi().await.unwrap();
    assert_eq!(low_recv.id(), low_send.id());
    assert!(!low_recv.is_0rtt());
    if matches!(lower, LowerStream::Early) {
        low_send
            .write_all(b"lower stream arrived later")
            .await
            .unwrap();
        low_send.finish().unwrap();
        assert_eq!(
            low_recv.read_to_end(64).await.unwrap(),
            b"lower stream arrived later"
        );
        assert!(
            low_recv.is_0rtt(),
            "receipt is updated after accept and retained after EOF"
        );
    }
    fixture.gate.release();
    tokio::try_join!(client.handshake_confirmed(), server.handshake_confirmed()).unwrap();
    // This accept happens after Finished: the older early receipt must survive.
    let (_high_response, mut high_recv) = server.accept_bi().await.unwrap();
    assert_eq!(high_recv.id(), high_send.id());
    assert!(high_recv.is_0rtt());
    assert_eq!(
        high_recv.read_to_end(64).await.unwrap(),
        b"higher stream arrived early"
    );
    assert!(
        high_recv.is_0rtt(),
        "draining must retain receipt after protocol state is freed"
    );
    if matches!(lower, LowerStream::Confirmed) {
        low_send
            .write_all(b"lower stream arrived later")
            .await
            .unwrap();
        low_send.finish().unwrap();
        assert_eq!(
            low_recv.read_to_end(64).await.unwrap(),
            b"lower stream arrived later"
        );
        assert!(
            !low_recv.is_0rtt(),
            "a lower stream ID does not inherit another stream's exposure"
        );
    } else {
        assert!(
            low_recv.is_0rtt(),
            "confirmation does not erase early receipt"
        );
    }
}

#[derive(Clone, Copy)]
enum Terminal {
    EmptyFin,
    Stop,
    Reset,
}

#[tokio::test]
async fn early_receipt_survives_empty_fin_stop_and_reset() {
    for provider in Provider::enabled() {
        for terminal in [Terminal::EmptyFin, Terminal::Stop, Terminal::Reset] {
            timeout(LIMIT, terminal_receipt(provider, terminal))
                .await
                .unwrap();
        }
    }
}

async fn terminal_receipt(provider: Provider, terminal: Terminal) {
    let fixture = Fixture::new(provider, Version::V1).await;
    fixture.warm().await;
    fixture.gate.hold();
    let (client, server) = fixture.early_pair().await;
    let (mut send, _reply) = client.open_bi().await.unwrap();
    if matches!(terminal, Terminal::EmptyFin) {
        send.finish().unwrap();
    } else {
        send.write_all(b"early").await.unwrap();
    }
    let (_response, mut recv) = server.accept_bi().await.unwrap();
    assert!(recv.is_0rtt());
    match terminal {
        Terminal::EmptyFin => assert!(recv.read_to_end(8).await.unwrap().is_empty()),
        Terminal::Stop => recv.stop(0u32).unwrap(),
        Terminal::Reset => {
            let mut bytes = [0; 5];
            recv.read_exact(&mut bytes).await.unwrap();
            send.reset(7u32).unwrap();
            assert_eq!(recv.received_reset().await.unwrap(), Some(7u32.into()));
        }
    }
    assert!(
        recv.is_0rtt(),
        "terminal state preserves actual early receipt"
    );
    fixture.gate.release();
    tokio::try_join!(client.handshake_confirmed(), server.handshake_confirmed()).unwrap();
    assert!(recv.is_0rtt());
    // A later confirmed stream may reuse freed receiver storage, but not provenance.
    let (mut next, _reply) = client.open_bi().await.unwrap();
    next.write_all(b"confirmed").await.unwrap();
    next.finish().unwrap();
    let (_response, mut next) = server.accept_bi().await.unwrap();
    assert!(!next.is_0rtt());
    assert_eq!(next.read_to_end(16).await.unwrap(), b"confirmed");
    assert!(!next.is_0rtt());
}
