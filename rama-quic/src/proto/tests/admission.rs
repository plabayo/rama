use super::*;

const LIMIT: Duration = Duration::from_millis(100);

fn pair() -> Pair {
    let mut config = EndpointConfig::default();
    config.handshake_timeout(LIMIT).unwrap();
    let mut pair = Pair::new(Arc::new(config), server_config());
    pair.server.handle_incoming = Box::new(|_| IncomingConnectionBehavior::Wait);
    pair
}

fn incoming(pair: &mut Pair) -> (ConnectionHandle, Incoming) {
    let client = pair.begin_connect(client_config());
    pair.drive_client();
    pair.drive_server();
    (client, pair.server.waiting_incoming.pop().unwrap())
}

#[test]
fn expired_handles_cannot_remove_a_reused_admission_slot() {
    #[derive(Debug)]
    enum Action {
        Ignore,
        Accept,
        Retry,
        Refuse,
    }
    for action in [
        Action::Ignore,
        Action::Accept,
        Action::Retry,
        Action::Refuse,
    ] {
        let mut pair = pair();
        let (old_client, stale) = incoming(&mut pair);
        pair.time += LIMIT;
        assert_eq!(pair.server.expire_incoming(pair.time, 1), 1);
        assert!(stale.is_expired());
        assert!(!stale.may_retry());
        // Only the server-side stale handle participates in the slot reuse test.
        pair.client.connections.remove(&old_client);
        let (client, current) = incoming(&mut pair);
        assert_eq!(pair.server.pending_incoming(), 1);
        match action {
            Action::Ignore => pair.server.ignore(stale),
            Action::Accept => {
                let mut buf = Vec::new();
                assert!(matches!(
                    pair.server.accept(stale, pair.time, &mut buf, None),
                    Err(AcceptError {
                        cause: ConnectionError::TimedOut,
                        ..
                    })
                ));
            }
            Action::Retry => {
                let stale = Endpoint::retry(&mut pair.server, stale, &mut Vec::new())
                    .unwrap_err()
                    .into_incoming();
                pair.server.ignore(stale);
            }
            Action::Refuse => {
                let _ = pair.server.refuse(stale, &mut Vec::new());
            }
        }
        assert_eq!(pair.server.pending_incoming(), 1);
        assert!(!current.is_expired());
        pair.server.try_accept(current, pair.time).unwrap();
        assert_eq!(pair.server.pending_incoming(), 0);
        assert!(pair.server.poll_incoming_timeout().is_none());
        pair.drive();
        let event = pair.client_conn_mut(client).poll();
        assert!(
            matches!(event, Some(Event::HandshakeDataReady)),
            "action {action:?}: {event:?}"
        );
        assert!(matches!(
            pair.client_conn_mut(client).poll(),
            Some(Event::Connected)
        ));
    }
}

#[test]
fn expiration_work_and_timer_storage_are_bounded_by_live_admissions() {
    let mut pair = pair();
    let mut handles = Vec::new();
    for _ in 0..3 {
        handles.push(incoming(&mut pair).1);
    }
    assert_eq!(pair.server.pending_incoming(), 3);
    pair.time += LIMIT;
    assert_eq!(pair.server.expire_incoming(pair.time, 2), 2);
    assert_eq!(pair.server.pending_incoming(), 1);
    assert!(pair.server.poll_incoming_timeout().unwrap() <= pair.time);
    assert_eq!(pair.server.expire_incoming(pair.time, 2), 1);
    assert!(pair.server.poll_incoming_timeout().is_none());
    for incoming in handles {
        pair.server.ignore(incoming);
    }
    for _ in 0..20 {
        let (_, handle) = incoming(&mut pair);
        pair.server.ignore(handle);
        assert_eq!(pair.server.pending_incoming(), 0);
        assert!(pair.server.poll_incoming_timeout().is_none());
    }
}

#[test]
fn acceptance_does_not_restart_the_handshake_deadline() {
    let mut pair = pair();
    let started = pair.time;
    let (_, incoming) = incoming(&mut pair);
    pair.time += LIMIT.checked_sub(Duration::from_millis(1)).unwrap();
    let server = pair.server.try_accept(incoming, pair.time).unwrap();
    pair.server_conn_mut(server).handle_timeout(started + LIMIT);
    let conn = pair.server_conn_mut(server);
    assert!(matches!(conn.poll(), Some(Event::HandshakeDataReady)));
    assert!(matches!(
        conn.poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut
        })
    ));
}

#[test]
fn removing_server_config_while_holding_incoming_does_not_panic() {
    let mut pair = pair();
    let (_, incoming) = incoming(&mut pair);
    pair.server.set_server_config(None);
    assert!(matches!(
        pair.server
            .accept(incoming, pair.time, &mut Vec::new(), None),
        Err(AcceptError {
            cause: ConnectionError::LocallyClosed,
            ..
        })
    ));
    assert_eq!(pair.server.pending_incoming(), 0);
    assert!(pair.server.poll_incoming_timeout().is_none());
}
