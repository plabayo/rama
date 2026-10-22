use super::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

fn fixture(mode: &str) -> RamaService {
    RamaService::spawn(&mut fixture_command(mode), "127.0.0.1:0".parse().unwrap())
}

fn fixture_command(mode: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "utils::startup_tests::child",
            "--ignored",
            "--nocapture",
        ])
        .env("RAMA_TEST_SERVICE_STARTUP", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::null());
    command
}

#[test]
fn delayed_startup_drains_output_and_keeps_a_bounded_diagnostic_tail() {
    let mut service = fixture("flood");
    service.wait_for_endpoint(TransportProtocol::Tcp);
    assert_ne!(service.port(), 0);
    assert!(service.diagnostics().contains("output drained before bind"));
    assert!(service.diagnostics.lock().len() <= 64 * 1024);
}

#[cfg(unix)]
#[test]
fn inherited_parent_listener_is_not_child_readiness() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let inherited_addr = listener.local_addr().unwrap();
    let mut command = fixture_command("inherited");
    command.stdin(Stdio::from(std::os::fd::OwnedFd::from(
        listener.try_clone().unwrap(),
    )));

    let mut service = RamaService::spawn(&mut command, "127.0.0.1:0".parse().unwrap());
    service.wait_for_endpoint(TransportProtocol::Tcp);
    assert_ne!(service.address(), inherited_addr);
}

#[test]
fn early_exit_and_absent_listener_fail_within_the_startup_budget() {
    for mode in ["exit", "never"] {
        let started = Instant::now();
        let mut service = fixture(mode);
        service.startup_deadline = started
            + if mode == "exit" {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(500)
            };
        let failure = catch_unwind(AssertUnwindSafe(|| {
            service.wait_for_endpoint(TransportProtocol::Tcp)
        }));
        let _failure = failure.expect_err("startup must fail discovery");
        if mode == "exit" {
            assert!(service.diagnostics().contains("deliberate startup failure"));
            assert!(service.process.try_wait().unwrap().is_some());
        }
        // Drop must kill and reap an alive child, and also tolerate the child
        // already reaped by check_running. Neither path may panic.
        drop(service);
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}

#[test]
fn multiple_tcp_listeners_require_an_explicit_role() {
    let mut service = fixture("multiple");

    // The marker only synchronizes this fixture's two binds. Addresses still
    // come from the child's native socket snapshot, never from its output.
    while !service.diagnostics().contains("both listeners bound") {
        service.check_running();
        assert!(Instant::now() < service.startup_deadline);
        thread::sleep(Duration::from_millis(10));
    }

    let failure = catch_unwind(AssertUnwindSafe(|| {
        service.wait_for_endpoint(TransportProtocol::Tcp)
    }))
    .expect_err("two listeners must not be selected arbitrarily");
    assert!(
        failure
            .downcast_ref::<String>()
            .unwrap()
            .contains("ambiguous")
    );

    let sockets = listening_sockets(service.process.id()).unwrap();
    assert_eq!(sockets.len(), 2);
    service.wait_for_endpoint_except(TransportProtocol::Tcp, Some(sockets[0].local_addr));
    assert_eq!(service.address(), sockets[1].local_addr);
}

#[test]
#[ignore = "subprocess fixture for startup_tests"]
fn child() {
    let Ok(mode) = std::env::var("RAMA_TEST_SERVICE_STARTUP") else {
        return;
    };
    if mode == "exit" {
        eprintln!("deliberate startup failure");
        return;
    }
    let mut listeners = Vec::new();
    if mode == "flood" {
        io::stderr().write_all(&vec![b'x'; 256 * 1024]).unwrap();
        eprintln!("output drained before bind");
        thread::sleep(Duration::from_millis(100));
        listeners.push(std::net::TcpListener::bind("127.0.0.1:0").unwrap());
    } else if mode == "multiple" {
        listeners.push(std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        listeners.push(std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        eprintln!("both listeners bound");
    } else if mode == "inherited" {
        thread::sleep(Duration::from_millis(100));
        listeners.push(std::net::TcpListener::bind("127.0.0.1:0").unwrap());
        // Stdin is the inherited listener, so keep both sockets alive until
        // the parent kills and reaps this fixture through its owning guard.
        loop {
            thread::park();
        }
    }

    let _eof = io::stdin().read(&mut [0]).unwrap();
}
