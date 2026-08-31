use super::utils;
use std::{net::UdpSocket, thread, time::Duration};

#[test]
fn test_resolve_svcb_and_https_with_local_dns_server() {
    // Finish Escargot's build before the mock server starts its read timeout.
    let (success, _, stderr) = utils::RamaService::run_capture(&["--version"]).unwrap();
    assert!(success, "failed to build rama CLI: {stderr}");

    let svcb = [
        0, 1, 0, // priority 1, root target
        0, 1, 0, 6, 2, b'h', b'2', 2, b'h', b'3', // alpn=h2,h3
        0, 3, 0, 2, 0x20, 0xfb, // port=8443
    ];
    let output = resolve_from_local_dns("SVCB", 64, &svcb);
    assert!(
        output.contains("Resolving SVCB for domain: example.test"),
        "output: {output}"
    );
    assert!(
        output.contains("* 1 . alpn=\"h2\",\"h3\" port=8443"),
        "output: {output}"
    );

    let https = [
        0, 0, // priority 0
        3, b's', b'v', b'c', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's',
        b't', 0,
    ];
    let output = resolve_from_local_dns("HTTPS", 65, &https);
    assert!(
        output.contains("Resolving HTTPS for domain: example.test"),
        "output: {output}"
    );
    assert!(output.contains("* 0 svc.example.test."), "output: {output}");
}

fn resolve_from_local_dns(record_type: &'static str, type_number: u16, rdata: &[u8]) -> String {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("bind local DNS server");
    socket
        .set_read_timeout(Some(Duration::from_secs(60)))
        .expect("set DNS server timeout");
    let name_server = socket.local_addr().unwrap().to_string();
    let rdata = rdata.to_vec();
    let server = thread::spawn(move || {
        let mut query = [0; 2048];
        let (query_len, peer) = socket.recv_from(&mut query).expect("receive DNS query");
        let response = service_binding_response(&query[..query_len], type_number, &rdata);
        socket.send_to(&response, peer).expect("send DNS response");
    });

    let (success, stdout, stderr) = utils::RamaService::run_capture(&[
        "resolve",
        "example.test",
        record_type,
        "--nameserver",
        &name_server,
        "--time",
        "2",
        "--tries",
        "1",
    ])
    .expect("run rama resolve");
    server.join().expect("join local DNS server");
    assert!(success, "stderr: {stderr}\nstdout: {stdout}");
    stdout
}

fn service_binding_response(query: &[u8], type_number: u16, rdata: &[u8]) -> Vec<u8> {
    assert!(query.len() >= 12, "truncated DNS query");
    let mut offset = 12;
    loop {
        let label_len = usize::from(*query.get(offset).expect("complete query name"));
        offset += 1;
        if label_len == 0 {
            break;
        }
        assert!(label_len < 64, "uncompressed query name");
        offset += label_len;
    }
    let question_end = offset + 4;
    assert!(question_end <= query.len(), "complete DNS question");
    assert_eq!(
        u16::from_be_bytes([query[offset], query[offset + 1]]),
        type_number
    );

    let mut response = Vec::with_capacity(question_end + 12 + rdata.len());
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&type_number.to_be_bytes());
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
    response.extend_from_slice(rdata);
    response
}

#[tokio::test]
#[ignore]
async fn test_resolve_default() {
    utils::init_tracing();
    let output = utils::RamaService::resolve("localhost", None).unwrap();

    assert!(
        output.contains("Resolving IP for domain: localhost"),
        "output: {output}"
    );
    assert!(
        output.contains("* 127.0.0.1") || output.contains("* ::1"),
        "output: {output}"
    );
}

#[tokio::test]
#[ignore]
async fn test_resolve_a() {
    utils::init_tracing();
    let output = utils::RamaService::resolve("localhost", Some("A")).unwrap();

    assert!(
        output.contains("Resolving A for domain: localhost"),
        "output: {output}"
    );
    assert!(output.contains("* 127.0.0.1"), "output: {output}");
}
