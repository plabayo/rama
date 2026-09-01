use std::{
    error::Error,
    io,
    net::UdpSocket,
    process::{Command, Output},
    thread,
    time::Duration,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn resolves_supported_records_with_local_dns_server() -> TestResult {
    let output = resolve_from_local_dns("A", 1, &[192, 0, 2, 1])?;
    assert!(
        output.contains("Resolving A for domain: example.test"),
        "output: {output}"
    );
    assert!(output.contains("* 192.0.2.1"), "output: {output}");

    let output = resolve_from_local_dns(
        "AAAA",
        28,
        &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    )?;
    assert!(
        output.contains("Resolving AAAA for domain: example.test"),
        "output: {output}"
    );
    assert!(output.contains("* 2001:db8::1"), "output: {output}");

    let output = resolve_from_local_dns("TXT", 16, b"\x05hello\x00")?;
    assert!(
        output.contains("Resolving TXT for domain: example.test"),
        "output: {output}"
    );
    assert!(output.contains("* \"hello\" \"\""), "output: {output}");

    // The target preserves its leading label's case and uses RFC 1035
    // compression for the question name suffix.
    let output = resolve_from_local_dns("CNAME", 5, b"\x05Alias\xc0\x0c")?;
    assert!(
        output.contains("Resolving CNAME for domain: example.test"),
        "output: {output}"
    );
    assert!(output.contains("* Alias.example.test."), "output: {output}");

    let svcb = [
        0, 1, 0, // priority 1, root target
        0, 1, 0, 6, 2, b'h', b'2', 2, b'h', b'3', // alpn=h2,h3
        0, 3, 0, 2, 0x20, 0xfb, // port=8443
    ];
    let output = resolve_from_local_dns("SVCB", 64, &svcb)?;
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
    let output = resolve_from_local_dns("HTTPS", 65, &https)?;
    assert!(
        output.contains("Resolving HTTPS for domain: example.test"),
        "output: {output}"
    );
    assert!(output.contains("* 0 svc.example.test."), "output: {output}");
    Ok(())
}

#[test]
fn no_answer_exits_with_an_error() -> TestResult {
    let output = run_resolve_from_local_dns("HTTPS", 65, None)?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!output.status.success(), "stdout: {stdout}");
    assert!(
        stderr.contains("failed to resolve domain into any HTTPS record"),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    Ok(())
}

fn resolve_from_local_dns(
    record_type: &'static str,
    type_number: u16,
    rdata: &[u8],
) -> TestResult<String> {
    let output = run_resolve_from_local_dns(record_type, type_number, Some(rdata))?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(
        output.status.success(),
        "stderr: {stderr}\nstdout: {stdout}"
    );
    Ok(stdout)
}

fn run_resolve_from_local_dns(
    record_type: &'static str,
    type_number: u16,
    rdata: Option<&[u8]>,
) -> TestResult<Output> {
    let socket = UdpSocket::bind(("127.0.0.1", 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(10)))?;
    let name_server = socket.local_addr()?.to_string();
    let rdata = rdata.map(<[u8]>::to_vec);
    let server = thread::spawn(move || -> io::Result<()> {
        let mut query = [0; 2048];
        let (query_len, peer) = socket.recv_from(&mut query)?;
        let response = dns_response(&query[..query_len], type_number, rdata.as_deref())?;
        socket.send_to(&response, peer)?;
        Ok(())
    });

    let trace_dir = rama::utils::fs::TempDir::with_prefix("rama-resolve-test-")?;
    let trace = trace_dir.path().join("trace.log");
    let output = Command::new(env!("CARGO_BIN_EXE_rama"))
        .args([
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
        .arg("--trace")
        .arg(&trace)
        .env("RUST_LOG", "info")
        .output()?;
    server
        .join()
        .map_err(|_panic| io::Error::other("local DNS server panicked"))??;
    Ok(output)
}

fn dns_response(query: &[u8], type_number: u16, rdata: Option<&[u8]>) -> io::Result<Vec<u8>> {
    if query.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated DNS query",
        ));
    }
    let mut offset = 12;
    loop {
        let label_len = usize::from(*query.get(offset).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "truncated DNS query name")
        })?);
        offset += 1;
        if label_len == 0 {
            break;
        }
        if label_len >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compressed DNS query name",
            ));
        }
        offset += label_len;
    }
    let question_end = offset
        .checked_add(4)
        .filter(|end| *end <= query.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS question"))?;
    let query_type = u16::from_be_bytes([query[offset], query[offset + 1]]);
    if query_type != type_number {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected DNS query type: {query_type}"),
        ));
    }

    let mut response = Vec::with_capacity(question_end + 12 + rdata.map_or(0, <[u8]>::len));
    response.extend_from_slice(&query[..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0, 1, 0, u8::from(rdata.is_some()), 0, 0, 0, 0]);
    response.extend_from_slice(&query[12..question_end]);
    let Some(rdata) = rdata else {
        return Ok(response);
    };
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&type_number.to_be_bytes());
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(&60_u32.to_be_bytes());
    let rdata_len = u16::try_from(rdata.len())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    response.extend_from_slice(&rdata_len.to_be_bytes());
    response.extend_from_slice(rdata);
    Ok(response)
}
