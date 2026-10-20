#![expect(
    clippy::unwrap_used,
    reason = "benchmark setup and protocol assertions"
)]

use rama::{
    bytes::{Bytes, BytesMut},
    extensions::ExtensionsRef as _,
    futures::stream,
    http::{
        Body, Method, Request, Response,
        body::{Frame, util::BodyExt as _},
        core::h3::{
            client,
            connection::Config,
            frame::{FrameDecoder, FrameEvent},
            qpack::{Decoder, DecoderConfig, Encoder, EncoderConfig},
            server,
        },
        proto::h3::{
            FrameHeader, FrameType, VarInt,
            qpack::{DecoderInstruction, EncoderInstruction},
        },
    },
    net::{address::SocketAddress, tls::ApplicationProtocol},
    quic::{
        ClientConfig, Connection, Endpoint, TransportConfig,
        proto::capture::QuicObservation,
        tls::{ClientSessionPolicy, TlsOptions},
    },
    rt::Executor,
    tls::{
        client::TlsClientConfig,
        server::{GeneratedServerAuthConfig, ServerAuthData, TlsServerConfig},
    },
    utils::octets::{kib, kib_u64, mib},
};
use std::{convert::Infallible, sync::Arc, time::Duration};

mod bench_alloc;
fn main() {
    divan::main();
}

#[divan::bench]
fn data_frame_slices(bencher: divan::Bencher) {
    let mut bytes = BytesMut::new();
    FrameHeader::new(FrameType::DATA, kib(16) as u64)
        .encode(&mut bytes)
        .unwrap();
    bytes.resize(bytes.len() + kib(16), 42);
    let bytes = bytes.freeze();
    bencher
        .counter(divan::counter::BytesCount::new(kib(16)))
        .bench(|| {
            let mut decoder = FrameDecoder::new(kib(32));
            let mut input = bytes.clone();
            decoder.feed_bytes(&mut input).unwrap();
            let mut received = 0;
            while let Some(event) = decoder.poll().unwrap() {
                if let FrameEvent::DataChunk(bytes) = event {
                    received += bytes.len();
                    divan::black_box(bytes);
                }
            }
            assert_eq!(received, kib(16));
        });
}

#[divan::bench(args = [0, kib(16), mib(1)], sample_count = 20)]
fn pooled_streaming_round_trip(bencher: divan::Bencher, size: usize) {
    round_trip(
        bencher.counter(divan::counter::BytesCount::new(size)),
        size,
        false,
        0,
        false,
    );
}

#[divan::bench(sample_count = 20)]
fn abandoned_response_churn(bencher: divan::Bencher) {
    round_trip(bencher, kib(16), true, 0, false);
}

// Retained responses keep scheduler entries alive without ready DATA. The
// active writer's cost should not grow linearly with these unrelated streams.
#[divan::bench(args = [16, 128, 1024], sample_count = 20)]
fn streaming_with_idle_responses(bencher: divan::Bencher, idle: usize) {
    round_trip(
        bencher.counter(divan::counter::BytesCount::new(kib(16))),
        kib(16),
        false,
        idle,
        false,
    );
}

#[divan::bench(args = [false, true], sample_count = 20)]
fn observation_round_trip(bencher: divan::Bencher, observed: bool) {
    round_trip(bencher, 0, false, 0, observed);
}

// Each sample gets idle endpoints, a fixed trusted certificate and a fresh TLS
// policy before measurement. The measured closure includes both sides of one
// full QUIC handshake and native observation publication, without HTTP startup.
// Shutdown and verification run in Drop, outside timing/allocation accounting.
#[divan::bench(args = [false, true], sample_count = 100, sample_size = 1)]
fn observation_handshake(bencher: divan::Bencher, observed: bool) {
    bencher
        .with_inputs(|| ObservedHandshake::new(observed))
        .bench_local_refs(ObservedHandshake::connect);
}

struct ObservedHandshake {
    runtime: tokio::runtime::Runtime,
    server: Endpoint,
    client: Endpoint,
    config: ClientConfig,
    observed: bool,
    connections: Option<(Connection, Connection)>,
}

impl ObservedHandshake {
    fn new(observed: bool) -> Self {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let client_tls = TlsClientConfig::new()
            .try_with_server_trust_anchors(auth.cert_chain.clone())
            .unwrap()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let server_tls = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let options = TlsOptions::default().with_client_sessions(ClientSessionPolicy::Fresh);
        let mut server_config =
            rama::quic::ServerConfig::try_from_rama_tls(&server_tls, options).unwrap();
        if observed {
            server_config.set_capture(Default::default());
        }
        let config = ClientConfig::try_from_rama_tls(&client_tls, options).unwrap();
        let (server, client) = runtime.block_on(async {
            let server = Endpoint::build(Executor::new())
                .with_server_config(server_config)
                .bind_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            let client = Endpoint::build(Executor::new())
                .bind_address(SocketAddress::local_ipv4(0))
                .await
                .unwrap();
            (server, client)
        });
        Self {
            runtime,
            server,
            client,
            config,
            observed,
            connections: None,
        }
    }

    fn connect(&mut self) {
        let pair = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let client = self
                    .client
                    .connect_with(
                        self.config.clone(),
                        self.server.local_addr().unwrap(),
                        "localhost",
                    )
                    .unwrap();
                let server = async { self.server.accept().await.unwrap().await.unwrap() };
                let (client, server) = tokio::join!(client, server);
                (client.unwrap(), server)
            })
            .await
            .unwrap()
        });
        self.connections = Some(pair);
    }
}

impl Drop for ObservedHandshake {
    fn drop(&mut self) {
        // Keep the accepted handle until after publication and transport shutdown.
        self.runtime.block_on(async {
            self.client.close(0u32, b"benchmark complete");
            self.server.close(0u32, b"benchmark complete");
            tokio::join!(self.client.shutdown(), self.server.shutdown());
        });
        let (_, server) = self.connections.as_ref().unwrap();
        let observation = server.extensions().get_ref::<QuicObservation>();
        assert_eq!(
            observation.is_some(),
            self.observed,
            "native capture policy"
        );
        if let Some(observation) = observation {
            assert!(observation.completeness.is_complete(), "{observation:?}");
            assert!(observation.first_flight.is_some(), "missing first flight");
            assert!(
                !observation.client_hello_message.is_empty(),
                "missing ClientHello"
            );
            assert!(
                !observation.transport_parameters.is_empty(),
                "missing parameters"
            );
        }
    }
}

fn round_trip(bencher: divan::Bencher, size: usize, abandon: bool, idle: usize, observed: bool) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (endpoint, client_endpoint, sender, retained) = rt.block_on(async {
        let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::default()).unwrap();
        let client_tls = TlsClientConfig::new()
            .try_with_server_trust_anchors(auth.cert_chain.clone())
            .unwrap()
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let server_tls = TlsServerConfig::new()
            .with_server_auth(auth)
            .with_alpn([ApplicationProtocol::HTTP_3].into_iter().collect());
        let mut transport = TransportConfig::default();
        let config = Config {
            max_requests: Config::default().max_requests.max(idle + 1),
            observation: observed.then(Default::default),
            ..Config::default()
        };
        config.configure_transport(&mut transport).unwrap();
        let mut server_config =
            rama::quic::ServerConfig::try_from_rama_tls(&server_tls, TlsOptions::default())
                .unwrap();
        let transport = Arc::new(transport);
        server_config.set_transport_config(transport.clone());
        if observed {
            server_config.set_capture(Default::default());
        }
        let mut client_config =
            rama::quic::ClientConfig::try_from_rama_tls(&client_tls, TlsOptions::default())
                .unwrap();
        client_config.set_transport_config(transport);
        let bind = SocketAddress::local_ipv4(0);
        let endpoint = Endpoint::build(Executor::new())
            .with_server_config(server_config)
            .bind_address(bind)
            .await
            .unwrap();
        let accept = tokio::spawn({
            let endpoint = endpoint.clone();
            let config = config.clone();
            async move {
                let connection = endpoint.accept().await.unwrap().await.unwrap();
                let (mut server, driver) = server::handshake(connection, config).unwrap();
                tokio::spawn(driver.run());
                tokio::spawn(async move {
                    while let Ok(stream) = server.accept().await {
                        tokio::spawn(async move {
                            let (request, response) = stream.resolve().await.unwrap();
                            if request.uri().request_target() == "/hold" {
                                let frames = stream::pending::<Result<Frame<Bytes>, Infallible>>();
                                let body = Body::from_frame_stream(frames);
                                let _result = response.send_response(Response::new(body)).await;
                                return;
                            }
                            // Cancellation is expected in the churn benchmark.
                            let _result = response
                                .send_response(Response::new(request.into_body()))
                                .await;
                        });
                    }
                });
            }
        });
        let client_endpoint = Endpoint::build(Executor::new())
            .bind_address(bind)
            .await
            .unwrap();
        let connection = client_endpoint
            .connect_with(client_config, endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let (sender, driver) =
            client::handshake::<Body>(connection, config, Executor::new()).unwrap();
        tokio::spawn(driver.run());
        accept.await.unwrap();
        let mut retained = Vec::with_capacity(idle);
        for _ in 0..idle {
            retained.push(
                sender
                    .clone()
                    .send_request(
                        Request::builder()
                            .uri("https://localhost/hold")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap(),
            );
        }
        (endpoint, client_endpoint, sender, retained)
    });
    let payload = Bytes::from(vec![42; size]);
    bencher.bench(|| {
        rt.block_on(async {
            let response = sender
                .clone()
                .send_request(
                    Request::builder()
                        .method(Method::POST)
                        .uri("https://localhost/echo")
                        .body(Body::from(payload.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            if abandon {
                drop(response);
                return;
            }
            let mut body = response.into_body();
            let mut received = 0;
            while let Some(frame) = body.frame().await {
                if let Ok(data) = frame.unwrap().into_data() {
                    received += data.len();
                }
            }
            assert_eq!(received, size);
        })
    });
    drop(retained);
    rt.block_on(async {
        client_endpoint.close(0u32, b"benchmark complete");
        endpoint.close(0u32, b"benchmark complete");
        tokio::join!(client_endpoint.shutdown(), endpoint.shutdown());
    });
}

// Field-section assembly is the deliberate copy path: fragmented HEADERS must
// become one bounded QPACK input while contiguous DATA keeps shared storage.
#[divan::bench(args = [1, 16, kib(4)])]
fn fragmented_headers(bencher: divan::Bencher, fragment: usize) {
    let mut bytes = BytesMut::new();
    FrameHeader::new(FrameType::HEADERS, kib(4) as u64)
        .encode(&mut bytes)
        .unwrap();
    bytes.resize(bytes.len() + kib(4), 42);
    let bytes = bytes.freeze();
    bencher.bench(|| {
        let mut decoder = FrameDecoder::with_input_limit(kib(8), kib(8));
        let mut remaining = bytes.clone();
        let mut sections = 0;
        while !remaining.is_empty() {
            let mut part = remaining.split_to(fragment.min(remaining.len()));
            decoder.feed_bytes(&mut part).unwrap();
            while let Some(event) = decoder.poll().unwrap() {
                if let FrameEvent::Headers(bytes) = event {
                    assert_eq!(bytes.len(), kib(4));
                    sections += 1;
                    divan::black_box(bytes);
                }
            }
        }
        assert_eq!(sections, 1);
    });
}

#[divan::bench(args = [false, true])]
fn qpack_round_trip(bencher: divan::Bencher, dynamic: bool) {
    let mut encoder = Encoder::new(EncoderConfig {
        max_table_capacity: if dynamic { kib(4) as u64 } else { 0 },
        ..EncoderConfig::default()
    });
    let mut decoder = Decoder::new(DecoderConfig::default());
    let mut id = 0;
    bencher.bench_local(|| {
        let section = encoder
            .encode(
                id,
                [
                    (":status", "200"),
                    ("content-type", "application/json"),
                    ("x-repeated-field", "a repeated custom field value"),
                ],
            )
            .unwrap();
        decoder
            .feed_encoder_stream(&encoder.take_encoder_stream())
            .unwrap();
        let fields = decoder.decode_field_section(id, section).unwrap().unwrap();
        assert_eq!(fields.len(), 3);
        encoder
            .feed_decoder_stream(&decoder.take_decoder_stream())
            .unwrap();
        id += 4;
        divan::black_box(fields);
    });
}

// Unknown cancellations are valid feedback even when no dynamic section was
// emitted for that stream. Their cost must not scale with unrelated sections.
#[divan::bench(args = [0, 16, 1024])]
fn qpack_unknown_cancellations(bencher: divan::Bencher, outstanding: usize) {
    let mut encoder = Encoder::new(EncoderConfig {
        max_blocked_streams: outstanding as u64,
        ..EncoderConfig::default()
    });
    for stream in 0..outstanding {
        encoder
            .encode((stream as u64 + 1) * 4, [("x-shared", "value")])
            .unwrap();
    }
    assert_eq!(encoder.tracked_section_count(), outstanding);
    // 0x40 is a complete Stream Cancellation instruction for stream zero.
    let cancellations = vec![0x40; kib(64)];
    bencher
        .counter(divan::counter::BytesCount::new(cancellations.len()))
        .bench_local(|| {
            encoder
                .feed_decoder_stream(divan::black_box(&cancellations))
                .unwrap();
        });
}

// Fragmented feedback repeatedly exercises the bounded partial-integer parser.
// Cost per input byte should remain independent of unrelated live sections.
#[divan::bench(args = [0, 16, 1024])]
fn qpack_fragmented_decoder_feedback(bencher: divan::Bencher, outstanding: usize) {
    let mut encoder = Encoder::new(EncoderConfig {
        max_blocked_streams: outstanding as u64,
        ..EncoderConfig::default()
    });
    for stream in 0..outstanding {
        encoder
            .encode((stream as u64 + 1) * 4, [("x-shared", "value")])
            .unwrap();
    }
    let mut instruction = BytesMut::new();
    DecoderInstruction::StreamCancellation {
        stream_id: VarInt::MAX.into_inner(),
    }
    .encode(&mut instruction);
    let feedback = instruction.repeat(kib(4));
    bencher
        .counter(divan::counter::BytesCount::new(feedback.len()))
        .bench_local(|| {
            for byte in divan::black_box(&feedback) {
                encoder
                    .feed_decoder_stream(std::slice::from_ref(byte))
                    .unwrap();
            }
        });
}

// Both literals use Huffman coding. Bytewise input must probe only their length
// prefixes until complete, rather than repeatedly decoding the first literal.
#[divan::bench(args = [kib(1), kib(4), kib(16)])]
fn qpack_fragmented_encoder_literals(bencher: divan::Bencher, size: usize) {
    let mut wire = BytesMut::new();
    EncoderInstruction::SetDynamicTableCapacity {
        capacity: kib_u64(64),
    }
    .encode(&mut wire);
    EncoderInstruction::InsertWithLiteralName {
        name: Bytes::from(vec![b'a'; size]),
        value: Bytes::from(vec![0xff; size]),
        name_huffman: true,
        value_huffman: true,
    }
    .encode(&mut wire);
    bencher
        .counter(divan::counter::BytesCount::new(wire.len()))
        .bench(|| {
            let mut decoder = Decoder::new(DecoderConfig {
                max_table_capacity: kib_u64(64),
                ..DecoderConfig::default()
            });
            for byte in wire.iter() {
                decoder
                    .feed_encoder_stream(divan::black_box(&[*byte]))
                    .unwrap();
            }
            assert_eq!(decoder.insert_count(), 1);
            divan::black_box(decoder);
        });
}
