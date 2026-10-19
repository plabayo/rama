use super::*;
use rama_core::{Service, ServiceInput, service::service_fn};
use rama_net::client::{ConnectionError, EstablishedClientConnection};
use rama_tls::server::peek_client_hello_from_input;
use rama_ua::profile::{format::canonical::ValueId, selection::variants::EmulationContext};
use rama_utils::octets::kib;
use std::time::Duration;

// Native connectors must remain ordinary native connectors even when UA support
// is compiled in. Counted-profile metadata is inert until an adapter consumes it.
#[tokio::test]
async fn native_tls_ignores_counted_profile_metadata_without_an_adapter() {
    let baseline = emitted_native_hello(None).await;
    for pin in [None, Some(ValueId([99; 32]))] {
        let (mut context, _) = super::fixture::selected("native-profile-boundary");
        context.pins.connection = pin;
        let actual = emitted_native_hello(Some(context)).await;
        assert_eq!(
            baseline
                .canonical(TlsCaptureLimits::default())
                .unwrap()
                .bytes,
            actual.canonical(TlsCaptureLimits::default()).unwrap().bytes,
            "neither a valid profile nor a missing pin may change native TLS output"
        );
    }
}

async fn emitted_native_hello(marker: Option<EmulationContext>) -> TlsCapture {
    let request = input();
    if let Some(context) = marker {
        context.publish(request.extensions());
    }
    let (client, server) = tokio::io::duplex(kib(32));
    let client = Arc::new(Mutex::new(Some(client)));
    let transport = service_fn(move |input: ConnectRequest| {
        let stream = client.lock().take().unwrap();
        async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(stream),
            })
        }
    });
    let connector = TlsConnector::auto(transport);
    let client = async {
        // The controlled peer closes after observing the hello, without completing
        // TLS. The test compares native bytes, not a fabricated handshake result.
        drop(connector.serve(request).await.unwrap_err());
    };
    let server = async {
        let (_, hello) =
            peek_client_hello_from_input(ServiceInput::new(server), Some(Duration::from_secs(5)))
                .await
                .unwrap();
        TlsCapture::capture(
            ProfileCaptureCompleteness::Complete,
            TlsCaptureTransport::Tcp,
            &hello.expect("native TLS must still emit its ClientHello"),
            TlsCaptureLimits::default(),
        )
        .unwrap()
    };
    tokio::time::timeout(Duration::from_secs(5), async {
        let ((), capture) = tokio::join!(client, server);
        capture
    })
    .await
    .unwrap()
}
