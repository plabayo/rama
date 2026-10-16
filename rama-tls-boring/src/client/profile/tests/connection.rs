use super::*;
use crate::server::TlsAcceptorData;
use rama_boring::ssl::Ssl;
use rama_core::{Service, ServiceInput, service::service_fn};
use rama_net::{
    client::{ConnectionError, ConnectionErrorKind, EstablishedClientConnection},
    tls::ApplicationProtocol,
};
use rama_tls::{
    client::{NegotiatedTlsParameters, ServerVerifyMode, TlsServerAuthentication},
    server::{
        CertificateIdentity, GeneratedServerAuthConfig, LeafCertRequest, ServerAuthData,
        TlsServerConfig,
    },
};
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::test]
async fn changed_policy_rejects_before_dial() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let inner = service_fn(move |_input: ConnectRequest| {
        counted.fetch_add(1, Ordering::Relaxed);
        async {
            Err::<
                EstablishedClientConnection<ServiceInput<tokio::io::DuplexStream>, ConnectRequest>,
                _,
            >(ConnectionError::local(
                invalid("unexpected dial"),
                ConnectionErrorKind::Internal,
            ))
        }
    });
    let connector = TlsConnector::auto(inner);
    let request = input();
    connector
        .profile_compiler()
        .prepare(&request, &capture())
        .unwrap()
        .apply(request.extensions());
    TlsClientConfig::new()
        .with_server_verify(ServerVerifyMode::Disable)
        .write_to(request.extensions());
    let error = connector.serve(request).await.unwrap_err();
    assert!(error.to_string().contains("policy changed"), "{error}");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn changed_policy_after_transport_rejects_before_handshake() {
    let inner = service_fn(|input: ConnectRequest| async move {
        TlsClientConfig::new()
            .with_server_verify(ServerVerifyMode::Disable)
            .write_to(input.extensions());
        let (client, _server) = tokio::io::duplex(1024);
        Ok::<_, ConnectionError>(EstablishedClientConnection {
            input,
            conn: ServiceInput::new(client),
        })
    });
    let connector = TlsConnector::secure(inner);
    let request = input();
    connector
        .profile_compiler()
        .prepare(&request, &capture())
        .unwrap()
        .apply(request.extensions());
    let extensions = request.extensions().clone();
    let error = connector.serve(request).await.unwrap_err();
    assert!(error.to_string().contains("policy changed"), "{error}");
    assert!(
        extensions
            .get_ref::<PendingTlsProfile>()
            .unwrap()
            .prepared
            .lock()
            .is_some()
    );
}

#[test]
fn prepared_session_is_bound_and_can_only_be_consumed_once() {
    let connector = TlsConnector::auto(());
    let request = input();
    connector
        .profile_compiler()
        .prepare(&request, &capture())
        .unwrap()
        .apply(request.extensions());
    let pending = request.extensions().get_ref::<PendingTlsProfile>().unwrap();
    pending.check(&request, None).unwrap();
    let changed = ConnectRequest::new("other.test:443".parse().unwrap())
        .with_application_protocol(Protocol::HTTPS);
    changed.extensions().extend(request.extensions());
    assert!(pending.check(&changed, None).is_err());
    #[cfg(feature = "http")]
    {
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_11));
        assert!(pending.check(&request, None).is_err());
        request
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_2));
        pending.check(&request, None).unwrap();
    }
    pending.take().unwrap();
    assert!(pending.check(&request, None).is_err());
    pending.take().unwrap_err();
}

#[tokio::test]
async fn connector_consumes_the_prepared_native_session_with_trust_and_alpn() {
    established(None).await;
}

pub(super) async fn established(
    context: Option<(
        &rama_ua::profile::selection::variants::EmulationContext,
        &ConnectionSelection,
    )>,
) -> rama_core::extensions::Extensions {
    let auth = ServerAuthData::new_generated(GeneratedServerAuthConfig::GeneratedCa {
        ca: Default::default(),
        leaf: LeafCertRequest {
            config: Default::default(),
            identities: [CertificateIdentity::Dns("prepared.test".parse().unwrap())]
                .into_iter()
                .collect(),
        },
    })
    .unwrap();
    let config = TlsClientConfig::new()
        .try_with_server_trust_anchors([auth.cert_chain.last().unwrap().clone()])
        .unwrap();
    let server = TlsAcceptorData::try_from(
        &TlsServerConfig::new()
            .with_single_cert(auth)
            .with_alpn(vec![ApplicationProtocol::HTTP_2].into()),
    )
    .unwrap()
    .into_static_acceptor_builder()
    .unwrap()
    .build();
    let (client_io, server_io) = tokio::io::duplex(32 * 1024);
    let io = Arc::new(Mutex::new(Some(client_io)));
    let inner = service_fn(move |input: ConnectRequest| {
        let io = io.lock().take().unwrap();
        async move {
            Ok::<_, ConnectionError>(EstablishedClientConnection {
                input,
                conn: ServiceInput::new(io),
            })
        }
    });
    let connector = TlsConnector::auto(inner).with_base_config(config);
    let request = input();
    let mut compiled = if let Some((context, selection)) = context {
        context.clone().publish(request.extensions());
        connector
            .profile_compiler()
            .compile(
                &request,
                selection,
                &selection.prepare_components().unwrap(),
                ProfilePreservationMode::Strict,
            )
            .unwrap()
    } else {
        connector
            .profile_compiler()
            .prepare(&request, &capture())
            .unwrap()
    };
    let marker = Ssl::new_ex_index::<bool>().unwrap();
    compiled
        .tls
        .as_mut()
        .unwrap()
        .1
        .prepared
        .get_mut()
        .as_mut()
        .unwrap()
        .client
        .ssl_mut_for_test()
        .set_ex_data(marker, true);
    compiled.apply(request.extensions());
    let client = async {
        let mut connection = connector.serve(request).await.unwrap();
        assert_eq!(
            connection.conn.ssl_ref().unwrap().ex_data(marker),
            Some(&true)
        );
        assert!(
            connection
                .conn
                .extensions()
                .get_ref::<TlsServerAuthentication>()
                .unwrap()
                .0
                .is_some()
        );
        assert_eq!(
            connection
                .conn
                .extensions()
                .get_ref::<NegotiatedTlsParameters>()
                .unwrap()
                .application_layer_protocol,
            Some(ApplicationProtocol::HTTP_2)
        );
        let mut message = [0; 6];
        connection.conn.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"server");
        connection.conn.write_all(b"client").await.unwrap();
        connection.conn.extensions().clone()
    };
    let server = async {
        let mut stream = rama_boring_tokio::accept(&server, server_io).await.unwrap();
        stream.write_all(b"server").await.unwrap();
        let mut message = [0; 6];
        stream.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"client");
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let (connection, ()) = tokio::join!(client, server);
        connection
    })
    .await
    .unwrap()
}
