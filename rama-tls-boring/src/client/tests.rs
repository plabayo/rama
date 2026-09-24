use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
};

use rama_boring::ssl::HandshakeError;
use rama_net::{address::Host, tls::ApplicationProtocol};
use rama_tls::client::{TlsClientConfig, parse_client_hello_handshake};

use super::{BoringClientConfigExt, TlsConnectorContextBuilder};

#[test]
fn permutation_is_per_handshake_and_explicit_order_takes_precedence() {
    let declared = [43u16, 10, 13, 16];
    let mut membership = None;
    for (permute, explicit) in [
        (None, false),
        (Some(false), false),
        (Some(true), true),
        (Some(true), false),
    ] {
        let mut config = TlsClientConfig::new()
            .with_server_name(Host::try_from("example.test").unwrap())
            .with_alpn(vec![ApplicationProtocol::HTTP_2].into())
            .with_grease(true)
            .with_extension_order(if explicit {
                declared.into_iter().map(Into::into).collect()
            } else {
                Vec::new()
            });
        if let Some(enabled) = permute {
            config.set_permute_extensions(enabled);
        }
        // Reuse ONE native context: rebuilding it could hide load-time shuffling.
        let context = TlsConnectorContextBuilder::try_from(&config)
            .unwrap()
            .build();
        let mut orders = BTreeSet::new();
        for _ in 0..20 {
            let ssl = context.configure().unwrap().into_ssl().unwrap();
            let Err(HandshakeError::WouldBlock(stream)) = ssl.connect(HelloSink::default()) else {
                panic!("the client must write its first flight before waiting for the server");
            };
            let hello = parse_client_hello_handshake(&stream.get_ref().0).unwrap();
            assert!(hello.extensions().first().unwrap().id().is_grease());
            assert!(hello.extensions().last().unwrap().id().is_grease());
            let mut all_ids: Vec<u16> = hello
                .extensions()
                .iter()
                .map(|ext| ext.id())
                .filter(|id| !id.is_grease())
                .map(Into::into)
                .collect();
            all_ids.sort_unstable();
            assert_eq!(&all_ids, membership.get_or_insert_with(|| all_ids.clone()));
            let order: Vec<u16> = hello
                .extensions()
                .iter()
                .map(|ext| ext.id().into())
                .filter(|id| declared.contains(id))
                .collect();
            let mut ids = order.clone();
            ids.sort_unstable();
            assert_eq!(ids, [10, 13, 16, 43]);
            if explicit {
                assert_eq!(order, declared);
            }
            orders.insert(order);
        }
        if permute == Some(true) && !explicit {
            assert!(
                orders.len() > 1,
                "fresh handshakes must not share one permutation"
            );
        } else {
            assert_eq!(orders.len(), 1);
        }
    }
}

#[derive(Debug, Default)]
struct HelloSink(Vec<u8>);

impl Read for HelloSink {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

impl Write for HelloSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
