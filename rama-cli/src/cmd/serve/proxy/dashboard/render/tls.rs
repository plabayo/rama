use std::fmt;

use rama::tls::{ProtocolVersion, client::ClientHello};

use super::*;

pub(in crate::cmd::serve::proxy::dashboard) fn render_connection_tls(
    details: &InspectorDetails,
) -> impl IntoHtml {
    let tls = details.metadata.connection.get_ref::<TlsObservation>();
    let client_hello = tls.and_then(|tls| tls.client_hello.as_ref());
    let ingress_tls = tls.and_then(|tls| tls.parameters.as_ref());
    let egress_tls = details
        .metadata
        .upstream
        .get_ref::<TlsObservation>()
        .and_then(|tls| tls.parameters.as_ref());
    section!(
        class = "connection-tls",
        div!(
            class = "section-title",
            h2!("TLS on this connection"),
            span!("Observed on request #", details.summary.id)
        ),
        div!(
            class = "tls-layout",
            client_hello.map(render_client_hello_card),
            ingress_tls
                .map(|parameters| render_negotiated_tls_card("Client ↔ inspector", parameters)),
            egress_tls
                .map(|parameters| render_negotiated_tls_card("Inspector ↔ server", parameters)),
            render_connection_fingerprint_card(&details.summary),
        )
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn tls_version_label(
    version: ProtocolVersion,
) -> impl fmt::Display + Clone {
    rama::utils::fmt::display_fn(move |f: &mut fmt::Formatter<'_>| {
        f.write_str(match version {
            ProtocolVersion::SSLv2 => "SSL 2.0",
            ProtocolVersion::SSLv3 => "SSL 3.0",
            ProtocolVersion::TLSv1_0 => "TLS 1.0",
            ProtocolVersion::TLSv1_1 => "TLS 1.1",
            ProtocolVersion::TLSv1_2 => "TLS 1.2",
            ProtocolVersion::TLSv1_3 => "TLS 1.3",
            ProtocolVersion::DTLSv1_0 => "DTLS 1.0",
            ProtocolVersion::DTLSv1_2 => "DTLS 1.2",
            ProtocolVersion::DTLSv1_3 => "DTLS 1.3",
            ProtocolVersion::Unknown(value) => return write!(f, "Unknown ({value:#06x})"),
        })
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn tls_fact(
    label: &'static str,
    value: impl fmt::Display + Clone,
) -> impl IntoHtml {
    div!(
        class = "tls-fact",
        span!(label),
        code!(title = display(value.clone()), display(value))
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_tls_offer_list(
    label: &'static str,
    values: impl ExactSizeIterator<Item = impl fmt::Display + Clone>,
) -> Option<impl IntoHtml> {
    let count = values.len();
    (count != 0).then(|| {
        details!(
            class = "tls-offer",
            summary!(
                span!(class = "tls-offer-title", label),
                span!(class = "tls-offer-count", count, " offered"),
                span!(class = "tls-offer-chevron", "aria-hidden" = "true", "›")
            ),
            ol!(
                class = "tls-offer-list",
                values.map(|value| li!(code!(title = display(value.clone()), display(value))))
            )
        )
    })
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_client_hello_card(
    hello: &ClientHello,
) -> impl IntoHtml {
    let versions = rama::utils::fmt::display_fn(|f: &mut fmt::Formatter<'_>| {
        match hello.supported_versions() {
            Some(versions) => rama::utils::fmt::write_joined(
                f,
                versions.iter().copied().map(tls_version_label),
                ", ",
            ),
            None => write!(f, "{}", tls_version_label(hello.protocol_version())),
        }
    });
    let alpn = rama::utils::fmt::display_fn(|f: &mut fmt::Formatter<'_>| {
        match hello.ext_alpn().filter(|protocols| !protocols.is_empty()) {
            Some(protocols) => rama::utils::fmt::write_joined(f, protocols, ", "),
            None => f.write_str("Not offered"),
        }
    });
    section!(
        class = "detail-card tls-card client-hello-card",
        div!(
            class = "card-title",
            h3!("Client hello"),
            span!("offered by client")
        ),
        div!(
            class = "tls-facts",
            hello
                .ext_server_name()
                .map(|name| tls_fact("Server name", name)),
            tls_fact("Supported TLS", versions),
            tls_fact("ALPN", alpn),
            tls_fact("Cipher suites", hello.cipher_suites().len()),
            tls_fact("Extensions", hello.extensions().len()),
            hello
                .ext_supported_groups()
                .map(|groups| tls_fact("Supported groups", groups.len())),
            hello
                .ext_signature_algorithms()
                .map(|algorithms| tls_fact("Signature algorithms", algorithms.len())),
            hello
                .has_encrypted_client_hello()
                .then(|| tls_fact("Encrypted ClientHello", "Offered")),
        ),
        div!(
            class = "tls-offers",
            render_tls_offer_list("Cipher suites", hello.cipher_suites().iter()),
            render_tls_offer_list(
                "Extensions",
                hello.extensions().iter().map(|extension| extension.id())
            ),
            hello
                .ext_supported_groups()
                .and_then(|groups| render_tls_offer_list("Supported groups", groups.iter())),
            hello
                .ext_signature_algorithms()
                .and_then(|algorithms| render_tls_offer_list(
                    "Signature algorithms",
                    algorithms.iter()
                )),
        )
    )
}

pub(in crate::cmd::serve::proxy::dashboard) fn render_negotiated_tls_card(
    title: &'static str,
    parameters: &CapturedTlsParameters,
) -> impl IntoHtml {
    section!(
        class = "detail-card tls-card negotiated-tls-card",
        div!(class = "card-title", h3!(title), span!("negotiated")),
        div!(
            class = "tls-facts",
            tls_fact(
                "TLS version",
                tls_version_label(parameters.protocol_version)
            ),
            tls_fact(
                "Application protocol",
                rama::utils::fmt::display_fn(|f: &mut fmt::Formatter<'_>| {
                    match &parameters.application_layer_protocol {
                        Some(protocol) => write!(f, "{protocol}"),
                        None => f.write_str("Not negotiated"),
                    }
                })
            ),
            parameters
                .peer_certificate_count
                .map(|count| tls_fact("Peer certificates", count)),
        )
    )
}
