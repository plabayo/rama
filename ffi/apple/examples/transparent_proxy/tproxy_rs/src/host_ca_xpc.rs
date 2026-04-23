use std::collections::BTreeMap;

use rama::{
    error::{BoxError, ErrorContext as _, ErrorExt as _, extra::OpaqueError},
    net::apple::xpc::{PeerSecurityRequirement, XpcClientConfig, XpcConnection, XpcMessage},
};

pub(crate) async fn request_ca_key_pem(
    service_name: &str,
    code_requirement: Option<&str>,
    cert_fingerprint_hex: &str,
) -> Result<String, BoxError> {
    let mut config = XpcClientConfig::new(service_name.to_owned());
    if let Some(code_requirement) = code_requirement.filter(|value| !value.is_empty()) {
        config = config.with_peer_requirement(PeerSecurityRequirement::CodeSigning(
            code_requirement.to_owned().into(),
        ));
    }

    let connection =
        XpcConnection::connect(config).context("create host CA XPC client connection")?;

    let mut request = BTreeMap::new();
    request.insert(
        "op".to_owned(),
        XpcMessage::String("get_ca_key_pem".to_owned()),
    );
    request.insert(
        "ca_cert_sha256_hex".to_owned(),
        XpcMessage::String(cert_fingerprint_hex.to_owned()),
    );

    let reply = connection
        .send_request(XpcMessage::Dictionary(request))
        .await
        .context("send host CA XPC request")?;

    let reply = match reply {
        XpcMessage::Dictionary(reply) => reply,
        other => {
            return Err(std::io::Error::other(format!(
                "host CA XPC reply was not a dictionary: {other:?}"
            ))
            .into_box_error());
        }
    };

    if let Some(XpcMessage::String(error)) = reply.get("error") {
        return Err(std::io::Error::other(format!("host CA XPC request failed: {error}"))
            .into_box_error());
    }

    match reply.get("ca_key_pem") {
        Some(XpcMessage::String(value)) => Ok(value.clone()),
        Some(other) => Err(std::io::Error::other(format!(
            "host CA XPC reply field `ca_key_pem` had unexpected type: {other:?}"
        ))
        .into_box_error()),
        None => Err(
            OpaqueError::from_static_str("host CA XPC reply did not include `ca_key_pem`")
                .into_box_error(),
        ),
    }
}
