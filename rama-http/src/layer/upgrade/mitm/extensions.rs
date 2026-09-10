use rama_core::extensions::{Extension, Extensions};

/// Message-local metadata selected for an HTTP MITM upgrade.
///
/// Request matchers can insert this on the matched request to transfer values
/// to the upgraded ingress stream. Response matchers and middleware can insert
/// it on the response to transfer values to the upgraded egress stream.
/// [`HttpUpgradeMitmRelay`](super::HttpUpgradeMitmRelay) transfers these values
/// only after both upgrades succeed, before calling the relay service.
/// The relay reserves a shared response-local selection before returning the
/// response, so outer response middleware can append values before the server
/// completes the ingress upgrade. Use `self_get_ref_or_insert(Self::default)`
/// to extend an existing selection instead of replacing its marker.
///
/// Only a message's own marker is used: a response must not inherit the
/// request's selection through its extension parent chain. The payload should
/// contain independently owned metadata, never the message's extensions or
/// its structural `Ingress`, `Egress`, or `OnUpgrade` state. In particular,
/// snapshots of HTTP parts should have empty extensions to avoid ownership
/// cycles and retaining resources from the HTTP exchange.
///
/// # Migrating response metadata
///
/// The relay previously copied all top-level response extensions onto the
/// egress transport. Inserting a value only on the response no longer transfers
/// it. Custom response matchers and middleware must also select each value
/// needed by the upgraded relay:
///
/// ```
/// use rama_core::extensions::{Extension, ExtensionsRef};
/// use rama_http::{Response, layer::upgrade::mitm::HttpUpgradeMitmRelayExtensions};
///
/// #[derive(Debug, Clone, Extension)]
/// struct NegotiatedProtocol(&'static str);
///
/// let response = Response::new(());
/// let protocol = NegotiatedProtocol("chat");
/// // Keep the value on the HTTP response if HTTP middleware also needs it.
/// response.extensions().insert(protocol.clone());
/// // Append to the shared selection, including when an inner relay reserved it.
/// let selected = &response
///     .extensions()
///     .self_get_ref_or_insert(HttpUpgradeMitmRelayExtensions::default)
///     .0;
/// selected.insert(protocol);
/// # assert_eq!(selected.get_ref::<NegotiatedProtocol>().unwrap().0, "chat");
/// ```
///
/// Use the same pattern on a matched request for ingress metadata. Always use
/// the local lookup shown here so a response cannot reuse its request's
/// selection through the extension parent chain.
#[derive(Debug, Clone, Default, Extension)]
pub struct HttpUpgradeMitmRelayExtensions(pub Extensions);
