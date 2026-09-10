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
#[derive(Debug, Clone, Default, Extension)]
pub struct HttpUpgradeMitmRelayExtensions(pub Extensions);
