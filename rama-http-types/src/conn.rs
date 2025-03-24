//! HTTP connection utilities.

use serde::{Deserialize, Serialize};

use crate::proto::h2::{
    PseudoHeaderOrder,
    frame::{SettingsConfig, StreamId},
};

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Context`] of a (h1) request
/// to customise the connection of the h1 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
pub struct Http1ClientContextParams {
    /// Set whether HTTP/1 connections will write header names as title case at
    /// the socket level.
    ///
    /// Default is false.
    pub title_header_case: bool,
}

#[derive(Debug, Clone, Default)]
/// Optional parameters that can be set in the [`Context`] of a (h2) request
/// to customise the connection of the h2 connection.
///
/// Can be used by Http connector services, especially in the context of proxies,
/// where there might not be one static config that is to be applied to all client connections.
pub struct H2ClientContextParams {
    /// Pseudo order of the headers stream
    pub headers_pseudo_order: Option<PseudoHeaderOrder>,

    /// Priority of the headers stream
    pub headers_priority: Option<StreamDependencyParams>,

    /// Priority stream list
    pub priority: Option<Vec<PriorityParams>>,

    /// Config for h2 settings
    pub setting_config: Option<SettingsConfig>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct StreamDependencyParams {
    /// The ID of the stream dependency target
    pub dependency_id: StreamId,

    /// The weight for the stream. The value exposed (and set) here is always in
    /// the range [0, 255], instead of [1, 256] (as defined in section 5.3.2.)
    /// so that the value fits into a `u8`.
    pub weight: u8,

    /// True if the stream dependency is exclusive.
    pub is_exclusive: bool,
}

#[derive(Debug, Clone)]
/// Injected into h2 requests for those who are interested in this.
pub struct LastPeerPriorityParams(pub PriorityParams);

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct PriorityParams {
    pub stream_id: StreamId,
    pub dependency: StreamDependencyParams,
}
