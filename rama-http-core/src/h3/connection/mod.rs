//! Connection-owned compression and critical-stream state.

use super::{
    DatagramConfig, Error,
    control::{Control, Role},
    frame::{FrameDecoder, FrameEvent},
    observation::{
        FirstRequestObservation, H3Observer, Recorder, RequestQpackPrefix, SettingsObservation,
    },
    qlog::{self, ControlFrame, Initiator},
    qpack::{Decoder, DecoderConfig, EncodeField, Encoder, EncoderConfig, FieldPair, QpackError},
};
use crate::server::conn::{HeaderReadTimeout, IdleTimeout};
use parking_lot::Mutex;
use rama_core::{
    bytes::{Bytes, BytesMut},
    extensions::{Extensions, ExtensionsRef},
    telemetry::tracing,
};
use rama_http::{
    datagram::{NativeRecvError, ViolationPolicy},
    headers::Priority,
};
use rama_http_types::proto::h3::{
    Code, FrameHeader, FrameType, Setting, SettingId, Settings, StreamType, VarInt, VarIntDecoder,
    control::ClientControlPreferences,
    critical_streams::{
        Order as CriticalStreamOrder, Preferences as CriticalStreamPreferences,
        Startup as CriticalStreamStartup,
    },
    observation::{
        H3ObservationSnapshot, H3RequestObservation, ObservationLimits, ObservedFieldRepresentation,
    },
    qpack::FieldSectionBase,
};
use rama_net::{stream::SocketInfo, tls::ApplicationProtocol};
use rama_quic::{
    Connection as QuicConnection, NegotiatedTlsParameters, RecvStream as QuicRecvStream,
    SendStream as QuicSendStream, StreamAbortHandle, TransportConfig, qlog::ConnectionQlogControl,
};
use rama_quic_proto::{Dir, coding::Codec};
use rama_utils::{
    octets::{kib, mib},
    reactive::{Change, ChangeListener, ChangeSignal},
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    pin::pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::{
    sync::{Notify, oneshot},
    time::{Instant, timeout_at},
};

mod critical_streams;
pub(super) mod receive;

/// Local HTTP/3 connection budgets. Peer limits are negotiated independently.
#[derive(Clone, Debug)]
pub struct Config {
    /// Optional independent budgets for wire observation; disabled by default.
    pub observation: Option<Box<ObservationLimits>>,
    /// Optional literal SETTINGS order, including unknown and reserved identifiers.
    ///
    /// QPACK values must match `decoder`; an omitted QPACK setting means zero.
    /// An explicit field-section limit must match the decoder's local limit.
    /// Server Extended CONNECT must match the application's capability;
    /// datagrams must match negotiated transport support. Client
    /// ENABLE_CONNECT_PROTOCOL values are preserved but grant no permission.
    /// Incompatible profiles fail before HTTP/3 control bytes are emitted.
    /// Ordinary connections allocate no profile.
    pub settings_profile: Option<Arc<Settings>>,
    /// QPACK stream allocation order and whether idle type prefixes are sent.
    pub critical_streams: CriticalStreamPreferences,
    /// Additional client frames after SETTINGS; disabled by default.
    pub client_control: Option<Arc<ClientControlPreferences>>,
    /// Local QPACK decoder limits, advertised where the protocol defines settings.
    pub decoder: DecoderConfig,
    /// Local encoder budgets. Peer capacity/blocked-stream settings override those fields.
    pub encoder: EncoderConfig,
    /// Maximum concurrent application requests retained by the engine.
    pub max_requests: usize,
    /// Deadline for incomplete server request heads, including blocked QPACK sections.
    /// `None` disables the deadline.
    pub header_read_timeout: Option<HeaderReadTimeout>,
    /// Server connection idle budgets. `None` disables the deadline.
    pub idle_timeout: Option<IdleTimeout>,
    /// Lifetime push quota; zero disables push. Bounds reordered push state.
    pub max_pushes: usize,
    /// Maximum buffered encoded non-DATA frame.
    ///
    /// This local wire-memory budget is independent of the decoded field-section
    /// size advertised in SETTINGS. QPACK literals can expand on the wire, so
    /// exceeding this bound is excessive load even for an otherwise valid field
    /// section (RFC 9114 §10.5.1). Increase both limits for large-header peers.
    pub max_frame_size: usize,
    /// Maximum QUIC chunk held by a stream reader.
    pub read_chunk_size: usize,
    /// Maximum unclassified peer unidirectional streams retained simultaneously.
    pub max_pending_uni_streams: usize,
    /// Accept Extended CONNECT (RFC 9220) as a server, advertising
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`. The service decides which `:protocol`
    /// tokens it serves; RFC 9220 §3 recommends `501` for others.
    pub extended_connect: bool,
    /// Receive HTTP/3 datagrams (RFC 9297). When QUIC DATAGRAM is negotiated this advertises
    /// `SETTINGS_H3_DATAGRAM`, as RFC 9297 §2.1.1 recommends for every endpoint able to
    /// receive them; `None` never advertises nor delivers them. A request only has datagram
    /// semantics once declared with
    /// [`HttpDatagrams`](rama_http_types::proto::ext::HttpDatagrams).
    pub datagrams: Option<DatagramConfig>,
    /// Reject, rather than drop, `Content-Length` or `Transfer-Encoding` on a successful response to CONNECT,
    /// which RFC 9110 §9.3.6 forbids as a tunnel follows the response.
    pub strict_connect_framing: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            observation: None,
            settings_profile: None,
            critical_streams: CriticalStreamPreferences::default(),
            client_control: None,
            decoder: DecoderConfig::default(),
            encoder: EncoderConfig::default(),
            max_requests: 128,
            header_read_timeout: Some(HeaderReadTimeout::default()),
            idle_timeout: Some(IdleTimeout::default()),
            max_pushes: 0,
            max_frame_size: kib(64),
            read_chunk_size: kib(16),
            max_pending_uni_streams: 32,
            extended_connect: false,
            datagrams: Some(DatagramConfig::default()),
            strict_connect_framing: false,
        }
    }
}

impl Config {
    /// Apply literal client SETTINGS within this configuration's receive budgets.
    ///
    /// Omitted QPACK values mean zero. The profile can lower configured limits;
    /// larger values are lowered to them and a datagram grant this configuration
    /// disables is dropped, keeping the order of every other entry. An omitted
    /// field-section limit keeps the local finite resource budget. Client
    /// ENABLE_CONNECT_PROTOCOL values are retained without enabling Extended
    /// CONNECT: only the server's setting grants that permission.
    pub fn try_with_client_settings(&self, settings: Arc<Settings>) -> Result<Self, Error> {
        let settings = self.fit_settings_profile(settings, false);
        let mut configured = self.clone();
        configured.decoder.max_table_capacity = settings.qpack_max_table_capacity();
        configured.decoder.max_blocked_streams = settings.qpack_blocked_streams();
        if let Some(limit) = settings.max_field_section_size() {
            configured.decoder.max_field_section_size =
                usize::try_from(limit).map_err(|_error| {
                    Error::connection(
                        Code::H3_INTERNAL_ERROR,
                        "field section limit exceeds platform range",
                    )
                })?;
        }
        if !settings.h3_datagram() {
            configured.datagrams = None;
        }
        configured.settings_profile = Some(settings);
        configured.settings()?;
        Ok(configured)
    }

    /// Apply literal server SETTINGS within existing receive budgets and capabilities.
    ///
    /// Omitted QPACK values mean zero. An Extended CONNECT grant without the local
    /// capability is dropped; a false or omitted value disables it. Datagram policy
    /// and receive budgets cannot be enabled or raised by the supplied settings.
    /// The native handshake also drops grants the QUIC transport cannot carry.
    pub fn try_with_server_settings(&self, settings: Arc<Settings>) -> Result<Self, Error> {
        let settings = self.fit_settings_profile(settings, true);
        let extended_connect = settings.enable_connect_protocol();
        let mut configured = self.try_with_client_settings(settings)?;
        configured.extended_connect = extended_connect;
        Ok(configured)
    }

    /// `profile` lowered to this configuration's decoder budgets, without grants it
    /// cannot honour. Entry order is kept; every change is traced.
    fn fit_settings_profile(&self, profile: Arc<Settings>, server: bool) -> Arc<Settings> {
        let ceiling = |setting: &Setting| match setting.id {
            SettingId::QPACK_MAX_TABLE_CAPACITY => Some(self.decoder.max_table_capacity),
            SettingId::QPACK_BLOCKED_STREAMS => Some(self.decoder.max_blocked_streams),
            SettingId::MAX_FIELD_SECTION_SIZE => Some(self.decoder.max_field_section_size as u64),
            _ => None,
        };
        let unavailable = |setting: &Setting| {
            setting.value == 1
                && match setting.id {
                    SettingId::H3_DATAGRAM => self.datagrams.is_none(),
                    SettingId::ENABLE_CONNECT_PROTOCOL => server && !self.extended_connect,
                    _ => false,
                }
        };
        if !profile.entries().iter().any(|setting| {
            unavailable(setting) || ceiling(setting).is_some_and(|ceiling| setting.value > ceiling)
        }) {
            return profile;
        }
        let mut fitted = Settings::new();
        for setting in profile.entries() {
            if unavailable(setting) {
                tracing::debug!(id = ?setting.id, "HTTP/3 SETTINGS profile drops an unavailable grant");
                continue;
            }
            let value =
                ceiling(setting).map_or(setting.value, |ceiling| setting.value.min(ceiling));
            if value != setting.value {
                tracing::debug!(
                    id = ?setting.id,
                    value = setting.value,
                    local = value,
                    "HTTP/3 SETTINGS profile lowers a value to the local budget"
                );
            }
            // Lowering keeps decoded entries unique and valid.
            if let Err(error) = fitted.set(setting.id, value) {
                tracing::debug!(%error, "HTTP/3 SETTINGS profile drops an entry");
            }
        }
        Arc::new(fitted)
    }

    /// Set optional client control frames without exceeding this configuration's budgets.
    /// Invalid input leaves the existing configuration unchanged.
    pub fn try_set_client_controls(
        &mut self,
        preferences: Option<Arc<ClientControlPreferences>>,
    ) -> Result<(), Error> {
        self.validate_client_controls(preferences.as_deref())?;
        self.client_control = preferences;
        Ok(())
    }

    fn validate_client_controls(
        &self,
        preferences: Option<&ClientControlPreferences>,
    ) -> Result<(), Error> {
        let Some(preferences) = preferences else {
            return Ok(());
        };
        let bytes = preferences.frames.iter().try_fold(0usize, |total, frame| {
            total.checked_add(frame.encoded_len()?)
        });
        if preferences.frames.len()
            > self
                .max_requests
                .saturating_add(self.max_pushes)
                .saturating_add(16)
            || bytes.is_none_or(|bytes| bytes > self.max_frame_size)
        {
            return Err(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "invalid or over-budget client control preferences",
            ));
        }
        Ok(())
    }

    /// Apply finite HTTP/3 receive budgets to a QUIC transport configuration.
    /// Configure the endpoint before establishing connections.
    pub fn configure_transport(&self, transport: &mut TransportConfig) -> Result<(), Error> {
        self.settings()?;
        transport.set_max_concurrent_bidi_streams(
            VarInt::from_u64(self.max_requests as u64).map_err(|_error| {
                Error::connection(Code::H3_INTERNAL_ERROR, "request limit too large")
            })?,
        );
        transport.set_max_concurrent_uni_streams(
            VarInt::from_u64(self.max_pending_uni_streams as u64).map_err(|_error| {
                Error::connection(Code::H3_INTERNAL_ERROR, "stream limit too large")
            })?,
        );
        transport.set_stream_receive_window(VarInt::from_u32(kib(256) as u32));
        transport.set_receive_window(VarInt::from_u32(mib(8) as u32));
        Ok(())
    }

    /// The SETTINGS this endpoint sends. Only a server's ENABLE_CONNECT_PROTOCOL
    /// grants permission; literal client values have no effect (RFC 9220 §3).
    /// `datagrams` is whether QUIC DATAGRAM was negotiated and datagrams are enabled.
    pub(crate) fn local_settings(&self, role: Role, datagrams: bool) -> Result<Settings, Error> {
        if role != Role::Client && self.client_control.is_some() {
            return Err(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "client control preferences require a client connection",
            ));
        }
        let mut settings = self.settings()?;
        let extended_connect = role == Role::Server && self.extended_connect;
        if self.settings_profile.is_some() {
            // A captured grant this connection cannot honour is dropped; an omitted
            // capability is not advertised, so the peer never uses it.
            let unavailable = |setting: &Setting| match setting.id {
                SettingId::ENABLE_CONNECT_PROTOCOL => {
                    role == Role::Server && setting.value == 1 && !extended_connect
                }
                SettingId::H3_DATAGRAM => setting.value == 1 && !datagrams,
                _ => false,
            };
            if settings.entries().iter().any(unavailable) {
                tracing::debug!("HTTP/3 SETTINGS profile drops grants this connection lacks");
                let mut fitted = Settings::new();
                for setting in settings
                    .entries()
                    .iter()
                    .filter(|setting| !unavailable(setting))
                {
                    fitted.insert(*setting).map_err(|_error| {
                        Error::connection(Code::H3_INTERNAL_ERROR, "invalid local settings")
                    })?;
                }
                return Ok(fitted);
            }
            return Ok(settings);
        }

        for (enabled, id) in [
            (extended_connect, SettingId::ENABLE_CONNECT_PROTOCOL),
            (datagrams, SettingId::H3_DATAGRAM),
        ] {
            if enabled {
                settings.set(id, 1).map_err(|_error| {
                    Error::connection(Code::H3_INTERNAL_ERROR, "invalid local settings")
                })?;
            }
        }
        Ok(settings)
    }

    pub(crate) fn settings(&self) -> Result<Settings, Error> {
        self.validate_client_controls(self.client_control.as_deref())?;
        if self.max_requests == 0
            || self.max_requests > tokio::sync::Semaphore::MAX_PERMITS
            || self.max_requests > u32::MAX as usize
            || self.max_pushes > self.max_requests
            || self.read_chunk_size == 0
            || self.max_pending_uni_streams < 3
            || self.decoder.max_decoder_stream_bytes < 10
        {
            return Err(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "invalid HTTP/3 resource budgets",
            ));
        }
        if let Some(profile) = &self.settings_profile {
            // Settings omitted from a capture retain their protocol defaults. In
            // particular, absence must not advertise a zero QPACK capacity while
            // the decoder accepts a larger table (or decodes modulo that capacity).
            if profile.qpack_max_table_capacity() != self.decoder.max_table_capacity
                || profile.qpack_blocked_streams() != self.decoder.max_blocked_streams
                || profile
                    .max_field_section_size()
                    .is_some_and(|limit| limit != self.decoder.max_field_section_size as u64)
                || profile.entries().iter().any(|setting| {
                    VarInt::from_u64(setting.id.value()).is_err()
                        || VarInt::from_u64(setting.value).is_err()
                })
            {
                return Err(Error::connection(
                    Code::H3_INTERNAL_ERROR,
                    "HTTP/3 SETTINGS profile contradicts decoder limits or wire bounds",
                ));
            }
            return Ok(profile.as_ref().clone());
        }

        let mut settings = Settings::new();
        for (id, value) in [
            (
                SettingId::QPACK_MAX_TABLE_CAPACITY,
                self.decoder.max_table_capacity,
            ),
            (
                SettingId::QPACK_BLOCKED_STREAMS,
                self.decoder.max_blocked_streams,
            ),
            (
                SettingId::MAX_FIELD_SECTION_SIZE,
                self.decoder.max_field_section_size as u64,
            ),
        ] {
            if VarInt::from_u64(value).is_err() {
                return Err(Error::connection(
                    Code::H3_INTERNAL_ERROR,
                    "setting exceeds QUIC integer range",
                ));
            }
            settings.set(id, value).map_err(|_error| {
                Error::connection(Code::H3_INTERNAL_ERROR, "invalid local settings")
            })?;
        }
        Ok(settings)
    }
}

/// Capabilities the peer advertised in its SETTINGS.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PeerSettings {
    pub(crate) extended_connect: bool,
}

// Uncontended in steady state: the driver files, one consumer per association drains.
type DatagramDemux = Mutex<super::datagram::Demux>;

// Enough for multiple decoder acknowledgements and GOAWAY; ordinary writes leave
// this credit for critical streams. QUIC caps it for very small peer windows.
pub(crate) const CRITICAL_SEND_RESERVE: u64 = 64;

type Decoded = Result<Vec<FieldPair>, Error>;
struct State {
    observation: Option<Box<Recorder>>,
    control: Control,
    encoder: Encoder,
    decoder: Decoder,
    waiting: BTreeMap<u64, oneshot::Sender<Decoded>>,
    cancelled: BTreeSet<u64>,
    error: Option<Error>,
    control_output: VecDeque<(Bytes, ControlFrame)>,
    control_in_flight: bool,
    receive_closed: bool,
    local_goaway: Option<u64>,
}

pub(crate) struct Shared {
    pub(crate) qlog: Option<ConnectionQlogControl>,
    pub(crate) role: Role,
    pub(crate) pushes: Mutex<super::push::State>,
    pub(crate) push_ready: Notify,
    pub(crate) transport_extensions: Extensions,
    state: Mutex<State>,
    encoder_stream: Mutex<Option<critical_streams::EncoderStream>>,
    pub(crate) config: Config,
    decoder_output_ready: Notify,
    progress: Notify,
    request_rejected: Notify,
    /// Pushed with `request_rejected`: a GOAWAY or a failure ends admission.
    admission_ended: ChangeSignal,
    failure: Notify,
    control_ready: Notify,
    settings_ready: Notify,
    datagrams: DatagramDemux,
    local_datagrams: AtomicBool,
    peer_datagrams: AtomicBool,
    // Our initial SETTINGS reached the QUIC control stream.
    settings_sent: AtomicBool,
    pub(crate) schedule: super::priority::Schedule,
}

impl State {
    fn begin_observation_control_batch(&mut self) {
        if let Some(record) = &mut self.observation {
            record.control_batch_active = true;
        }
    }

    fn end_observation_control_batch(&mut self) {
        if let Some(record) = &mut self.observation {
            record.control_batch_active = false;
        }
    }

    fn freeze_first_request_observation(&mut self) -> bool {
        if self.control.settings().is_none()
            || self.observation.as_ref().is_none_or(|record| {
                record.request_qpack.is_none()
                    || record.control_batch_active
                    || record.first_request.get().is_some()
            })
        {
            return false;
        }
        let Self {
            observation,
            decoder,
            error,
            ..
        } = self;
        let Some(record) = observation else {
            return false;
        };
        let Some(prefix) = record.request_qpack else {
            return false;
        };
        let instructions = decoder.instruction_observation().map(|(instructions, _)| {
            let retained = prefix.instruction_count.min(instructions.len());
            (
                &instructions[..retained],
                prefix.complete && retained == prefix.instruction_count,
            )
        });
        let snapshot = record.request_snapshot(
            instructions,
            decoder
                .encoder_bindings()
                .map(|bindings| (bindings, prefix.bindings_complete)),
            error.map(Error::code),
        );
        // Budget failures stay frozen too; a later request cannot replace this
        // incomplete boundary with apparently complete evidence.
        record.first_request.set(snapshot).is_ok()
    }

    fn observation_snapshot(&mut self) -> Option<Arc<H3ObservationSnapshot>> {
        let Self {
            observation,
            decoder,
            error,
            ..
        } = self;
        observation.as_mut().map(|record| {
            record.snapshot(
                decoder.instruction_observation(),
                decoder.encoder_bindings(),
                error.map(Error::code),
            )
        })
    }
}

impl Shared {
    fn publish_first_request_observation(&self) {
        let published = self.state.lock().freeze_first_request_observation();
        if published {
            self.settings_ready.notify_waiters();
        }
    }

    fn register_peer_uni(&self, stream_id: u64, ty: StreamType) -> Result<(), Error> {
        let mut state = self.state.lock();
        if let Some(observation) = &mut state.observation {
            observation.stream(stream_id, ty);
        }
        state.control.register(ty)?;
        drop(state);
        qlog::stream_type(self.qlog.as_ref(), Initiator::Remote, stream_id, ty);
        Ok(())
    }

    pub(super) fn observation_snapshot(&self) -> Option<Arc<H3ObservationSnapshot>> {
        self.state.lock().observation_snapshot()
    }

    pub(super) async fn observation_first_request(
        &self,
        deadline: Instant,
        unavailable: &Arc<H3ObservationSnapshot>,
    ) -> FirstRequestObservation {
        loop {
            let ready = self.settings_ready.notified();
            let mut ready = pin!(ready);
            ready.as_mut().enable();
            {
                let mut state = self.state.lock();
                if let Some(snapshot) = state
                    .observation
                    .as_ref()
                    .and_then(|record| record.first_request.get())
                {
                    return FirstRequestObservation::Ready(snapshot.clone());
                }
                let error = state.error;
                if error.is_some() || Instant::now() >= deadline {
                    let snapshot = state
                        .observation_snapshot()
                        .unwrap_or_else(|| unavailable.clone());
                    return if let Some(error) = error {
                        FirstRequestObservation::Closed {
                            snapshot,
                            error: Some(error.code()),
                        }
                    } else {
                        FirstRequestObservation::TimedOut(snapshot)
                    };
                }
            }
            _ = timeout_at(deadline, ready).await;
        }
    }

    pub(super) async fn observation_settings(
        &self,
        deadline: Instant,
        unavailable: &Arc<H3ObservationSnapshot>,
    ) -> SettingsObservation {
        loop {
            let ready = self.settings_ready.notified();
            let mut ready = pin!(ready);
            ready.as_mut().enable();
            {
                let mut state = self.state.lock();
                let received = state.control.settings().is_some();
                let batching = state
                    .observation
                    .as_ref()
                    .is_some_and(|record| record.control_batch_active);
                let error = state.error;
                let closed = error.is_some();
                if (received && !batching) || closed || Instant::now() >= deadline {
                    let snapshot = state
                        .observation_snapshot()
                        .unwrap_or_else(|| unavailable.clone());
                    return if received {
                        SettingsObservation::Received(snapshot)
                    } else if closed {
                        SettingsObservation::Closed {
                            snapshot,
                            error: error.map(Error::code),
                        }
                    } else {
                        SettingsObservation::TimedOut(snapshot)
                    };
                }
            }
            _ = timeout_at(deadline, ready).await;
        }
    }

    pub(crate) fn request_observation(
        self: &Arc<Self>,
        stream_id: u64,
        fields: &[FieldPair],
    ) -> Option<(H3Observer, H3RequestObservation)> {
        let limits = self.config.observation.as_deref()?;
        let mut state = self.state.lock();
        let record = state.observation.as_mut()?;
        let unavailable = record.unavailable.clone();
        let initial_request = record.request_qpack.is_none();
        let first_request = record.first_request.clone();
        if initial_request {
            state.decoder.bind_initial_request(stream_id, fields);
            let bindings_complete = state
                .decoder
                .encoder_bindings()
                .is_some_and(|bindings| bindings.complete);
            let prefix = state.decoder.instruction_observation().map_or(
                RequestQpackPrefix {
                    instruction_count: 0,
                    complete: false,
                    bindings_complete,
                },
                |(instructions, complete)| RequestQpackPrefix {
                    instruction_count: instructions.len(),
                    complete,
                    bindings_complete,
                },
            );
            let record = state.observation.as_mut()?;
            record.request_qpack = Some(prefix);
            record.changed();
        }
        let snapshot = state.observation_snapshot()?;
        let captured = state.decoder.take_field_observation(stream_id);
        let captured_complete = captured.is_some();
        let retained = captured.unwrap_or_default();
        let priority_field = fields.iter().find(|field| field.name == b"priority"[..]);
        let priority = priority_field.and_then(|field| {
            (field.value.len()
                <= limits.bytes.saturating_sub(
                    retained
                        .len()
                        .saturating_mul(size_of::<ObservedFieldRepresentation>()),
                ))
            .then(|| Box::from(&field.value[..]))
        });
        let fields_complete = captured_complete
            && retained.len() == fields.len()
            && (priority_field.is_none() || priority.is_some());
        drop(state);
        if initial_request {
            // SETTINGS may already be decoded while the receive owner is idle.
            self.progress.notify_waiters();
        }
        Some((
            H3Observer::new(self, unavailable),
            H3RequestObservation {
                stream_id,
                connection: snapshot,
                first_request,
                fields: retained,
                fields_complete,
                priority,
            },
        ))
    }

    pub(crate) fn from_connection(
        config: Config,
        role: Role,
        connection: &QuicConnection,
    ) -> Result<Arc<Self>, Error> {
        if config.settings_profile.is_some() {
            let datagrams = config.datagrams.is_some() && connection.datagram_receive_enabled();
            config.local_settings(role, datagrams)?;
        }

        let extensions = connection.extensions().clone();
        // Preserve connector-provided certificate chains and local addresses.
        // CONNECT streams fork this store, keeping stream metadata isolated.
        if !extensions.contains::<NegotiatedTlsParameters>()
            && let Some(parameters) = connection.handshake_data()
        {
            extensions.insert(parameters);
        }
        extensions.get_ref_or_insert(|| SocketInfo::new(None, connection.remote_address().into()));
        let shared = Self::create(config, role, extensions, connection.qlog_control())?;
        // Known from the transport parameters: request streams register from the start.
        shared.local_datagrams.store(
            shared.local_datagrams_supported(connection),
            Ordering::Release,
        );
        Ok(shared)
    }

    /// Datagrams are enabled and this endpoint receives QUIC DATAGRAM frames, whatever the
    /// peer supports: what `SETTINGS_H3_DATAGRAM` advertises (RFC 9297 §2.1.1).
    fn local_datagrams_supported(&self, connection: &QuicConnection) -> bool {
        self.config.datagrams.is_some() && connection.datagram_receive_enabled()
    }

    #[cfg(any(test, feature = "fuzz-utils"))]
    pub(crate) fn new(
        config: Config,
        role: Role,
        transport_extensions: Extensions,
    ) -> Result<Arc<Self>, Error> {
        Self::create(config, role, transport_extensions, None)
    }

    fn create(
        config: Config,
        role: Role,
        transport_extensions: Extensions,
        qlog: Option<ConnectionQlogControl>,
    ) -> Result<Arc<Self>, Error> {
        let local_settings = config.settings()?;
        let mut decoder = Decoder::new(config.decoder);
        let mut encoder = Encoder::before_peer_settings(config.encoder);
        decoder.set_qlog(qlog.clone());
        encoder.set_qlog(qlog.clone());
        if let Some(limits) = config.observation.as_deref() {
            decoder.observe(*limits);
        }
        Ok(Arc::new(Self {
            qlog,
            role,
            pushes: Mutex::new(super::push::State::new()),
            push_ready: Notify::new(),
            transport_extensions,
            encoder_stream: Mutex::new(None),
            state: Mutex::new(State {
                observation: config
                    .observation
                    .as_deref()
                    .map(|limits| Box::new(Recorder::new(*limits, &local_settings))),
                control: Control::new(role),
                encoder,
                decoder,
                waiting: BTreeMap::new(),
                cancelled: BTreeSet::new(),
                error: None,
                control_output: VecDeque::new(),
                control_in_flight: false,
                receive_closed: false,
                local_goaway: None,
            }),
            schedule: super::priority::Schedule::new(
                config.max_requests.saturating_add(config.max_pushes),
            ),
            config,
            decoder_output_ready: Notify::new(),
            progress: Notify::new(),
            request_rejected: Notify::new(),
            admission_ended: ChangeSignal::new(),
            failure: Notify::new(),
            control_ready: Notify::new(),
            settings_ready: Notify::new(),
            datagrams: Mutex::default(),
            local_datagrams: AtomicBool::new(false),
            peer_datagrams: AtomicBool::new(false),
            settings_sent: AtomicBool::new(false),
        }))
    }

    #[cfg(test)]
    pub(crate) fn dynamic_insert_count(&self) -> u64 {
        self.state.lock().encoder.insert_count()
    }

    pub(crate) fn error(&self) -> Option<Error> {
        self.state.lock().error
    }

    /// Preserve an already-discovered fatal cause when an owner releases transport.
    pub(crate) fn close_code(&self) -> VarInt {
        let code = self.error().map_or(Code::H3_NO_ERROR, Error::code);
        VarInt::from_u64(code.value())
            .unwrap_or(VarInt::from_u32(Code::H3_INTERNAL_ERROR.value() as u32))
    }

    /// A clean connection close still permits draining received stream data and FIN.
    pub(crate) fn receive_error(&self) -> Option<Error> {
        self.receive_error_for_stream(None)
    }

    pub(crate) fn receive_error_for_stream(&self, request_id: Option<u64>) -> Option<Error> {
        let state = self.state.lock();
        if request_id.is_some_and(|id| state.control.goaway().is_some_and(|limit| id >= limit)) {
            return Some(Error::stream(
                Code::H3_REQUEST_REJECTED,
                "request excluded by GOAWAY",
            ));
        }
        state.error.filter(|error| !error.is_clean_close())
    }

    pub(crate) fn fail(&self, error: Error) {
        let mut state = self.state.lock();
        if state.error.is_none_or(Error::is_clean_close) {
            state.error = Some(error);
        }
        let error = state.error.unwrap_or(error);
        for (id, tx) in std::mem::take(&mut state.waiting) {
            state.decoder.drop_blocked_stream(id);
            let error = if state.control.goaway().is_some_and(|limit| id >= limit) {
                Error::stream(Code::H3_REQUEST_REJECTED, "request excluded by GOAWAY")
            } else if error.is_clean_close() {
                error.incomplete("connection closed before required QPACK inserts")
            } else {
                error
            };
            _ = tx.send(Err(error));
        }
        drop(state);
        let wakers = self.datagrams.lock().close();
        wakers.into_iter().for_each(Waker::wake);
        self.progress.notify_waiters();
        self.push_ready.notify_waiters();
        self.failure.notify_waiters();
        self.request_rejected.notify_waiters();
        self.admission_ended.notify(Change::Other);
        self.settings_ready.notify_waiters();
        self.decoder_output_ready.notify_one();
    }

    pub(crate) async fn failed(&self) -> Error {
        loop {
            let failed = self.failure.notified();
            let mut failed = pin!(failed);
            failed.as_mut().enable();
            if let Some(error) = self.error() {
                return error;
            }
            failed.await;
        }
    }

    /// GOAWAY proves these requests were not processed, even after connection close.
    pub(crate) fn rejection(&self, id: Option<u64>) -> Option<Error> {
        self.goaway()
            .filter(|limit| id.is_none_or(|id| id >= *limit))
            .map(|_| Error::stream(Code::H3_REQUEST_REJECTED, "request excluded by GOAWAY"))
    }

    /// Wake `listener` once a GOAWAY or a failure ends request admission.
    pub(crate) fn subscribe_admission_end(&self, listener: Weak<dyn ChangeListener>) {
        self.admission_ended.subscribe(listener);
    }

    pub(crate) async fn rejected(&self, id: Option<u64>) -> Error {
        loop {
            let progress = self.request_rejected.notified();
            let mut progress = pin!(progress);
            progress.as_mut().enable();
            if let Some(error) = self.rejection(id) {
                return error;
            }
            if let Some(error) = self.error()
                && (id.is_none() || !error.is_clean_close())
            {
                return error;
            }
            progress.await;
        }
    }

    pub(crate) fn send_priority(
        &self,
        id: u64,
        push: bool,
        priority: Priority,
    ) -> Result<(), Error> {
        let id = VarInt::from_u64(id)
            .map_err(|_error| Error::stream(Code::H3_ID_ERROR, "invalid priority target"))?;
        let value = priority.field_value();
        let ty = if push {
            FrameType::PRIORITY_UPDATE_PUSH
        } else {
            FrameType::PRIORITY_UPDATE_REQUEST
        };
        let mut bytes = BytesMut::with_capacity(16);
        FrameHeader::new(ty, (id.size() + value.as_bytes().len()) as u64)
            .encode(&mut bytes)
            .ok_or(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "invalid priority frame",
            ))?;
        id.encode(&mut bytes);
        let value_start = bytes.len();
        bytes.extend_from_slice(value.as_bytes());
        let bytes = bytes.freeze();
        let frame = ControlFrame::PriorityUpdate {
            push,
            element_id: id.into_inner(),
            field_value: bytes.slice(value_start..),
        };
        let mut state = self.state.lock();
        if let Some(error) = state.error {
            return Err(error);
        }
        if state.control_output.len()
            >= self
                .config
                .max_requests
                .saturating_add(self.config.max_pushes)
                .saturating_add(16)
        {
            return Err(Error::stream(
                Code::H3_EXCESSIVE_LOAD,
                "priority output budget exceeded",
            ));
        }
        state.control_output.push_back((bytes, frame));
        drop(state);
        self.control_ready.notify_one();
        Ok(())
    }

    pub(crate) fn send_control_id(&self, ty: FrameType, id: u64) -> Result<(), Error> {
        let id = VarInt::from_u64(id)
            .map_err(|_error| Error::connection(Code::H3_INTERNAL_ERROR, "invalid control ID"))?;
        let mut bytes = BytesMut::with_capacity(16);
        FrameHeader::new(ty, id.size() as u64)
            .encode(&mut bytes)
            .ok_or(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "invalid control frame",
            ))?;
        id.encode(&mut bytes);
        let mut state = self.state.lock();
        if state.control_output.len()
            >= self
                .config
                .max_requests
                .saturating_add(self.config.max_pushes)
                .saturating_add(16)
        {
            return Err(Error::connection(
                Code::H3_EXCESSIVE_LOAD,
                "control output budget exceeded",
            ));
        }
        debug_assert!(matches!(
            ty,
            FrameType::MAX_PUSH_ID | FrameType::CANCEL_PUSH
        ));
        let frame = if ty == FrameType::MAX_PUSH_ID {
            ControlFrame::MaxPushId(id.into_inner())
        } else {
            ControlFrame::CancelPush(id.into_inner())
        };
        state.control_output.push_back((bytes.freeze(), frame));
        drop(state);
        self.control_ready.notify_one();
        Ok(())
    }

    pub(crate) fn send_goaway(&self, id: u64) -> Result<(), Error> {
        let value = VarInt::from_u64(id)
            .map_err(|_error| Error::connection(Code::H3_INTERNAL_ERROR, "invalid local GOAWAY"))?;
        let mut state = self.state.lock();
        if state.local_goaway.is_some_and(|previous| id > previous) {
            return Err(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "local GOAWAY increased",
            ));
        }
        if state.local_goaway == Some(id) {
            return Ok(());
        }
        if state.control_output.len() >= 16 {
            return Err(Error::connection(
                Code::H3_EXCESSIVE_LOAD,
                "control output budget exceeded",
            ));
        }
        let mut bytes = BytesMut::with_capacity(10);
        FrameHeader::new(FrameType::GOAWAY, value.size() as u64)
            .encode(&mut bytes)
            .ok_or(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "invalid GOAWAY frame",
            ))?;
        value.encode(&mut bytes);
        state.local_goaway = Some(id);
        state
            .control_output
            .push_back((bytes.freeze(), ControlFrame::Goaway(id)));
        drop(state);
        self.control_ready.notify_one();
        self.progress.notify_waiters();
        Ok(())
    }

    pub(crate) fn goaway(&self) -> Option<u64> {
        self.state.lock().control.goaway()
    }

    /// Whether native HTTP/3 datagrams may be sent: `SETTINGS_H3_DATAGRAM` was both sent
    /// and received with value 1 (RFC 9297 §2.1.1).
    pub(crate) fn native_datagrams(&self) -> bool {
        self.local_datagrams.load(Ordering::Acquire)
            && self.settings_sent.load(Ordering::Acquire)
            && self.peer_datagrams.load(Ordering::Acquire)
    }

    /// Register a request stream with the datagram demux, before any of its bytes are sent
    /// (client) or as it is accepted (server). `None` when this connection cannot receive
    /// datagrams.
    pub(crate) fn register_datagrams(
        self: &Arc<Self>,
        stream: u64,
        semantics: super::datagram::Semantics,
        abort: StreamAbortHandle,
    ) -> Option<Arc<super::datagram::Registration>> {
        let config = self.config.datagrams.as_ref()?;
        if !self.local_datagrams.load(Ordering::Acquire) {
            return None;
        }
        let violated = Arc::new(AtomicBool::new(false));
        let action = self.datagrams.lock().register(
            config,
            stream,
            semantics,
            abort,
            violated.clone(),
            Instant::now(),
        );
        action.run();
        Some(Arc::new(super::datagram::Registration::new(
            self.clone(),
            stream,
            violated,
        )))
    }

    pub(crate) fn decide_datagrams(&self, stream: u64, claimed: bool) {
        if let Some(config) = &self.config.datagrams {
            let action = self.datagrams.lock().decide(config, stream, claimed);
            action.run();
        }
    }

    pub(crate) fn refuse_datagrams(&self, stream: u64) {
        if self.config.datagrams.is_some() {
            self.datagrams.lock().refuse(stream);
        }
    }

    pub(crate) fn unregister_datagrams(&self, stream: u64) {
        let waker = self.datagrams.lock().unregister(stream);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// The stream's receive side or consumer ended; later datagrams for it are dropped.
    pub(crate) fn datagram_receive_ended(&self, stream: u64, end: super::datagram::ReceiveEnd) {
        let waker = self.datagrams.lock().receive_ended(stream, end);
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    pub(crate) fn poll_datagram(
        &self,
        stream: u64,
        cx: &Context<'_>,
    ) -> Poll<Result<Option<Bytes>, NativeRecvError>> {
        self.datagrams.lock().poll_recv(stream, cx)
    }

    /// The local encoder's dynamic insertions and sections awaiting the peer's decoder.
    #[cfg(test)]
    pub(crate) fn qpack_sections(&self) -> (u64, usize) {
        let state = self.state.lock();
        (
            state.encoder.insert_count(),
            state.encoder.tracked_section_count(),
        )
    }

    #[cfg(test)]
    pub(crate) fn datagram_demux(&self) -> parking_lot::MutexGuard<'_, super::datagram::Demux> {
        self.datagrams.lock()
    }

    pub(crate) fn datagrams_dropped(&self, stream: u64) -> u64 {
        self.datagrams.lock().slot_dropped(stream)
    }

    pub(crate) fn datagram_drops(&self) -> super::datagram::DatagramDrops {
        self.datagrams.lock().drops()
    }

    /// File one QUIC DATAGRAM payload under its request stream.
    pub(crate) fn receive_datagram(
        &self,
        datagram: Bytes,
        connection: &QuicConnection,
    ) -> Result<(), Error> {
        let Some(config) = self
            .config
            .datagrams
            .as_ref()
            .filter(|_| self.local_datagrams.load(Ordering::Acquire))
        else {
            // RFC 9297 §2.1.1: the peer may not send until we advertise support.
            self.datagrams.lock().count_unadvertised();
            return Ok(());
        };
        let observed_length = datagram.len();
        let split = super::datagram::split(
            datagram,
            self.role == Role::Server,
            connection.remote_stream_limit(Dir::Bi),
        );
        let (stream, payload) = match split {
            super::datagram::Split::Datagram(stream, payload) => (stream, payload),
            super::datagram::Split::InvalidId | super::datagram::Split::BeyondLimit => {
                let beyond_limit = matches!(split, super::datagram::Split::BeyondLimit);
                if config.violations == ViolationPolicy::Reject {
                    return Err(super::datagram::invalid_prefix_error(beyond_limit));
                }
                self.datagrams.lock().count_invalid(beyond_limit);
                return Ok(());
            }
        };
        qlog::datagram(
            self.qlog.as_ref(),
            "http3:datagram_parsed",
            stream,
            observed_length,
        );
        let lifetime = super::datagram::pending_lifetime(connection.rtt());
        let action =
            self.datagrams
                .lock()
                .deliver(config, stream, &payload, Instant::now(), lifetime);
        action.run();
        Ok(())
    }

    /// Wait for the peer's SETTINGS, which arrive once at the start of its control stream.
    pub(crate) async fn peer_settings(&self) -> Result<PeerSettings, Error> {
        self.read_peer_settings(|settings| PeerSettings {
            extended_connect: settings.enable_connect_protocol(),
        })
        .await
    }

    /// Wait until initial encoder-stream setup exposes real write credit.
    /// This does not wait for credit on an already registered stream.
    pub(crate) async fn encoder_ready(&self) -> Result<(), Error> {
        loop {
            let ready = self.progress.notified();
            let mut ready = pin!(ready);
            ready.as_mut().enable();
            // Keep the state -> stream lock order used by encoding. Neither
            // guard survives the await; setup/failure notifications cannot race
            // between registering this waiter and checking these conditions.
            if let Some(error) = self.error() {
                return Err(error);
            }
            if self.encoder_stream.lock().is_some() {
                return Ok(());
            }
            ready.await;
        }
    }

    pub(crate) async fn peer_settings_snapshot(&self) -> Result<Settings, Error> {
        self.read_peer_settings(Clone::clone).await
    }

    async fn read_peer_settings<T>(&self, read: impl FnOnce(&Settings) -> T) -> Result<T, Error> {
        loop {
            let ready = self.settings_ready.notified();
            let mut ready = pin!(ready);
            ready.as_mut().enable();
            {
                let state = self.state.lock();
                if let Some(settings) = state.control.settings() {
                    return Ok(read(settings));
                }
                if let Some(error) = state.error {
                    return Err(error);
                }
            }
            ready.await;
        }
    }

    pub(crate) fn cancel(&self, id: u64) {
        let mut state = self.state.lock();
        state.waiting.remove(&id);
        if state.error.is_some() {
            state.decoder.drop_blocked_stream(id);
            return;
        }
        match state.decoder.cancel_stream(id) {
            Ok(()) => (),
            Err(QpackError::OutputBlocked) => {
                if state.cancelled.len()
                    >= self
                        .config
                        .max_requests
                        .saturating_add(self.config.max_pushes)
                    && !state.cancelled.contains(&id)
                {
                    state.error = Some(Error::connection(
                        Code::H3_EXCESSIVE_LOAD,
                        "pending cancellation budget exceeded",
                    ));
                } else {
                    state.cancelled.insert(id);
                }
            }
            Err(error) => {
                state.error = Error::from_qpack(error);
            }
        }
        let error = state.error;
        drop(state);
        if let Some(error) = error {
            self.fail(error);
        }
        self.decoder_output_ready.notify_one();
    }

    pub(crate) async fn decode(&self, id: u64, bytes: Bytes) -> Decoded {
        let result = self.decode_request(id, bytes).await;
        if self.config.observation.is_some() {
            self.state.lock().decoder.take_field_observation(id);
        }
        result
    }

    pub(crate) async fn wait_priority(
        &self,
        id: u64,
        last: Option<Priority>,
    ) -> Result<Priority, Error> {
        loop {
            let progress = self.progress.notified();
            let mut progress = pin!(progress);
            progress.as_mut().enable();
            if let Some(error) = self.error() {
                return Err(error);
            }
            let current = self.schedule.current_priority(id).ok_or_else(|| {
                Error::stream(Code::H3_REQUEST_CANCELLED, "priority request completed")
            })?;
            if Some(current) != last {
                return Ok(current);
            }
            progress.await;
        }
    }

    pub(crate) fn override_priority(&self, id: u64, priority: Priority) {
        self.schedule.override_priority(id, priority);
        self.progress.notify_waiters();
    }

    pub(crate) async fn decode_request(&self, id: u64, bytes: Bytes) -> Decoded {
        loop {
            // Enable before trying the codec, closing the drain-before-wait race.
            let progress = self.progress.notified();
            let mut progress = pin!(progress);
            progress.as_mut().enable();
            let receiver = {
                let mut state = self.state.lock();
                if let Some(error) = state.error {
                    if error.is_clean_close() {
                        return state
                            .decoder
                            .decode_field_section_after_close(id, bytes)
                            .map_err(|error| compression_error(error).remote())?
                            .ok_or(
                                error.incomplete("connection closed before required QPACK inserts"),
                            );
                    }
                    return Err(error);
                }
                match state.decoder.decode_field_section(id, bytes.clone()) {
                    Ok(Some(fields)) => {
                        self.decoder_output_ready.notify_one();
                        return Ok(fields);
                    }
                    Ok(None) => {
                        let (tx, rx) = oneshot::channel();
                        if state.waiting.insert(id, tx).is_some() {
                            return Err(Error::connection(
                                Code::H3_INTERNAL_ERROR,
                                "concurrent field sections on one stream",
                            ));
                        }
                        Some(rx)
                    }
                    Err(QpackError::OutputBlocked) => None,
                    Err(error) => return Err(compression_error(error).remote()),
                }
            };
            self.decoder_output_ready.notify_one();
            if let Some(receiver) = receiver {
                return receiver.await.unwrap_or(Err(Error::stream(
                    Code::H3_REQUEST_CANCELLED,
                    "field section cancelled",
                )));
            }
            progress.await;
        }
    }

    pub(crate) fn encode<'a, I, F, N, V>(
        &self,
        id: u64,
        fields: I,
        base: Option<FieldSectionBase>,
    ) -> Result<Bytes, Error>
    where
        I: IntoIterator<Item = F>,
        F: Into<EncodeField<'a, N, V>>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut state = self.state.lock();
        if let Some(error) = state.error {
            return Err(error);
        }
        let mut stream = self.encoder_stream.lock();
        if let Some(stream) = stream.as_mut() {
            stream.encode(&mut state.encoder, id, fields, base)
        } else {
            state
                .encoder
                .encode_with_credit(id, fields, 0, base)
                .map_err(encoding_error)
        }
    }

    fn resume(state: &mut State) -> Result<(), Error> {
        for _ in 0..super::cooperative::OPERATIONS_PER_QUANTUM {
            if state.receive_closed {
                state.decoder.discard_output_after_close();
            }
            let Some((id, result)) = state.decoder.resume_next() else {
                break;
            };
            if matches!(result, Err(QpackError::OutputBlocked)) {
                break;
            }
            let result = result.map_err(|error| compression_error(error).remote());
            let failure = result.as_ref().err().copied();
            if state
                .waiting
                .remove(&id)
                .is_none_or(|tx| tx.send(result).is_err())
            {
                state.decoder.take_field_observation(id);
            }
            if let Some(error) = failure
                && error.scope() == super::qpack::ErrorScope::Connection
            {
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) async fn control_flushed(&self) -> Result<(), Error> {
        loop {
            let changed = self.progress.notified();
            let mut changed = pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.state.lock();
                if let Some(error) = state.error {
                    return Err(error);
                }
                if state.control_output.is_empty() && !state.control_in_flight {
                    return Ok(());
                }
            }
            changed.await;
        }
    }

    pub(super) fn feed_instructions(&self, ty: StreamType, chunk: &[u8]) -> Result<bool, Error> {
        let mut state = self.state.lock();
        if state.receive_closed {
            state.decoder.discard_output_after_close();
        }
        let before = state
            .decoder
            .instruction_observation()
            .map(|(instructions, complete)| (instructions.len(), complete));
        let result = if ty == StreamType::QPACK_ENCODER {
            state.decoder.feed_encoder_stream(chunk)
        } else {
            state.encoder.feed_decoder_stream(chunk)
        };
        let after = state
            .decoder
            .instruction_observation()
            .map(|(instructions, complete)| (instructions.len(), complete));
        if before != after
            && let Some(observation) = &mut state.observation
        {
            observation.changed();
        }
        let blocked = match result {
            Ok(()) => {
                Self::resume(&mut state)?;
                false
            }
            Err(QpackError::OutputBlocked) => true,
            Err(error) => return Err(compression_error(error)),
        };
        drop(state);
        self.decoder_output_ready.notify_one();
        Ok(blocked)
    }

    pub(super) fn decoder_output_written(&self, bytes: usize) -> Result<(), Error> {
        let mut state = self.state.lock();
        state.decoder.output_written(bytes);
        while let Some(id) = state.cancelled.first().copied() {
            match state.decoder.cancel_stream(id) {
                Ok(()) => {
                    state.cancelled.remove(&id);
                }
                Err(QpackError::OutputBlocked) => break,
                Err(error) => return Err(compression_error(error)),
            }
        }
        Self::resume(&mut state)?;
        drop(state);
        self.progress.notify_waiters();
        Ok(())
    }

    pub(super) fn take_decoder_output(&self) -> Result<Bytes, Error> {
        let mut state = self.state.lock();
        if let Some(error) = state.error {
            return Err(error);
        }
        let output = state.decoder.take_output_for_write();
        drop(state);
        self.progress.notify_waiters();
        Ok(output)
    }
}

fn encoding_error(error: QpackError) -> Error {
    match error {
        // Required output can reject this message without corrupting the table
        // or preventing other streams from using the connection.
        QpackError::OutputBlocked => Error::stream(
            Code::H3_EXCESSIVE_LOAD,
            "insufficient encoder stream credit for required insertions",
        ),
        error => compression_error(error),
    }
}

fn compression_error(error: QpackError) -> Error {
    Error::from_qpack(error).unwrap_or(Error::connection(
        Code::H3_INTERNAL_ERROR,
        "unexpected local QPACK backpressure",
    ))
}

trait UniPrefix {
    fn into_prefix(self) -> (Option<(StreamType, Bytes)>, Option<FrameDecoder>);
}

impl UniPrefix for () {
    fn into_prefix(self) -> (Option<(StreamType, Bytes)>, Option<FrameDecoder>) {
        (None, None)
    }
}

impl UniPrefix for (StreamType, Bytes) {
    fn into_prefix(self) -> (Option<(StreamType, Bytes)>, Option<FrameDecoder>) {
        (Some(self), None)
    }
}

impl UniPrefix for (StreamType, Bytes, FrameDecoder) {
    fn into_prefix(self) -> (Option<(StreamType, Bytes)>, Option<FrameDecoder>) {
        (Some((self.0, self.1)), Some(self.2))
    }
}

async fn receive_uni(
    connection: &QuicConnection,
    shared: Arc<Shared>,
    mut stream: QuicRecvStream,
    prefix: impl UniPrefix + Send,
) -> Result<(), Error> {
    let (prefix, frames) = prefix.into_prefix();
    let (ty, mut chunk) = if let Some(prefix) = prefix {
        prefix
    } else {
        let mut kind = VarIntDecoder::new();
        let (ty, chunk) = loop {
            let Some(chunk) = stream
                .read_chunk(shared.config.read_chunk_size, true)
                .await
                .unwrap_or(None)
            else {
                return Ok(());
            }; // RFC 9114 §6.2: pre-type termination is permitted.
            let mut bytes = chunk.bytes;
            if let Some(value) = kind.decode(&mut bytes) {
                break (StreamType::new(value.into_inner()), bytes);
            }
        };
        shared.register_peer_uni(stream.id().into(), ty)?;
        (ty, chunk)
    };
    if ty == StreamType::PUSH {
        let mut id = VarIntDecoder::new();
        loop {
            if let Some(id) = id.decode(&mut chunk) {
                return shared.accept_push_stream(id.into_inner(), stream, chunk);
            }
            match stream.read_chunk(shared.config.read_chunk_size, true).await {
                Ok(Some(bytes)) => chunk = bytes.bytes,
                _ => return Ok(()),
            }
        }
    }

    if !matches!(
        ty,
        StreamType::CONTROL | StreamType::QPACK_ENCODER | StreamType::QPACK_DECODER
    ) {
        _ = stream.stop(VarInt::from_u32(
            Code::H3_STREAM_CREATION_ERROR.value() as u32
        ));
        return Ok(());
    }
    let mut frames = frames
        .unwrap_or_else(|| {
            FrameDecoder::with_input_limit(
                shared.config.max_frame_size,
                shared.config.read_chunk_size,
            )
            .with_header_events()
        })
        .with_reserved_payload_capture(
            shared
                .state
                .lock()
                .observation
                .as_ref()
                .map_or(0, |record| record.control_payload_budget()),
        );
    let mut budget = super::cooperative::Budget::default();
    let observe_control = shared.config.observation.is_some();
    loop {
        if ty == StreamType::CONTROL && observe_control {
            // The chunk is already owned, including across a cooperative yield.
            shared.state.lock().begin_observation_control_batch();
        }
        budget.consume().await;
        if ty == StreamType::CONTROL {
            frames.feed_bytes(&mut chunk).map_err(|_error| {
                Error::connection(Code::H3_INTERNAL_ERROR, "frame input not drained")
            })?;
            while let Some(event) = frames.poll().map_err(|e| {
                Error::from_frame(&e).unwrap_or(Error::connection(
                    Code::H3_INTERNAL_ERROR,
                    "frame backpressure",
                ))
            })? {
                budget.consume().await;
                let mut state = shared.state.lock();
                state.control.receive(&event)?;
                if let Some(observation) = &mut state.observation {
                    observation.control(&event);
                    frames.set_ignored_payload_limit(observation.control_payload_budget());
                }
                if let FrameEvent::Settings(ref settings) = event {
                    state
                        .encoder
                        .apply_peer_settings(settings)
                        .map_err(compression_error)?;
                    drop(state);
                    qlog::parameters(shared.qlog.as_ref(), Initiator::Remote, settings);
                    qlog::parsed_settings(shared.qlog.as_ref(), stream.id().into(), settings);
                    shared
                        .peer_datagrams
                        .store(settings.h3_datagram(), Ordering::Release);
                    shared.settings_ready.notify_waiters();
                } else {
                    drop(state);
                    qlog::parsed(shared.qlog.as_ref(), stream.id().into(), &event);
                }
                if let FrameEvent::MaxPushId(id) = event {
                    shared.pushes.lock().max_id(id);
                    shared.push_ready.notify_waiters();
                }
                if let FrameEvent::CancelPush(id) = event {
                    shared.cancel_push(id, false)?;
                }
                if let FrameEvent::GoAway(limit) = event {
                    if shared.role == Role::Server {
                        shared.pushes.lock().reject_from(limit);
                    }
                    shared.request_rejected.notify_waiters();
                    shared.admission_ended.notify(Change::Other);
                }
                if let FrameEvent::PriorityUpdate {
                    push,
                    element_id,
                    ref field_value,
                } = event
                {
                    if push {
                        let priority = Priority::parse(field_value).ok();
                        let stream_id = shared.pushes.lock().priority(element_id, priority)?;
                        if let Some(id) = stream_id
                            && let Some(priority) = priority
                        {
                            shared.schedule.peer_priority(id, priority);
                        }
                        continue;
                    }
                    if element_id % 4 != 0 {
                        return Err(Error::connection(
                            Code::H3_ID_ERROR,
                            "priority target is not a request stream",
                        ));
                    }
                    // RFC 9218 §7.2 bounds future request IDs by the cumulative
                    // stream credit advertised on QUIC, including replenishment.
                    if element_id / 4 >= connection.remote_stream_limit(Dir::Bi) {
                        return Err(Error::connection(
                            Code::H3_ID_ERROR,
                            "priority target exceeds advertised request stream limit",
                        ));
                    }
                    if let Ok(priority) = Priority::parse(field_value) {
                        shared
                            .schedule
                            .update_pending_limit(connection.max_concurrent_streams(Dir::Bi));
                        shared.schedule.update(element_id, priority)?;
                    }
                }
                shared.progress.notify_waiters();
                shared.push_ready.notify_waiters();
            }
            if observe_control {
                shared.state.lock().end_observation_control_batch();
                shared.settings_ready.notify_waiters();
            }
        } else {
            // Retry the same bytes on local output backpressure; codec feed is transactional.
            loop {
                let progress = shared.progress.notified();
                let mut progress = pin!(progress);
                progress.as_mut().enable();
                let blocked = shared.feed_instructions(ty, &chunk)?;
                if !blocked {
                    break;
                }
                progress.await;
            }
        }
        chunk = stream
            .read_chunk(shared.config.read_chunk_size, true)
            .await
            .map_err(|_error| critical_receive_closed(connection))?
            .ok_or_else(|| critical_receive_closed(connection))?
            .bytes;
    }
}

async fn confirm_connection(connection: &QuicConnection) -> Result<(), Error> {
    connection.handshake_confirmed().await.map_err(|_error| {
        Error::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "QUIC handshake failed")
    })?;
    let alpn = connection
        .handshake_data()
        .and_then(|data| data.application_layer_protocol);
    if alpn != Some(ApplicationProtocol::HTTP_3) {
        return Err(Error::connection(
            Code::H3_GENERAL_PROTOCOL_ERROR,
            "HTTP/3 requires h3 ALPN",
        ));
    }
    if connection.max_concurrent_streams(Dir::Uni) < 3 {
        return Err(Error::connection(
            Code::H3_STREAM_CREATION_ERROR,
            "local endpoint must permit three critical streams",
        ));
    }
    if connection.available_streams(Dir::Uni) < 3 {
        return Err(Error::connection(
            Code::H3_STREAM_CREATION_ERROR,
            "peer must permit three critical streams",
        ));
    }
    Ok(())
}

fn critical_receive_closed(connection: &QuicConnection) -> Error {
    connection.close_reason().as_ref().map_or_else(
        || {
            Error::connection(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "critical receive stream closed",
            )
        },
        Error::from_transport,
    )
}

#[cfg(test)]
pub(crate) fn initial_control(
    config: &Config,
    role: Role,
    datagrams: bool,
) -> Result<Bytes, Error> {
    initial_control_recorded(config, role, datagrams, None)
}

fn initial_control_recorded(
    config: &Config,
    role: Role,
    datagrams: bool,
    qlog: Option<(&ConnectionQlogControl, u64)>,
) -> Result<Bytes, Error> {
    let settings = config.local_settings(role, datagrams)?;
    let mut payload = BytesMut::new();
    settings
        .encode_payload(&mut payload)
        .ok_or(Error::connection(
            Code::H3_INTERNAL_ERROR,
            "invalid settings",
        ))?;
    let mut output = BytesMut::new();
    VarInt::from_u32(StreamType::CONTROL.value() as u32).encode(&mut output);
    FrameHeader::new(FrameType::SETTINGS, payload.len() as u64)
        .encode(&mut output)
        .ok_or(Error::connection(
            Code::H3_INTERNAL_ERROR,
            "invalid SETTINGS length",
        ))?;
    output.extend_from_slice(&payload);
    if let Some(preferences) = &config.client_control {
        for frame in &preferences.frames {
            frame.encode(&mut output).ok_or(Error::connection(
                Code::H3_INTERNAL_ERROR,
                "invalid client control frame",
            ))?;
        }
    }
    if let Some((control, id)) = qlog {
        qlog::parameters(Some(control), Initiator::Local, &settings);
        qlog::created_settings(Some(control), id, &settings);
    }
    Ok(output.freeze())
}

/// Drives the HTTP/3 control and QPACK streams independently of application bodies.
///
/// Run this future for as long as the connection is used. Dropping it closes the
/// connection and wakes blocked field sections.
pub struct Driver {
    connection: QuicConnection,
    shared: Arc<Shared>,
    role: Role,
    received: Option<Box<receive::settings::InitialReceive>>,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Driver")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl Driver {
    pub(crate) fn new(connection: QuicConnection, shared: Arc<Shared>, role: Role) -> Self {
        Self {
            connection,
            shared,
            role,
            received: None,
        }
    }

    pub(super) fn with_received_settings(
        mut self,
        received: receive::settings::SettingsPrelude,
    ) -> Result<Self, Error> {
        if let Err(error) = received.apply_peer_settings(&self.shared) {
            // The retained owner still holds every receive handle. Close before
            // either its cleanup or Driver Drop can choose a different outcome.
            self.shared.fail(error);
            let code = VarInt::from_u64(error.code().value())
                .unwrap_or(VarInt::from_u32(Code::H3_INTERNAL_ERROR.value() as u32));
            self.connection
                .close(code, b"HTTP/3 peer SETTINGS rejected");
            return Err(error);
        }
        self.received = Some(Box::new(received.into_receiver(&self.shared)));
        Ok(self)
    }

    /// Run until the transport closes or a connection-level protocol error occurs.
    pub async fn run(mut self) -> Result<(), Error> {
        let result = self.run_inner().await;
        // Stream operations wake together with `closed()`. Whichever branch won,
        // preserve the connection's actual close code rather than a secondary
        // critical-stream or accept error caused by that same closure. A fatal
        // error already discovered by a request outranks local cleanup closure.
        let result = match (self.shared.receive_error(), self.connection.close_reason()) {
            (Some(error), _) => Err(error),
            (None, Some(reason)) => {
                let error = Error::from_transport(&reason);
                if error.code() == Code::H3_NO_ERROR {
                    Ok(())
                } else {
                    Err(error)
                }
            }
            (None, None) => result,
        };
        if let Err(error) = result {
            self.shared.fail(error);
            if let Ok(code) = VarInt::from_u64(error.code().value()) {
                self.connection.close(code, b"HTTP/3 connection error");
            }
        } else {
            // Wake terminal waiters without making Drop discard complete buffered responses.
            let error = self.connection.close_reason().as_ref().map_or_else(
                || Error::connection(Code::H3_NO_ERROR, "HTTP/3 connection closed"),
                Error::from_transport,
            );
            self.shared.fail(error);
        }
        result
    }

    async fn run_inner(&mut self) -> Result<(), Error> {
        if let Some(received) = self.received.take() {
            // Only staged handshakes allocate receive state and boxed handlers.
            Box::pin(async {
                let mut receiver =
                    receive::settings::resume(&self.connection, &self.shared, *received);
                self.run_receiving(&mut receiver).await
            })
            .await
        } else if self.shared.config.observation.is_some() {
            // Keep observation-only receive state out of ordinary driver frames.
            Box::pin(async {
                let mut receiver = receive::observed(&self.connection, &self.shared);
                self.run_receiving(&mut receiver).await
            })
            .await
        } else {
            let mut receiver = receive::direct(&self.connection, &self.shared);
            self.run_receiving(&mut receiver).await
        }
    }

    async fn write_initial_control(&self, control: &mut QuicSendStream) -> Result<(), Error> {
        control.set_priority(i32::MAX).map_err(|_error| {
            Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "control stream closed")
        })?;
        // Advertise datagrams only when QUIC DATAGRAM can carry them.
        let datagrams = self.shared.local_datagrams_supported(&self.connection);
        self.shared
            .local_datagrams
            .store(datagrams, Ordering::Release);
        let mut bytes = [initial_control_recorded(
            &self.shared.config,
            self.role,
            datagrams,
            self.shared
                .qlog
                .as_ref()
                .map(|control_qlog| (control_qlog, control.id().into())),
        )?];
        if self.role == Role::Client && self.shared.config.max_pushes != 0 {
            self.shared.send_control_id(
                FrameType::MAX_PUSH_ID,
                self.shared.config.max_pushes as u64 - 1,
            )?;
        }

        while !bytes[0].is_empty() {
            control.write_chunks(&mut bytes).await.map_err(|_error| {
                Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "control stream stopped")
            })?;
        }
        // QUIC holds our SETTINGS now: native datagrams may follow them.
        self.shared.settings_sent.store(true, Ordering::Release);
        Ok(())
    }

    async fn queue_ordered_startup(
        &self,
        control: &mut QuicSendStream,
        encoder: &mut QuicSendStream,
        decoder: &mut QuicSendStream,
    ) -> Result<(), Error> {
        self.write_initial_control(control).await?;
        // All three streams have equal critical priority. The order here is a
        // send-buffer preference, not a promise of peer delivery chronology.
        encoder.set_priority(i32::MAX).map_err(|_error| {
            Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "encoder stream closed")
        })?;
        decoder.set_priority(i32::MAX).map_err(|_error| {
            Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "decoder stream closed")
        })?;
        let preferences = self.shared.config.critical_streams;
        let streams = match preferences.order {
            CriticalStreamOrder::EncoderFirst => [
                (encoder, StreamType::QPACK_ENCODER, preferences.encoder),
                (decoder, StreamType::QPACK_DECODER, preferences.decoder),
            ],
            CriticalStreamOrder::DecoderFirst => [
                (decoder, StreamType::QPACK_DECODER, preferences.decoder),
                (encoder, StreamType::QPACK_ENCODER, preferences.encoder),
            ],
        };
        for (stream, kind, startup) in streams {
            if startup == CriticalStreamStartup::Immediate {
                critical_streams::write_prefix(stream, kind).await?;
            }
        }
        Ok(())
    }

    async fn run_receiving(&self, receiver: &mut impl receive::Receiver) -> Result<(), Error> {
        // The owner keeps partially consumed chunks and type/frame decoders
        // outside the select so clean-close draining cannot discard them.
        let result = async {
            confirm_connection(&self.connection).await?;
            let open = || async {
                self.connection.open_uni().await.map_err(|_error| {
                    Error::connection(
                        Code::H3_STREAM_CREATION_ERROR,
                        "cannot open critical stream",
                    )
                })
            };
            let mut control = open().await?;
            let (first, second) = tokio::try_join!(open(), open())?;
            let (mut encoder, mut decoder) = match self.shared.config.critical_streams.order {
                CriticalStreamOrder::EncoderFirst => (first, second),
                CriticalStreamOrder::DecoderFirst => (second, first),
            };
            for (stream, kind) in [
                (&control, StreamType::CONTROL),
                (&encoder, StreamType::QPACK_ENCODER),
                (&decoder, StreamType::QPACK_DECODER),
            ] {
                qlog::stream_type(
                    self.shared.qlog.as_ref(),
                    Initiator::Local,
                    stream.id().into(),
                    kind,
                );
            }
            // Keep this receive owner alive across both phases. In particular,
            // queued startup writes must not prevent peer SETTINGS/credit progress.
            let mut receiving = pin!(receiver.run());
            let preferences = self.shared.config.critical_streams;
            let ordered = preferences.ordered_startup;
            if ordered {
                tokio::select! {
                    result = self.queue_ordered_startup(&mut control, &mut encoder, &mut decoder) => result?,
                    result = receiving.as_mut() => return result,
                    error = self.shared.failed() => return Err(error),
                    error = self.connection.closed() => return Err(Error::from_transport(&error)),
                }
            }
            let encoder_task = critical_streams::encoder_task(
                self.shared.clone(), encoder,
                ordered && preferences.encoder == CriticalStreamStartup::Immediate,
            )?;
            let control_task = async {
                if !ordered {
                    self.write_initial_control(&mut control).await?;
                }
                loop {
                    let next = {
                        let mut state = self.shared.state.lock();
                        let next = state.control_output.pop_front();
                        state.control_in_flight = next.is_some();
                        next
                    };
                    if let Some((bytes, frame)) = next {
                        let push_grant = match frame {
                            ControlFrame::MaxPushId(max) => Some(max),
                            _ => None,
                        };
                        let mut bytes = [bytes];
                        while !bytes[0].is_empty() {
                            std::future::poll_fn(|cx| {
                                let mut pushes = self.shared.pushes.lock();
                                let result = control.poll_write_chunks(cx, &mut bytes);
                                if !matches!(result, std::task::Poll::Ready(Err(_)))
                                    && bytes[0].is_empty()
                                    && let Some(max) = push_grant
                                {
                                    pushes.grant(max);
                                }
                                result
                            })
                            .await
                            .map_err(|_error| {
                                Error::connection(
                                    Code::H3_CLOSED_CRITICAL_STREAM,
                                    "control stream stopped",
                                )
                            })?;
                        }
                        self.shared.state.lock().control_in_flight = false;
                        qlog::created_control(
                            self.shared.qlog.as_ref(),
                            control.id().into(),
                            &frame,
                        );
                        self.shared.progress.notify_waiters();
                    } else {
                        tokio::select! {
                            _ = self.shared.control_ready.notified() => (),
                            _ = control.stopped() => return Err(Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "control stream stopped")),
                        }
                    }
                }
            };
            let reject_server_bidi = async {
                if self.role == Role::Client {
                    _ = self.connection.accept_bi().await;
                    return Err(Error::connection(
                        Code::H3_STREAM_CREATION_ERROR,
                        "server initiated bidirectional stream",
                    ));
                }
                // Admission owns bidi streams until shutdown. Afterwards the driver
                // rejects newly arriving requests while accepted work drains (§5.2).
                loop {
                    let progress = self.shared.progress.notified();
                    let mut progress = pin!(progress);
                    progress.as_mut().enable();
                    if self.shared.state.lock().local_goaway.is_some() {
                        break;
                    }
                    progress.await;
                }
                let mut budget = super::cooperative::Budget::default();
                loop {
                    budget.consume().await;
                    let (send, _recv) = self
                        .connection
                        .accept_bi()
                        .await
                        .map_err(|error| Error::from_transport(&error))?;
                    self.shared.cancel(send.id().into());
                    send.abort_handle()
                        .abort(VarInt::from_u32(Code::H3_REQUEST_REJECTED.value() as u32));
                }
            };
            // The driver is the only QUIC DATAGRAM reader; sessions never race for it.
            let datagrams = async {
                let mut budget = super::cooperative::Budget::default();
                loop {
                    let Ok(datagram) = self.connection.read_datagram().await else {
                        // Connection closure is reported by the other branches.
                        return std::future::pending().await;
                    };
                    self.shared.receive_datagram(datagram, &self.connection)?;
                    budget.consume().await;
                }
            };
            tokio::select! {
                error = self.shared.failed() => Err(error),
                result = datagrams => result,
                result = control_task => result,
                result = encoder_task => result,
                result = critical_streams::write_decoder(self.shared.clone(), decoder, ordered && preferences.decoder == CriticalStreamStartup::Immediate) => result,
                result = receiving.as_mut() => result,
                result = reject_server_bidi => result,
                error = self.connection.closed() => {
                    let error = Error::from_transport(&error);
                    if error.code() == Code::H3_NO_ERROR { Ok(()) } else { Err(error) }
                },
            }
        }.await;

        if self
            .connection
            .close_reason()
            .as_ref()
            .is_some_and(|reason| Error::from_transport(reason).is_clean_close())
            && self.shared.receive_error().is_none()
        {
            // The sending futures above are gone, so their feedback reservations can
            // be discarded. Keep blocked fields pending until all received inserts
            // and GOAWAY frames have been processed.
            self.shared.state.lock().receive_closed = true;
            self.shared.settings_ready.notify_waiters();
            self.shared.progress.notify_waiters();
            receiver.drain().await?;
            // A final insert can unblock more sections than one scheduling quantum.
            // Resume all available sections cooperatively before failing the remainder.
            let mut budget = super::cooperative::Budget::default();
            loop {
                let resumed = {
                    let mut state = self.shared.state.lock();
                    let before = state.waiting.len();
                    if let Err(error) = Shared::resume(&mut state) {
                        drop(state);
                        self.shared.fail(error);
                        return Err(error);
                    }
                    state.waiting.len() < before
                };
                if !resumed {
                    break;
                }
                budget.consume().await;
            }
        }
        result
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        let close_code = self.shared.close_code();
        if self.shared.error().is_none() {
            self.shared.fail(Error::connection(
                Code::H3_REQUEST_CANCELLED,
                "HTTP/3 driver stopped",
            ));
        }
        self.connection.close(close_code, b"HTTP/3 driver stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h3::{headers, tests::Pair};
    use rama_http_types::proto::h3::{
        PseudoHeader,
        control::ClientControlFrame,
        critical_streams::Startup,
        qpack::encoding::{FieldPreferences, HeaderPreferences, Representation},
    };
    use rama_quic_proto::{Side, StreamId};
    use std::{
        future::{Future as _, poll_fn},
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Wake, Waker},
        time::Duration,
    };

    #[test]
    fn client_control_preferences_enforce_roles_limits_and_transactional_updates() {
        let valid = Arc::new(ClientControlPreferences {
            frames: vec![ClientControlFrame::Ignored {
                frame_type: FrameType::new(0x21),
                payload: Bytes::from_static(b"ab"),
            }]
            .into(),
        });
        let mut config = Config {
            max_frame_size: 4,
            ..Config::default()
        };
        config.try_set_client_controls(Some(valid.clone())).unwrap();
        for frame in [
            ClientControlFrame::Ignored {
                frame_type: FrameType::new(0x21),
                payload: Bytes::from_static(b"abc"),
            },
            ClientControlFrame::Ignored {
                frame_type: FrameType::SETTINGS,
                payload: Bytes::new(),
            },
            ClientControlFrame::Ignored {
                frame_type: FrameType::new(1 << 62),
                payload: Bytes::new(),
            },
        ] {
            assert!(
                config
                    .try_set_client_controls(Some(Arc::new(ClientControlPreferences {
                        frames: vec![frame].into()
                    })))
                    .is_err()
            );
            assert!(Arc::ptr_eq(config.client_control.as_ref().unwrap(), &valid));
        }
        config.max_frame_size = 1024;
        // Role admission must fail on its own, without a masking byte limit.
        for (side, dir) in [
            (Side::Server, Dir::Bi),
            (Side::Client, Dir::Uni),
            (Side::Server, Dir::Uni),
        ] {
            let frame = ClientControlFrame::RequestPriority {
                request: StreamId::new(side, dir, 0),
                value: Bytes::from_static(b"u=1"),
            };
            let mut output = vec![0xaa];
            assert!(frame.encode(&mut output).is_none());
            assert_eq!(output, [0xaa]);
            config
                .try_set_client_controls(Some(Arc::new(ClientControlPreferences {
                    frames: vec![frame].into(),
                })))
                .unwrap_err();
            assert!(Arc::ptr_eq(config.client_control.as_ref().unwrap(), &valid));
        }
        config
            .try_set_client_controls(Some(Arc::new(ClientControlPreferences {
                frames: vec![ClientControlFrame::RequestPriority {
                    request: StreamId::new(Side::Client, Dir::Bi, 0),
                    value: Bytes::from_static(b"u=1"),
                }]
                .into(),
            })))
            .unwrap();
        config.try_set_client_controls(Some(valid.clone())).unwrap();
        config.max_requests = 0;
        config.max_pushes = 0;
        let too_many = ClientControlPreferences {
            frames: vec![valid.frames[0].clone(); 17].into(),
        };
        assert!(
            config
                .try_set_client_controls(Some(Arc::new(too_many)))
                .is_err()
        );
        assert!(Arc::ptr_eq(config.client_control.as_ref().unwrap(), &valid));
        let config = Config {
            client_control: Some(valid),
            ..Config::default()
        };
        config.local_settings(Role::Server, false).unwrap_err();
        config.local_settings(Role::Client, false).unwrap();
    }

    #[test]
    fn client_settings_application_preserves_order_and_omitted_defaults() {
        let original = Config::default();
        let mut wire = Settings::new();
        wire.set(SettingId::FIRST_RESERVED, 17).unwrap();
        wire.set(SettingId::QPACK_BLOCKED_STREAMS, 0).unwrap();
        wire.set(SettingId::new(0xface), 29).unwrap();
        let wire = Arc::new(wire);
        let configured = original.try_with_client_settings(wire.clone()).unwrap();
        assert_eq!(configured.decoder.max_table_capacity, 0);
        assert_eq!(configured.decoder.max_blocked_streams, 0);
        assert_eq!(
            configured.decoder.max_field_section_size,
            original.decoder.max_field_section_size
        );
        assert!(configured.datagrams.is_none());
        assert_eq!(
            configured.local_settings(Role::Client, false).unwrap(),
            *wire
        );
        assert!(original.settings_profile.is_none());
        assert!(original.datagrams.is_some());
    }

    #[test]
    fn client_settings_application_lowers_budgets_and_drops_unavailable_grants() {
        let config = Config::default();
        for (id, value, local) in [
            (
                SettingId::QPACK_MAX_TABLE_CAPACITY,
                config.decoder.max_table_capacity + 1,
                config.decoder.max_table_capacity,
            ),
            (
                SettingId::QPACK_BLOCKED_STREAMS,
                config.decoder.max_blocked_streams + 1,
                config.decoder.max_blocked_streams,
            ),
            (
                SettingId::MAX_FIELD_SECTION_SIZE,
                config.decoder.max_field_section_size as u64 + 1,
                config.decoder.max_field_section_size as u64,
            ),
        ] {
            let mut wire = Settings::new();
            wire.set(id, value).unwrap();
            let configured = config.try_with_client_settings(Arc::new(wire)).unwrap();
            assert_eq!(configured.settings_profile.unwrap().get(id), Some(local));
        }
        // Values beyond the QUIC integer range are invalid input, not a budget.
        for (id, value) in [
            (SettingId::new(1 << 62), 0),
            (SettingId::FIRST_RESERVED, 1 << 62),
        ] {
            let mut wire = Settings::new();
            wire.set(id, value).unwrap();
            config.try_with_client_settings(Arc::new(wire)).unwrap_err();
            assert!(config.settings_profile.is_none());
        }
        let mut wire = Settings::new();
        wire.set(SettingId::H3_DATAGRAM, 1).unwrap();
        let wire = Arc::new(wire);
        let configured = config.try_with_client_settings(wire.clone()).unwrap();
        assert!(configured.datagrams.is_some());
        let disabled = Config {
            datagrams: None,
            ..config
        };
        let configured = disabled.try_with_client_settings(wire).unwrap();
        assert!(configured.settings_profile.unwrap().is_empty());
    }

    #[test]
    fn client_connect_protocol_setting_preserves_literal_values_without_enabling_servers() {
        let original = Config::default();
        for value in [0, 1] {
            let mut settings = Settings::new();
            settings
                .set(SettingId::ENABLE_CONNECT_PROTOCOL, value)
                .unwrap();
            let settings = Arc::new(settings);
            let configured = original.try_with_client_settings(settings.clone()).unwrap();
            assert!(!configured.extended_connect);
            assert_eq!(
                configured.local_settings(Role::Client, false).unwrap(),
                *settings
            );
            // A server advertises the grant only when it has the capability.
            for server_enabled in [false, true] {
                let mut server = configured.clone();
                server.extended_connect = server_enabled;
                let advertised = server.local_settings(Role::Server, false).unwrap();
                assert_eq!(
                    advertised.enable_connect_protocol(),
                    value == 1 && server_enabled
                );
            }
        }
        assert!(original.settings_profile.is_none());
        assert!(original.datagrams.is_some());
    }

    fn settings_profile_config() -> Config {
        let mut config = Config::default();
        let mut settings = Settings::new();
        for (id, value) in [
            (SettingId::FIRST_RESERVED, 7),
            (
                SettingId::QPACK_BLOCKED_STREAMS,
                config.decoder.max_blocked_streams,
            ),
            (SettingId::new(0xface), 42),
            (
                SettingId::QPACK_MAX_TABLE_CAPACITY,
                config.decoder.max_table_capacity,
            ),
        ] {
            settings.set(id, value).unwrap();
        }
        config.settings_profile = Some(Arc::new(settings));
        config
    }

    #[test]
    fn settings_profile_preserves_literal_control_bytes() {
        let config = settings_profile_config();
        let expected = config.settings_profile.as_ref().unwrap();
        let actual = config.local_settings(Role::Client, false).unwrap();
        assert_eq!(&actual, expected.as_ref());

        let mut payload = BytesMut::new();
        expected.encode_payload(&mut payload).unwrap();
        let mut wire = BytesMut::new();
        VarInt::from_u32(StreamType::CONTROL.value() as u32).encode(&mut wire);
        FrameHeader::new(FrameType::SETTINGS, payload.len() as u64)
            .encode(&mut wire)
            .unwrap();
        wire.extend_from_slice(&payload);
        assert_eq!(
            initial_control(&config, Role::Client, false).unwrap(),
            wire.freeze()
        );
    }

    #[test]
    fn settings_profile_rejects_decoder_mismatches_and_drops_unavailable_grants() {
        let config = settings_profile_config();
        let mut bad = config.clone();
        bad.decoder.max_table_capacity += 1;
        bad.settings().unwrap_err();
        let mut bad = config.clone();
        bad.decoder.max_blocked_streams += 1;
        bad.settings().unwrap_err();
        let mut bad = config.clone();
        Arc::make_mut(bad.settings_profile.as_mut().unwrap())
            .set(SettingId::MAX_FIELD_SECTION_SIZE, 1)
            .unwrap();
        bad.settings().unwrap_err();
        let mut bad = config.clone();
        Arc::make_mut(bad.settings_profile.as_mut().unwrap())
            .set(SettingId::new(1 << 62), 0)
            .unwrap();
        bad.settings().unwrap_err();
        let mut bad = config.clone();
        Arc::make_mut(bad.settings_profile.as_mut().unwrap())
            .set(
                SettingId::new(SettingId::FIRST_RESERVED.value() + SettingId::RESERVED_INTERVAL),
                1 << 62,
            )
            .unwrap();
        bad.settings().unwrap_err();

        // An omitted capability is never enabled implicitly during serialization,
        // and a captured grant the connection lacks is dropped.
        let profile = config.settings_profile.as_deref().unwrap().clone();
        assert_eq!(config.local_settings(Role::Client, true).unwrap(), profile);
        let mut server = config.clone();
        server.extended_connect = true;
        assert_eq!(server.local_settings(Role::Server, false).unwrap(), profile);
        let mut granted = config;
        Arc::make_mut(granted.settings_profile.as_mut().unwrap())
            .set(SettingId::ENABLE_CONNECT_PROTOCOL, 1)
            .unwrap();
        assert_eq!(
            granted.local_settings(Role::Server, false).unwrap(),
            profile
        );
    }

    #[test]
    fn settings_profile_omitted_qpack_values_require_zero_runtime_limits() {
        let mut config = Config {
            settings_profile: Some(Arc::new(Settings::new())),
            ..Config::default()
        };
        config.settings().unwrap_err();
        config.decoder.max_table_capacity = 0;
        config.settings().unwrap_err();
        config.decoder.max_blocked_streams = 0;
        assert!(
            config
                .local_settings(Role::Client, false)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn required_fields_wait_for_local_encoder_registration_after_peer_settings() {
        for representation in [
            Representation::DynamicIndexBeforeBase,
            Representation::DynamicIndexAfterBase,
            Representation::LiteralDynamicNameBeforeBase,
            Representation::LiteralDynamicNameAfterBase,
        ] {
            for pseudo in [false, true] {
                let shared =
                    Shared::new(Config::default(), Role::Client, Extensions::new()).unwrap();
                {
                    let mut state = shared.state.lock();
                    state
                        .control
                        .receive(&FrameEvent::Header(FrameHeader::new(
                            FrameType::SETTINGS,
                            0,
                        )))
                        .unwrap();
                    state
                        .control
                        .receive(&FrameEvent::Settings(Settings::new()))
                        .unwrap();
                }
                let mut settings = Box::pin(shared.peer_settings());
                assert!(
                    settings
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_ready()
                );
                let field = FieldPreferences {
                    representation,
                    ..FieldPreferences::default()
                };
                let mut preferences = HeaderPreferences::default();
                if pseudo {
                    preferences
                        .pseudo_headers
                        .insert(PseudoHeader::Authority, field);
                } else {
                    preferences.headers.append("x-current", field);
                }
                let extensions = Extensions::new();
                extensions.insert(preferences);
                let mut ready = Box::pin(headers::wait_for_header_admission(&shared, &extensions));
                let mut cx = Context::from_waker(Waker::noop());
                assert!(
                    ready.as_mut().poll(&mut cx).is_pending(),
                    "peer SETTINGS alone exposed a missing writer"
                );
                let error = Error::connection(Code::H3_INTERNAL_ERROR, "encoder setup failed");
                shared.fail(error);
                assert_eq!(ready.as_mut().poll(&mut cx), Poll::Ready(Err(error)));
            }
        }
    }

    #[test]
    fn encoder_readiness_wait_observes_failure_before_and_after_registration() {
        struct CountWakes(AtomicUsize);
        impl Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        for fail_before_poll in [false, true] {
            let shared = Shared::new(Config::default(), Role::Client, Extensions::new()).unwrap();
            let error = Error::connection(Code::H3_INTERNAL_ERROR, "encoder setup failed");
            let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
            let waker = Waker::from(wakes.clone());
            let mut cx = Context::from_waker(&waker);
            let mut ready = Box::pin(shared.encoder_ready());
            if fail_before_poll {
                shared.fail(error);
            } else {
                assert!(ready.as_mut().poll(&mut cx).is_pending());
                shared.fail(error);
                assert_eq!(wakes.0.load(Ordering::Relaxed), 1);
            }
            assert_eq!(ready.as_mut().poll(&mut cx), Poll::Ready(Err(error)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn encoder_registration_wakes_waiters_without_other_progress_events() {
        struct CountWakes(AtomicUsize);
        impl Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        tokio::time::timeout(Duration::from_secs(20), async {
            let mut notifications = Vec::new();
            let mut readiness = Vec::new();
            for startup in [Startup::Immediate, Startup::OnDemand] {
                let pair = Pair::in_memory(None, None).await;
                let mut config = Config::default();
                config.critical_streams.encoder = startup;
                let shared = Shared::new(config, Role::Client, Extensions::new()).unwrap();
                let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
                let waker = Waker::from(wakes.clone());
                let mut cx = Context::from_waker(&waker);
                let mut ready = Box::pin(shared.encoder_ready());
                assert!(ready.as_mut().poll(&mut cx).is_pending());
                let stream = pair.client.open_uni().await.unwrap();
                let task = critical_streams::encoder_task(shared.clone(), stream, false).unwrap();
                tokio::pin!(task);
                if startup == Startup::Immediate {
                    assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
                    assert!(ready.as_mut().poll(&mut cx).is_pending());
                    // Only this task can publish the isolated Shared's encoder.
                    // Drive actual prefix queuing, not a synthetic readiness flag.
                    poll_fn(|cx| {
                        assert!(task.as_mut().poll(cx).is_pending());
                        if shared.encoder_stream.lock().is_some() {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    })
                    .await;
                    let mut incoming = pair.server.accept_uni().await.unwrap();
                    let mut prefix = [0];
                    incoming.read_exact(&mut prefix).await.unwrap();
                    assert_eq!(prefix, [StreamType::QPACK_ENCODER.value() as u8]);
                }
                // Check both startup outcomes together: a missing notification must
                // not mask the other branch in this aggregate regression guard.
                notifications.push(wakes.0.load(Ordering::Relaxed));
                readiness.push(ready.as_mut().poll(&mut cx));
                pair.close().await;
            }
            assert_eq!(notifications, [1, 1], "encoder registration notifications");
            assert_eq!(
                readiness,
                [Poll::Ready(Ok(())); 2],
                "encoder registration readiness"
            );
        })
        .await
        .unwrap();
    }

    #[test]
    fn ordinary_compression_progress_does_not_wake_request_rejection_waiters() {
        struct CountWakes(AtomicUsize);
        impl Wake for CountWakes {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let shared = Shared::new(Config::default(), Role::Client, Extensions::default()).unwrap();
        let wakes = Arc::new(CountWakes(AtomicUsize::new(0)));
        let waker = Waker::from(wakes.clone());
        let mut cx = Context::from_waker(&waker);
        let mut waiters: Vec<_> = (0..512)
            .map(|id| Box::pin(shared.rejected(Some(id * 4))))
            .collect();
        for waiter in &mut waiters {
            assert!(waiter.as_mut().poll(&mut cx).is_pending());
        }
        for _ in 0..128 {
            shared.take_decoder_output().unwrap();
            shared.decoder_output_written(0).unwrap();
        }
        assert_eq!(wakes.0.load(Ordering::Relaxed), 0);
        shared.fail(Error::connection(Code::H3_INTERNAL_ERROR, "test shutdown"));
        assert_eq!(wakes.0.load(Ordering::Relaxed), waiters.len());
        for waiter in &mut waiters {
            assert!(waiter.as_mut().poll(&mut cx).is_ready());
        }
    }

    #[test]
    fn cancellation_retries_after_decoder_output_credit_returns() {
        let shared = Shared::new(
            Config {
                decoder: DecoderConfig {
                    max_decoder_stream_bytes: 10,
                    ..DecoderConfig::default()
                },
                ..Config::default()
            },
            Role::Server,
            Extensions::default(),
        )
        .unwrap();
        let mut encoder = Encoder::new(EncoderConfig::default());
        for id in 0..12 {
            // No encoder instructions are delivered: cancellation must release
            // the peer's tracked section even if no HEADERS were decoded.
            encoder
                .encode(id * 4, [("x-cancel", "repeated value")])
                .unwrap();
            shared.cancel(id * 4);
        }
        assert!(!shared.state.lock().cancelled.is_empty());
        while encoder.tracked_section_count() != 0 {
            let output = shared.take_decoder_output().unwrap();
            assert!(
                !output.is_empty(),
                "queued cancellations must eventually drain"
            );
            encoder.feed_decoder_stream(&output).unwrap();
            shared.decoder_output_written(output.len()).unwrap();
        }
        assert!(shared.state.lock().cancelled.is_empty());
        assert_eq!(encoder.tracked_reference_count(), 0);
    }

    #[test]
    fn cancelling_after_connection_failure_releases_blocked_fields_without_feedback() {
        let shared = Shared::new(Config::default(), Role::Client, Extensions::default()).unwrap();
        let mut encoder = Encoder::new(EncoderConfig::default());
        let encoded = encoder.encode(0, [("x-blocked", "pending")]).unwrap();
        {
            let mut state = shared.state.lock();
            assert!(
                state
                    .decoder
                    .decode_field_section(0, encoded)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(state.decoder.blocked_stream_count(), 1);
        }
        let error = Error::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "connection failed");
        shared.fail(error);
        shared.cancel(0);
        let mut state = shared.state.lock();
        assert_eq!(state.decoder.blocked_stream_count(), 0);
        assert!(state.decoder.take_decoder_stream().is_empty());
        assert!(state.cancelled.is_empty());
        assert_eq!(state.error, Some(error));
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use rama_http_types::proto::h3::{
        Setting,
        observation::{InsertionFieldMatch, ObservedEncoderInstruction, SettingsStatus},
        qpack::{EncoderInstruction, FieldLine, HeaderPrefix},
    };
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use tokio::time::Duration;

    fn shared(limits: ObservationLimits) -> Arc<Shared> {
        Shared::new(
            Config {
                observation: Some(Box::new(limits)),
                ..Config::default()
            },
            Role::Server,
            Extensions::new(),
        )
        .unwrap()
    }

    fn request_at_owner_boundary(
        shared: &Arc<Shared>,
        stream_id: u64,
        fields: &[FieldPair],
    ) -> Option<(H3Observer, H3RequestObservation)> {
        let result = shared.request_observation(stream_id, fields);
        shared.publish_first_request_observation();
        result
    }

    fn observer(shared: &Arc<Shared>) -> H3Observer {
        request_at_owner_boundary(shared, 0, &[]).unwrap().0
    }

    fn settings(shared: &Shared) {
        let mut settings = Settings::new();
        settings
            .insert(Setting::new(SettingId::new(0x21), 19))
            .unwrap();
        settings
            .insert(Setting::new(SettingId::QPACK_MAX_TABLE_CAPACITY, 0))
            .unwrap();
        let mut state = shared.state.lock();
        for event in [
            FrameEvent::Header(FrameHeader::new(FrameType::SETTINGS, 5)),
            FrameEvent::Settings(settings),
        ] {
            state.control.receive(&event).unwrap();
            state.observation.as_mut().unwrap().control(&event);
        }
        state.freeze_first_request_observation();
        drop(state);
        shared.settings_ready.notify_waiters();
    }

    #[test]
    fn observation_initial_insertions_publish_with_the_first_request_and_stay_frozen() {
        for settings_first in [false, true] {
            let shared = shared(ObservationLimits::default());
            if settings_first {
                settings(&shared);
            }
            // A pre-request snapshot must not hide newly associated fields.
            let mut instructions = BytesMut::new();
            EncoderInstruction::SetDynamicTableCapacity { capacity: 4096 }
                .encode(&mut instructions);
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x-bootstrap"),
                value: Bytes::from_static(b"fresh request"),
                name_huffman: false,
                value_huffman: false,
            }
            .encode(&mut instructions);
            shared
                .feed_instructions(StreamType::QPACK_ENCODER, &instructions)
                .unwrap();
            let before = shared.observation_snapshot().unwrap();
            assert!(before.encoder_bindings.is_none());
            let mut section = BytesMut::new();
            HeaderPrefix::new(0, 0)
                .encode(&mut section, 4096 / 32)
                .unwrap();
            FieldLine::LiteralWithLiteralName {
                name: Bytes::from_static(b"x-bootstrap"),
                value: Bytes::from_static(b"fresh request"),
                name_huffman: false,
                value_huffman: false,
                never_index: false,
            }
            .encode(&mut section);
            let fields = shared
                .state
                .lock()
                .decoder
                .decode_field_section(0, section.freeze())
                .unwrap()
                .unwrap();
            let (_, first) = request_at_owner_boundary(&shared, 0, &fields).unwrap();
            assert_eq!(first.stream_id, 0);
            assert!(first.connection.revision > before.revision);
            let bound = first.connection.encoder_bindings.as_ref().unwrap();
            assert!(bound.complete);
            assert_eq!(bound.stream_id, 0);
            assert_eq!(bound.insertions.len(), 1);
            assert_eq!(
                bound.insertions[0].field,
                InsertionFieldMatch::Unique { field_index: 0 }
            );
            if !settings_first {
                settings(&shared);
            }
            let frozen = first.first_request.get().unwrap();
            assert!(frozen.encoder_bindings.as_ref().unwrap().complete);
            let mut later = BytesMut::new();
            EncoderInstruction::Duplicate { index: 0 }.encode(&mut later);
            shared
                .feed_instructions(StreamType::QPACK_ENCODER, &later)
                .unwrap();
            let (_, next) = request_at_owner_boundary(&shared, 4, &fields).unwrap();
            assert_eq!(next.stream_id, 4);
            assert_eq!(
                next.view(&next.connection, SettingsStatus::Received, None)
                    .request_stream_id,
                4,
            );
            assert!(Arc::ptr_eq(frozen, next.first_request.get().unwrap()));
            assert!(frozen.encoder_bindings.as_ref().unwrap().complete);
            assert!(!next.connection.encoder_bindings.as_ref().unwrap().complete);
            assert_eq!(
                next.connection.encoder_bindings.as_ref().unwrap().stream_id,
                0
            );
        }
    }

    #[test]
    fn observation_first_request_waits_for_the_ready_control_batch() {
        for headers_first in [false, true] {
            let shared = shared(ObservationLimits::default());
            shared.state.lock().begin_observation_control_batch();
            let first = if headers_first {
                Some(request_at_owner_boundary(&shared, 0, &[]).unwrap().1)
            } else {
                None
            };
            settings(&shared);
            let first =
                first.unwrap_or_else(|| request_at_owner_boundary(&shared, 0, &[]).unwrap().1);
            assert!(first.first_request.get().is_none());
            {
                let mut state = shared.state.lock();
                let record = state.observation.as_mut().unwrap();
                record.control(&FrameEvent::Header(FrameHeader::new(
                    FrameType::new(0x21),
                    1,
                )));
                record.control(&FrameEvent::Ignored {
                    ty: FrameType::new(0x21),
                    len: 1,
                    payload: Some(Bytes::from_static(b"x")),
                });
                state.end_observation_control_batch();
            }
            shared.publish_first_request_observation();
            let boundary = first.first_request.get().unwrap();
            assert_eq!(boundary.control.len(), 2);
            assert_eq!(boundary.control[1].frame_type, 0x21);
            assert_eq!(boundary.control[1].value.as_ref(), b"x");
            shared
                .state
                .lock()
                .observation
                .as_mut()
                .unwrap()
                .stream(6, StreamType::QPACK_ENCODER);
            let later = request_at_owner_boundary(&shared, 4, &[]).unwrap().1;
            assert!(Arc::ptr_eq(boundary, later.first_request.get().unwrap()));
            assert!(boundary.streams.is_empty());
        }
    }

    #[test]
    fn observation_first_request_boundary_does_not_follow_eligible_routes() {
        for settings_first in [false, true] {
            let shared = shared(ObservationLimits::default());
            if settings_first {
                settings(&shared);
            }
            let (_, first) = request_at_owner_boundary(&shared, 0, &[]).unwrap();
            assert_eq!(first.first_request.get().is_some(), settings_first);
            let request_snapshot = first.connection.clone();
            if !settings_first {
                settings(&shared);
                assert!(!request_snapshot.settings_received);
            }
            let boundary = first.first_request.get().unwrap().clone();
            assert!(boundary.settings_received);
            {
                let mut state = shared.state.lock();
                state
                    .observation
                    .as_mut()
                    .unwrap()
                    .stream(6, StreamType::QPACK_ENCODER);
            }
            let (_, request) = request_at_owner_boundary(&shared, 4, &[]).unwrap();
            assert!(Arc::ptr_eq(&boundary, request.first_request.get().unwrap()));
            assert!(request.connection.revision > boundary.revision);
            assert!(boundary.settings_received);
            assert_eq!(boundary.streams.len(), 0);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn observation_settings_waits_are_explicit_and_snapshots_are_immutable() {
        let shared = shared(ObservationLimits::default());
        let observer = observer(&shared);
        let before = observer.snapshot();
        assert!(before.settings.is_none());
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut first = Box::pin(observer.settings(deadline));
        let mut second = Box::pin(observer.settings(deadline));
        let mut cancelled = Box::pin(observer.settings(deadline));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(first.as_mut().poll(&mut cx).is_pending());
        assert!(second.as_mut().poll(&mut cx).is_pending());
        assert!(cancelled.as_mut().poll(&mut cx).is_pending());
        drop(cancelled);
        settings(&shared);
        for future in [&mut first, &mut second] {
            let Poll::Ready(SettingsObservation::Received(snapshot)) =
                future.as_mut().poll(&mut cx)
            else {
                panic!("SETTINGS must wake every remaining waiter");
            };
            let settings = snapshot.settings.as_ref().unwrap();
            assert_eq!(settings[0].id, 0x21);
            assert!(settings[0].grease);
            assert_eq!(settings[1].id, 1);
        }
        assert!(
            before.settings.is_none(),
            "an already-delivered snapshot is immutable"
        );
        assert!(matches!(
            observer.settings(Instant::now()).await,
            SettingsObservation::Received(_)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn observation_settings_timeout_and_close_are_distinct() {
        let shared = shared(ObservationLimits::default());
        let observer = observer(&shared);
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut waiting = Box::pin(observer.settings(deadline));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        let SettingsObservation::TimedOut(snapshot) = waiting.await else {
            panic!("expected capture timeout");
        };
        assert!(snapshot.settings.is_none());
        let mut waiting = Box::pin(observer.settings(Instant::now() + Duration::from_secs(1)));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        shared.fail(Error::connection(
            Code::H3_GENERAL_PROTOCOL_ERROR,
            "test close",
        ));
        assert!(matches!(
            waiting.await,
            SettingsObservation::Closed {
                error: Some(Code::H3_GENERAL_PROTOCOL_ERROR),
                ..
            }
        ));
    }

    #[test]
    fn observation_snapshot_retention_is_bounded_and_recovers_when_released() {
        let shared = shared(ObservationLimits {
            retained_snapshots: 1,
            ..ObservationLimits::default()
        });
        let observer = H3Observer::new(&shared, Arc::new(Default::default()));
        let first = observer.snapshot();
        assert!(first.completeness.snapshot);
        settings(&shared);
        let unavailable = observer.snapshot();
        assert!(!unavailable.completeness.snapshot);
        assert!(Arc::ptr_eq(&unavailable, &observer.snapshot()));
        assert!(first.settings.is_none());
        drop(first);
        let current = observer.snapshot();
        assert!(current.completeness.snapshot);
        assert!(current.settings.is_some());
    }

    #[test]
    fn observation_first_request_pin_counts_toward_snapshot_capacity() {
        let shared = shared(ObservationLimits {
            retained_snapshots: 2,
            ..ObservationLimits::default()
        });
        let observer = observer(&shared);
        settings(&shared);
        shared.state.lock().observation.as_mut().unwrap().changed();
        let retained = observer.snapshot();
        assert!(retained.completeness.snapshot);
        shared.state.lock().observation.as_mut().unwrap().changed();
        assert!(!observer.snapshot().completeness.snapshot);
        drop(retained);
        assert!(observer.snapshot().completeness.snapshot);
        let state = shared.state.lock();
        assert!(
            state
                .observation
                .as_ref()
                .unwrap()
                .first_request
                .get()
                .unwrap()
                .settings_received
        );
    }

    #[test]
    fn observation_first_request_budget_failure_cannot_move_the_boundary() {
        let shared = shared(ObservationLimits {
            retained_snapshots: 1,
            ..ObservationLimits::default()
        });
        let (observer, first) = request_at_owner_boundary(&shared, 0, &[]).unwrap();
        let boundary = first.first_request.clone();
        assert!(boundary.get().is_none());
        settings(&shared);
        assert!(!boundary.get().unwrap().completeness.snapshot);
        drop(first);
        assert!(observer.snapshot().completeness.snapshot);
        assert!(!boundary.get().unwrap().completeness.snapshot);
    }

    #[test]
    fn observation_consumed_instructions_survive_a_later_invalid_instruction() {
        let shared = shared(ObservationLimits::default());
        let observer = observer(&shared);
        let before = observer.snapshot();
        let mut input = Vec::new();
        EncoderInstruction::SetDynamicTableCapacity { capacity: 64 }.encode(&mut input);
        EncoderInstruction::Duplicate { index: 0 }.encode(&mut input);
        shared
            .feed_instructions(StreamType::QPACK_ENCODER, &input)
            .unwrap_err();
        let after = observer.snapshot();
        assert_eq!(after.encoder_instructions.len(), 1);
        assert!(after.revision > before.revision);
        assert!(before.encoder_instructions.is_empty());
    }

    #[test]
    fn observation_request_fields_and_priority_share_a_bounded_budget() {
        let mut encoded = vec![0, 0];
        FieldLine::LiteralWithLiteralName {
            name: Bytes::from_static(b"priority"),
            value: Bytes::from_static(b"u=1"),
            name_huffman: false,
            value_huffman: false,
            never_index: false,
        }
        .encode(&mut encoded);
        for (limits, count, priority, complete) in [
            (ObservationLimits::default(), 1, true, true),
            (
                ObservationLimits {
                    fields: 0,
                    ..ObservationLimits::default()
                },
                0,
                true,
                false,
            ),
            (
                ObservationLimits {
                    bytes: size_of::<ObservedFieldRepresentation>(),
                    ..ObservationLimits::default()
                },
                1,
                false,
                false,
            ),
            (
                ObservationLimits {
                    bytes: 0,
                    ..ObservationLimits::default()
                },
                0,
                false,
                false,
            ),
        ] {
            let shared = shared(limits);
            let fields = shared
                .state
                .lock()
                .decoder
                .decode_field_section(0, Bytes::copy_from_slice(&encoded))
                .unwrap()
                .unwrap();
            let (_, request) = request_at_owner_boundary(&shared, 0, &fields).unwrap();
            assert_eq!(request.fields.len(), count);
            assert_eq!(request.priority.is_some(), priority);
            assert_eq!(request.fields_complete, complete);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn observation_settings_remain_received_when_close_races_delivery() {
        let shared = shared(ObservationLimits::default());
        let observer = observer(&shared);
        let mut waiting = Box::pin(observer.settings(Instant::now() + Duration::from_secs(1)));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        settings(&shared);
        shared.fail(Error::connection(
            Code::H3_GENERAL_PROTOCOL_ERROR,
            "test close",
        ));
        let SettingsObservation::Received(snapshot) = waiting.await else {
            panic!("received SETTINGS must remain observable after close");
        };
        assert!(snapshot.settings.is_some());
        assert_eq!(
            snapshot.connection_error,
            Some(Code::H3_GENERAL_PROTOCOL_ERROR.value())
        );
    }

    #[tokio::test(start_paused = true)]
    async fn observation_client_sections_release_pending_field_metadata() {
        let shared = Shared::new(
            Config {
                observation: Some(Box::new(ObservationLimits {
                    pending_fields: 2,
                    ..ObservationLimits::default()
                })),
                ..Config::default()
            },
            Role::Client,
            Extensions::new(),
        )
        .unwrap();
        let mut encoder = Encoder::before_peer_settings(EncoderConfig::default());
        for id in (0..40).step_by(4) {
            let encoded = encoder.encode(id, [(":status", "200")]).unwrap();
            assert_eq!(shared.decode(id, encoded).await.unwrap().len(), 1);
            assert!(
                shared
                    .state
                    .lock()
                    .decoder
                    .take_field_observation(id)
                    .is_none()
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn observation_settings_waits_for_the_ready_control_batch() {
        let shared = shared(ObservationLimits::default());
        let observer = observer(&shared);
        shared.state.lock().begin_observation_control_batch();
        settings(&shared);
        let mut waiting = Box::pin(observer.settings(Instant::now() + Duration::from_secs(1)));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        shared.state.lock().end_observation_control_batch();
        shared.settings_ready.notify_waiters();
        assert!(matches!(waiting.await, SettingsObservation::Received(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn observation_settings_waits_through_receive_drain() {
        let shared = shared(ObservationLimits::default());
        let observer = observer(&shared);
        shared.state.lock().receive_closed = true;
        let mut waiting = Box::pin(observer.settings(Instant::now() + Duration::from_secs(1)));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        settings(&shared);
        assert!(matches!(waiting.await, SettingsObservation::Received(_)));
    }

    #[test]
    fn observation_settings_receipt_survives_exhausted_capture_budgets() {
        let shared = shared(ObservationLimits {
            bytes: 0,
            events: 0,
            ..ObservationLimits::default()
        });
        let observer = observer(&shared);
        let before = observer.snapshot();
        settings(&shared);
        let after = observer.snapshot();
        assert!(!before.settings_received);
        assert!(after.settings_received);
        assert!(after.settings.is_none());
        assert!(!after.completeness.settings);
        assert!(after.revision > before.revision);
        assert!(matches!(
            SettingsStatus::Pending.for_snapshot(&after),
            SettingsStatus::Incomplete
        ));
    }

    #[test]
    fn observation_overflow_without_new_data_reuses_snapshot() {
        let shared = shared(ObservationLimits {
            streams: 0,
            events: 0,
            ..ObservationLimits::default()
        });
        let observer = observer(&shared);
        let record_event = || {
            let mut state = shared.state.lock();
            let record = state.observation.as_mut().unwrap();
            record.stream(2, StreamType::new(0x21));
            record.control(&FrameEvent::Header(FrameHeader::new(
                FrameType::new(0x21),
                0,
            )));
            record.control(&FrameEvent::Ignored {
                ty: FrameType::new(0x21),
                len: 0,
                payload: None,
            });
        };
        record_event();
        let first = observer.snapshot();
        for _ in 0..100 {
            record_event();
            assert!(Arc::ptr_eq(&first, &observer.snapshot()));
        }
    }

    #[test]
    fn observation_stream_event_and_byte_caps_do_not_grow_with_peer_repeats() {
        for limits in [
            ObservationLimits {
                streams: 1,
                events: 1,
                ..ObservationLimits::default()
            },
            ObservationLimits {
                bytes: 0,
                ..ObservationLimits::default()
            },
        ] {
            let shared = shared(limits);
            let observer = observer(&shared);
            for index in 0..1000 {
                let mut state = shared.state.lock();
                let record = state.observation.as_mut().unwrap();
                record.stream(index * 4 + 2, StreamType::new(0x21));
                record.control(&FrameEvent::Header(FrameHeader::new(
                    FrameType::new(0x21),
                    1000,
                )));
                record.control(&FrameEvent::Ignored {
                    ty: FrameType::new(0x21),
                    len: 1000,
                    payload: None,
                });
            }
            let snapshot = observer.snapshot();
            assert!(snapshot.streams.len() <= limits.streams);
            assert!(snapshot.control.len() <= limits.events);
            assert!(!snapshot.completeness.streams);
            assert!(!snapshot.completeness.control);
            if limits.bytes == 0 {
                assert!(snapshot.streams.is_empty() && snapshot.control.is_empty());
            }
        }
        let shared = Shared::new(Config::default(), Role::Server, Extensions::new()).unwrap();
        assert!(shared.state.lock().observation.is_none());
        assert!(
            shared
                .state
                .lock()
                .decoder
                .instruction_observation()
                .is_none()
        );
        assert!(request_at_owner_boundary(&shared, 0, &[]).is_none());
    }

    #[test]
    fn delayed_publication_keeps_head_qpack_prefix_and_live_cache_separate() {
        for instruction_limit in [1, 256] {
            let shared = shared(ObservationLimits {
                events: instruction_limit,
                ..ObservationLimits::default()
            });
            settings(&shared);
            let mut initial = BytesMut::new();
            EncoderInstruction::SetDynamicTableCapacity { capacity: 4096 }.encode(&mut initial);
            shared
                .feed_instructions(StreamType::QPACK_ENCODER, &initial)
                .unwrap();
            let (observer, first) = shared.request_observation(0, &[]).unwrap();
            assert!(first.first_request.get().is_none());

            let mut later = BytesMut::new();
            EncoderInstruction::InsertWithLiteralName {
                name: Bytes::from_static(b"x-later"),
                value: Bytes::from_static(b"not part of the initial request"),
                name_huffman: false,
                value_huffman: false,
            }
            .encode(&mut later);
            shared
                .feed_instructions(StreamType::QPACK_ENCODER, &later)
                .unwrap();
            let live = observer.snapshot();
            shared.publish_first_request_observation();
            let frozen = first.first_request.get().unwrap();
            assert_eq!(frozen.encoder_instructions.len(), 1);
            assert!(matches!(
                frozen.encoder_instructions[0],
                ObservedEncoderInstruction::Capacity { capacity: 4096 }
            ));
            assert!(frozen.completeness.qpack);
            let bindings = frozen.encoder_bindings.as_ref().unwrap();
            assert_eq!(bindings.stream_id, 0);
            assert!(bindings.insertions.is_empty() && bindings.complete);
            assert!(!Arc::ptr_eq(frozen, &live));
            assert!(Arc::ptr_eq(&live, &observer.snapshot()));
            assert_eq!(
                live.encoder_instructions.len(),
                if instruction_limit == 1 { 1 } else { 2 }
            );
            assert_eq!(live.completeness.qpack, instruction_limit != 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn first_request_waiters_distinguish_settings_publication_and_terminal_drain() {
        let shared = shared(ObservationLimits::default());
        settings(&shared);
        let observer = H3Observer::new(&shared, Arc::new(H3ObservationSnapshot::default()));
        assert!(matches!(
            observer.settings(Instant::now()).await,
            SettingsObservation::Received(_)
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut cx = Context::from_waker(Waker::noop());
        {
            let mut cancelled = pin!(observer.first_request(deadline));
            assert!(cancelled.as_mut().poll(&mut cx).is_pending());
        }

        let mut first_waiter = pin!(observer.first_request(deadline));
        let mut second_waiter = pin!(observer.first_request(deadline));
        assert!(first_waiter.as_mut().poll(&mut cx).is_pending());
        assert!(second_waiter.as_mut().poll(&mut cx).is_pending());
        let (_, first) = shared.request_observation(0, &[]).unwrap();
        shared.state.lock().receive_closed = true;
        shared.settings_ready.notify_waiters();
        assert!(first_waiter.as_mut().poll(&mut cx).is_pending());
        assert!(second_waiter.as_mut().poll(&mut cx).is_pending());
        shared.publish_first_request_observation();
        let expected = first.first_request.get().unwrap();
        for waiter in [first_waiter.as_mut(), second_waiter.as_mut()] {
            let Poll::Ready(FirstRequestObservation::Ready(snapshot)) = waiter.poll(&mut cx) else {
                panic!("buffered publication must win over the early receive-closed signal")
            };
            assert!(Arc::ptr_eq(expected, &snapshot));
        }
        shared.fail(Error::connection(
            Code::H3_NO_ERROR,
            "clean close after buffered drain",
        ));
        let FirstRequestObservation::Ready(snapshot) = observer.first_request(deadline).await
        else {
            panic!("published facts must remain observable after a clean close")
        };
        assert!(Arc::ptr_eq(expected, &snapshot));
    }

    #[tokio::test(start_paused = true)]
    async fn first_request_timeout_and_failure_do_not_imply_a_published_boundary() {
        let shared = shared(ObservationLimits::default());
        let observer = H3Observer::new(&shared, Arc::new(H3ObservationSnapshot::default()));
        let FirstRequestObservation::TimedOut(snapshot) =
            observer.first_request(Instant::now()).await
        else {
            panic!("an expired consumer deadline must be explicit")
        };
        assert!(!snapshot.settings_received);
        assert!(
            shared
                .state
                .lock()
                .observation
                .as_ref()
                .unwrap()
                .first_request
                .get()
                .is_none()
        );
        let failure = Error::connection(
            Code::H3_GENERAL_PROTOCOL_ERROR,
            "peer failed before publication",
        );
        shared.fail(failure);
        let FirstRequestObservation::Closed { snapshot, error } = observer
            .first_request(Instant::now() + Duration::from_secs(1))
            .await
        else {
            panic!("a failed connection must wake publication waiters")
        };
        assert_eq!(error, Some(failure.code()));
        assert_eq!(snapshot.connection_error, Some(failure.code().value()));
    }
}
