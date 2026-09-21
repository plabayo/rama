//! Connection-owned compression and critical-stream state.

use super::{
    Error,
    control::{Control, Role},
    frame::{FrameDecoder, FrameEvent},
    qpack::{Decoder, DecoderConfig, Encoder, EncoderConfig, FieldPair, QpackError},
};
use parking_lot::Mutex;
use rama_core::bytes::{Bytes, BytesMut};
use rama_http_types::proto::h3::{
    Code, FrameHeader, FrameType, SettingId, Settings, StreamType, VarInt, VarIntDecoder,
};
use rama_quic_proto::coding::Codec;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use tokio::sync::{Notify, oneshot};

/// Local HTTP/3 connection budgets. Peer limits are negotiated independently.
#[derive(Clone, Debug)]
pub struct Config {
    /// Local QPACK decoder limits, advertised where the protocol defines settings.
    pub decoder: DecoderConfig,
    /// Local encoder budgets. Peer capacity/blocked-stream settings override those fields.
    pub encoder: EncoderConfig,
    /// Maximum concurrent application requests retained by the engine.
    pub max_requests: usize,
    /// Lifetime push quota; zero disables push. Bounds reordered push state.
    pub max_pushes: usize,
    /// Maximum buffered encoded non-DATA frame.
    pub max_frame_size: usize,
    /// Maximum QUIC chunk held by a stream reader.
    pub read_chunk_size: usize,
    /// Maximum unclassified peer unidirectional streams retained simultaneously.
    pub max_pending_uni_streams: usize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            decoder: DecoderConfig::default(),
            encoder: EncoderConfig::default(),
            max_requests: 128,
            max_pushes: 0,
            max_frame_size: rama_utils::octets::kib(64),
            read_chunk_size: rama_utils::octets::kib(16),
            max_pending_uni_streams: 32,
        }
    }
}

impl Config {
    /// Apply finite HTTP/3 receive budgets to a QUIC transport configuration.
    /// Configure the endpoint before establishing connections.
    pub fn configure_transport(
        &self,
        transport: &mut rama_quic::TransportConfig,
    ) -> Result<(), Error> {
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
        transport.set_stream_receive_window(VarInt::from_u32(rama_utils::octets::kib(256) as u32));
        transport.set_receive_window(VarInt::from_u32(rama_utils::octets::mib(8) as u32));
        Ok(())
    }

    pub(crate) fn settings(&self) -> Result<Settings, Error> {
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

// Enough for multiple decoder acknowledgements and GOAWAY; ordinary writes leave
// this credit for critical streams. QUIC caps it for very small peer windows.
pub(crate) const CRITICAL_SEND_RESERVE: u64 = 64;

type Decoded = Result<Vec<FieldPair>, Error>;
struct State {
    control: Control,
    encoder: Encoder,
    decoder: Decoder,
    waiting: BTreeMap<u64, oneshot::Sender<Decoded>>,
    cancelled: BTreeSet<u64>,
    error: Option<Error>,
    control_output: VecDeque<(Bytes, Option<u64>)>,
    control_in_flight: bool,
    local_goaway: Option<u64>,
}

pub(crate) struct Shared {
    pub(crate) role: Role,
    pub(crate) pushes: Mutex<super::push::State>,
    pub(crate) push_ready: Notify,
    pub(crate) transport_extensions: rama_core::extensions::Extensions,
    state: Mutex<State>,
    encoder_stream: Mutex<Option<rama_quic::SendStream>>,
    pub(crate) config: Config,
    output: [Notify; 2],
    progress: Notify,
    failure: Notify,
    control_ready: Notify,
    pub(crate) schedule: Mutex<super::priority::Schedule>,
}

impl Shared {
    pub(crate) fn new(config: Config, role: Role) -> Result<Arc<Self>, Error> {
        config.settings()?;
        Ok(Arc::new(Self {
            role,
            pushes: Mutex::new(super::push::State::new()),
            push_ready: Notify::new(),
            transport_extensions: rama_core::extensions::Extensions::new(),
            encoder_stream: Mutex::new(None),
            state: Mutex::new(State {
                control: Control::new(role),
                encoder: Encoder::before_peer_settings(config.encoder),
                decoder: Decoder::new(config.decoder),
                waiting: BTreeMap::new(),
                cancelled: BTreeSet::new(),
                error: None,
                control_output: VecDeque::new(),
                control_in_flight: false,
                local_goaway: None,
            }),
            schedule: Mutex::new(super::priority::Schedule::new(
                config.max_requests.saturating_add(config.max_pushes),
            )),
            config,
            output: [Notify::new(), Notify::new()],
            progress: Notify::new(),
            failure: Notify::new(),
            control_ready: Notify::new(),
        }))
    }

    #[cfg(test)]
    pub(crate) fn dynamic_insert_count(&self) -> u64 {
        self.state.lock().encoder.insert_count()
    }

    pub(crate) fn error(&self) -> Option<Error> {
        self.state.lock().error
    }

    pub(crate) fn fail(&self, error: Error) {
        let mut state = self.state.lock();
        if state.error.is_none() {
            state.error = Some(error);
        }
        for (_, tx) in std::mem::take(&mut state.waiting) {
            _ = tx.send(Err(error));
        }
        drop(state);
        self.progress.notify_waiters();
        self.push_ready.notify_waiters();
        self.failure.notify_waiters();
        for output in &self.output {
            output.notify_one();
        }
    }

    pub(crate) async fn failed(&self) -> Error {
        loop {
            let failed = self.failure.notified();
            let mut failed = std::pin::pin!(failed);
            failed.as_mut().enable();
            if let Some(error) = self.error() {
                return error;
            }
            failed.await;
        }
    }

    pub(crate) async fn rejected(&self, id: Option<u64>) -> Error {
        loop {
            let progress = self.progress.notified();
            let mut progress = std::pin::pin!(progress);
            progress.as_mut().enable();
            if let Some(error) = self.error() {
                return error;
            }
            if self
                .goaway()
                .is_some_and(|limit| id.is_none_or(|id| id >= limit))
            {
                return Error::stream(Code::H3_REQUEST_REJECTED, "request excluded by GOAWAY");
            }
            progress.await;
        }
    }

    pub(crate) fn send_priority(
        &self,
        id: u64,
        push: bool,
        priority: rama_http::headers::Priority,
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
        bytes.extend_from_slice(value.as_bytes());
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
        state.control_output.push_back((bytes.freeze(), None));
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
        state.control_output.push_back((
            bytes.freeze(),
            (ty == FrameType::MAX_PUSH_ID).then_some(id.into_inner()),
        ));
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
        state.control_output.push_back((bytes.freeze(), None));
        drop(state);
        self.control_ready.notify_one();
        Ok(())
    }

    pub(crate) fn goaway(&self) -> Option<u64> {
        self.state.lock().control.goaway()
    }

    pub(crate) fn cancel(&self, id: u64) {
        let mut state = self.state.lock();
        state.waiting.remove(&id);
        match state.decoder.cancel_stream(id) {
            Ok(()) => (),
            Err(QpackError::OutputBlocked) => {
                if state.cancelled.len() >= self.config.max_requests
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
        self.output[1].notify_one();
    }

    pub(crate) async fn decode(&self, id: u64, bytes: Bytes) -> Decoded {
        loop {
            // Enable before trying the codec, closing the drain-before-wait race.
            let progress = self.progress.notified();
            let mut progress = std::pin::pin!(progress);
            progress.as_mut().enable();
            let receiver = {
                let mut state = self.state.lock();
                if let Some(error) = state.error {
                    return Err(error);
                }
                match state.decoder.decode_field_section(id, bytes.clone()) {
                    Ok(Some(fields)) => {
                        self.output[1].notify_one();
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
                    Err(error) => return Err(compression_error(error)),
                }
            };
            self.output[1].notify_one();
            if let Some(receiver) = receiver {
                return receiver.await.unwrap_or(Err(Error::stream(
                    Code::H3_REQUEST_CANCELLED,
                    "field section cancelled",
                )));
            }
            progress.await;
        }
    }

    pub(crate) fn encode<I, F, N, V>(&self, id: u64, fields: I) -> Result<Bytes, Error>
    where
        I: IntoIterator<Item = F>,
        F: Into<super::qpack::EncodeField<N, V>>,
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        let mut state = self.state.lock();
        if let Some(error) = state.error {
            return Err(error);
        }
        let mut stream = self.encoder_stream.lock();
        if let Some(stream) = stream.as_mut() {
            stream
                .try_write_generated(CRITICAL_SEND_RESERVE, |credit| {
                    let result = state
                        .encoder
                        .encode_with_credit(id, fields, credit)
                        .map_err(compression_error);
                    (state.encoder.take_encoder_stream(), result)
                })
                .map_err(|_error| {
                    Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "encoder stream closed")
                })?
        } else {
            state
                .encoder
                .encode_with_credit(id, fields, 0)
                .map_err(compression_error)
        }
    }

    fn resume(state: &mut State) -> Result<(), Error> {
        for _ in 0..super::cooperative::OPERATIONS_PER_QUANTUM {
            let Some((id, result)) = state.decoder.resume_next() else {
                break;
            };
            if matches!(result, Err(QpackError::OutputBlocked)) {
                break;
            }
            let result = result.map_err(compression_error);
            let failure = result.as_ref().err().copied();
            if let Some(tx) = state.waiting.remove(&id) {
                _ = tx.send(result);
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
            let mut changed = std::pin::pin!(changed);
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
        let result = if ty == StreamType::QPACK_ENCODER {
            state.decoder.feed_encoder_stream(chunk)
        } else {
            state.encoder.feed_decoder_stream(chunk)
        };
        let blocked = match result {
            Ok(()) => {
                Self::resume(&mut state)?;
                false
            }
            Err(QpackError::OutputBlocked) => true,
            Err(error) => return Err(compression_error(error)),
        };
        drop(state);
        self.output[1].notify_one();
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

    pub(super) fn take_output(&self, encoder: bool) -> Result<Bytes, Error> {
        let mut state = self.state.lock();
        if let Some(error) = state.error {
            return Err(error);
        }
        let output = if encoder {
            state.encoder.take_encoder_stream()
        } else {
            state.decoder.take_output_for_write()
        };
        drop(state);
        self.progress.notify_waiters();
        Ok(output)
    }
}

fn compression_error(error: QpackError) -> Error {
    Error::from_qpack(error).unwrap_or(Error::connection(
        Code::H3_INTERNAL_ERROR,
        "unexpected local QPACK backpressure",
    ))
}

pub(crate) async fn write_instructions(
    shared: Arc<Shared>,
    mut stream: rama_quic::SendStream,
    encoder: bool,
) -> Result<(), Error> {
    stream.set_priority(i32::MAX).map_err(|_error| {
        Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "critical stream closed")
    })?;
    let ty = if encoder {
        StreamType::QPACK_ENCODER
    } else {
        StreamType::QPACK_DECODER
    };
    let mut bytes = BytesMut::with_capacity(1);
    VarInt::from_u32(ty.value() as u32).encode(&mut bytes);
    let mut output = [bytes.freeze()];
    let mut instructions = false;
    loop {
        while !output[0].is_empty() {
            let before = output[0].len();
            stream.write_chunks(&mut output).await.map_err(|_error| {
                Error::connection(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    "critical send stream closed",
                )
            })?;
            if instructions {
                shared.decoder_output_written(before - output[0].len())?;
            }
        }
        if encoder {
            let stopped = stream.stopped();
            *shared.encoder_stream.lock() = Some(stream);
            _ = stopped.await;
            return Err(Error::connection(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "encoder stream stopped",
            ));
        }
        output[0] = shared.take_output(encoder)?;
        instructions = true;
        if output[0].is_empty() {
            tokio::select! {
                _ = shared.output[usize::from(!encoder)].notified() => (),
                _ = stream.stopped() => return Err(Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "critical stream stopped")),
            }
        }
    }
}

pub(crate) async fn receive_uni(
    shared: Arc<Shared>,
    mut stream: rama_quic::RecvStream,
) -> Result<(), Error> {
    let mut kind = VarIntDecoder::new();
    let (ty, mut chunk) = loop {
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
    shared.state.lock().control.register(ty)?;
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
    let mut frames =
        FrameDecoder::with_input_limit(shared.config.max_frame_size, shared.config.read_chunk_size)
            .with_header_events();
    let mut budget = super::cooperative::Budget::default();
    loop {
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
                if let FrameEvent::Settings(ref settings) = event {
                    state
                        .encoder
                        .apply_peer_settings(settings)
                        .map_err(compression_error)?;
                }
                drop(state);
                if let FrameEvent::MaxPushId(id) = event {
                    shared.pushes.lock().max_id(id);
                    shared.push_ready.notify_waiters();
                }
                if let FrameEvent::CancelPush(id) = event {
                    shared.cancel_push(id, false)?;
                }
                if let FrameEvent::GoAway(limit) = event
                    && shared.role == Role::Server
                {
                    shared.pushes.lock().reject_from(limit);
                }
                if let FrameEvent::PriorityUpdate {
                    push,
                    element_id,
                    ref field_value,
                } = event
                {
                    if push {
                        let priority = rama_http::headers::Priority::parse(field_value).ok();
                        if let Some(id) = shared.pushes.lock().priority(element_id, priority)?
                            && let Some(priority) = priority
                        {
                            shared.schedule.lock().peer_priority(id, priority);
                        }
                        continue;
                    }
                    if element_id % 4 != 0 {
                        return Err(Error::connection(
                            Code::H3_ID_ERROR,
                            "priority target is not a request stream",
                        ));
                    }
                    if let Ok(priority) = rama_http::headers::Priority::parse(field_value) {
                        shared.schedule.lock().update(element_id, priority)?;
                    }
                }
                shared.progress.notify_waiters();
                shared.push_ready.notify_waiters();
            }
        } else {
            // Retry the same bytes on local output backpressure; codec feed is transactional.
            loop {
                let progress = shared.progress.notified();
                let mut progress = std::pin::pin!(progress);
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
            .map_err(|_error| {
                Error::connection(
                    Code::H3_CLOSED_CRITICAL_STREAM,
                    "critical receive stream reset",
                )
            })?
            .ok_or(Error::connection(
                Code::H3_CLOSED_CRITICAL_STREAM,
                "critical receive stream closed",
            ))?
            .bytes;
    }
}

pub(crate) fn initial_control(config: &Config) -> Result<Bytes, Error> {
    let settings = config.settings()?;
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
    Ok(output.freeze())
}

/// Drives the HTTP/3 control and QPACK streams independently of application bodies.
///
/// Run this future for as long as the connection is used. Dropping it closes the
/// connection and wakes blocked field sections.
pub struct Driver {
    connection: rama_quic::Connection,
    shared: Arc<Shared>,
    role: Role,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Driver")
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

impl Driver {
    pub(crate) fn new(connection: rama_quic::Connection, shared: Arc<Shared>, role: Role) -> Self {
        Self {
            connection,
            shared,
            role,
        }
    }

    /// Run until the transport closes or a connection-level protocol error occurs.
    pub async fn run(self) -> Result<(), Error> {
        let result = self.run_inner().await;
        if let Err(error) = result {
            self.shared.fail(error);
            if let Ok(code) = VarInt::from_u64(error.code().value()) {
                self.connection.close(code, b"HTTP/3 connection error");
            }
        }
        result
    }

    async fn run_inner(&self) -> Result<(), Error> {
        use rama_core::futures::{StreamExt, stream::FuturesUnordered};
        self.connection
            .handshake_confirmed()
            .await
            .map_err(|_error| {
                Error::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "QUIC handshake failed")
            })?;
        let alpn = self
            .connection
            .handshake_data()
            .and_then(|data| data.application_layer_protocol);
        if alpn != Some(rama_net::tls::ApplicationProtocol::HTTP_3) {
            return Err(Error::connection(
                Code::H3_GENERAL_PROTOCOL_ERROR,
                "HTTP/3 requires h3 ALPN",
            ));
        }
        if self
            .connection
            .max_concurrent_streams(rama_quic_proto::Dir::Uni)
            < 3
        {
            return Err(Error::connection(
                Code::H3_STREAM_CREATION_ERROR,
                "local endpoint must permit three critical streams",
            ));
        }
        let open = || async {
            self.connection.open_uni().await.map_err(|_error| {
                Error::connection(
                    Code::H3_STREAM_CREATION_ERROR,
                    "cannot open critical stream",
                )
            })
        };
        let (mut control, encoder, decoder) = tokio::try_join!(open(), open(), open())?;
        let control_task = async {
            control.set_priority(i32::MAX).map_err(|_error| {
                Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "control stream closed")
            })?;
            let mut bytes = [initial_control(&self.shared.config)?];
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
            loop {
                let next = {
                    let mut state = self.shared.state.lock();
                    let next = state.control_output.pop_front();
                    state.control_in_flight = next.is_some();
                    next
                };
                if let Some((bytes, push_grant)) = next {
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
                    self.shared.progress.notify_waiters();
                } else {
                    tokio::select! {
                        _ = self.shared.control_ready.notified() => (),
                        _ = control.stopped() => return Err(Error::connection(Code::H3_CLOSED_CRITICAL_STREAM, "control stream stopped")),
                    }
                }
            }
        };
        let receive = async {
            let mut streams = FuturesUnordered::new();
            loop {
                tokio::select! {
                    result = self.connection.accept_uni() => {
                        let stream = result.map_err(|_error| Error::connection(Code::H3_GENERAL_PROTOCOL_ERROR, "QUIC accept failed"))?;
                        if streams.len() >= self.shared.config.max_pending_uni_streams {
                            return Err(Error::connection(Code::H3_EXCESSIVE_LOAD, "too many pending unidirectional streams"));
                        }
                        streams.push(receive_uni(self.shared.clone(), stream));
                    }
                    result = streams.next(), if !streams.is_empty() => {
                        if let Some(result) = result { result?; }
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
            std::future::pending::<Result<(), Error>>().await
        };
        tokio::select! {
            error = self.shared.failed() => Err(error),
            result = control_task => result,
            result = write_instructions(self.shared.clone(), encoder, true) => result,
            result = write_instructions(self.shared.clone(), decoder, false) => result,
            result = receive => result,
            result = reject_server_bidi => result,
            error = self.connection.closed() => {
                let error = Error::from_transport(&error);
                if error.code() == Code::H3_NO_ERROR { Ok(()) } else { Err(error) }
            },
        }
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.shared.fail(Error::connection(
            Code::H3_REQUEST_CANCELLED,
            "HTTP/3 driver stopped",
        ));
        self.connection.close(
            VarInt::from_u32(Code::H3_NO_ERROR.value() as u32),
            b"HTTP/3 driver stopped",
        );
    }
}
