//! Two senders sharing one bottleneck link in virtual time, to measure how the congestion
//! controller and the pacer of a connection divide that link with a competing flow.
//!
//! The first flow runs the configured [`Controller`] and the connection's [`Pacer`], called in
//! the order and with the arguments `poll_transmit` and loss recovery use. The second is a
//! reference CUBIC sender without pacing, standing in for a bulk TCP transfer.

use std::{
    collections::{BTreeMap, VecDeque},
    ops::Range,
};

use rand::prelude::*;
use rand_pcg::Pcg32;

use crate::proto::{
    CongestionControl, Duration, Instant, TIMER_GRANULARITY, TransportConfig,
    congestion::Controller,
    connection::{RttEstimator, pacing::Pacer},
};

mod tests;

/// Rate of the shared link in bits per second.
const LINK_BITS_PER_SECOND: u64 = 10_000_000;
/// Propagation delay of the shared link in each direction.
const LINK_DELAY: Duration = Duration::from_millis(15);
/// Spacing of the packets of one burst on the sender's own, much faster, access link.
const ACCESS_SPACING: Duration = Duration::from_micros(12);
/// IPv4 and UDP headers around a QUIC datagram.
const UDP_OVERHEAD: u64 = 28;
/// IPv4 and TCP headers, with timestamps, around a full segment.
const TCP_OVERHEAD: u64 = 52;
/// Datagram size the measured sender settles on over an Ethernet path.
const DATAGRAM_SIZE: u16 = 1452;
/// Segment size of the competing flow over the same path.
const SEGMENT_SIZE: u16 = 1448;
/// Datagrams one `poll_transmit` call may build for a single segmented send.
const SEGMENTS_PER_TRANSMIT: usize = 10;
/// The delay a QUIC receiver may add before acknowledging, as its default transport parameter.
const QUIC_MAX_ACK_DELAY: Duration = Duration::from_millis(25);
/// The delayed acknowledgement timer of the competing flow's receiver.
const TCP_MAX_ACK_DELAY: Duration = Duration::from_millis(40);
/// Head start of the competing flow, so the measured one joins a link already in use.
const COMPETITOR_HEAD_START: Duration = Duration::from_secs(5);

/// The congestion controller of the competing flow.
#[derive(Clone, Copy)]
pub(super) enum Rival {
    /// The reference CUBIC sender.
    Cubic,
    /// The crate's NewReno controller, which halves its window on loss.
    Reno,
}

/// One measurement: who shares the link, how the measured flow is acknowledged, and for how long.
#[derive(Clone, Copy)]
pub(super) struct Scenario {
    /// Seed of every random choice; equal scenarios give equal outcomes.
    pub(super) seed: u64,
    /// Packets the competing flow's receiver collects before it acknowledges; `None` leaves
    /// the measured flow alone on the link.
    pub(super) competitor: Option<usize>,
    /// The competing flow's congestion controller.
    pub(super) rival: Rival,
    /// Packets the link holds behind the one it is serialising; an arrival beyond that is
    /// dropped.
    pub(super) queue: usize,
    /// Packets the measured flow's receiver collects before it acknowledges.
    pub(super) ack_every: usize,
    /// Upper bound of the scheduling delay added to every sender wake-up.
    pub(super) jitter: Duration,
    /// Time measured, starting when the measured flow starts.
    pub(super) duration: Duration,
}

/// What one scenario measured.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Outcome {
    /// Bytes per second delivered for the measured flow, in kbit/s.
    pub(super) kbps: f64,
    /// The same for the competing flow over the same period; zero without one.
    pub(super) competitor_kbps: f64,
    /// Fraction of the measured flow's packets it declared lost.
    pub(super) loss_rate: f64,
    /// Times the measured flow's congestion window was reduced.
    pub(super) reductions: u64,
    /// Mean number of packets the measured flow released per wake-up that sent anything.
    pub(super) mean_burst: f64,
}

impl Scenario {
    /// Runs the scenario to its end.
    pub(super) fn run(self) -> Outcome {
        let start = Instant::now();
        let mut rng = Pcg32::seed_from_u64(self.seed);
        let config = TransportConfig::default();

        let lead = if self.competitor.is_some() {
            COMPETITOR_HEAD_START
        } else {
            Duration::ZERO
        };
        let measured_start = start + lead + random_delay(&mut rng, Duration::from_millis(100));
        let measured = Flow::new(
            Sender::measured(&config, start),
            Receiver::new(self.ack_every, 1, QUIC_MAX_ACK_DELAY, true),
            u64::from(DATAGRAM_SIZE) + UDP_OVERHEAD,
            start,
        );
        let mut world = World {
            events: BTreeMap::new(),
            scheduled: 0,
            rng,
            jitter: self.jitter,
            queue: self.queue,
            link: Link::default(),
            flows: vec![measured],
            measure: measured_start..measured_start + self.duration,
        };
        world.schedule(measured_start, Event::Wake { flow: 0 });
        if let Some(ack_every) = self.competitor {
            world.flows.push(Flow::new(
                Sender::competitor(&config, self.rival, start),
                // Three prompt acknowledgements above a hole are a TCP sender's duplicate threshold.
                Receiver::new(ack_every, 3, TCP_MAX_ACK_DELAY, false),
                u64::from(SEGMENT_SIZE) + TCP_OVERHEAD,
                start,
            ));
            let at = start + random_delay(&mut world.rng, Duration::from_millis(50));
            world.schedule(at, Event::Wake { flow: 1 });
        }
        world.run();

        let seconds = self.duration.as_secs_f64();
        let kbps = |flow: &Flow| flow.receiver.delivered as f64 * 8.0 / seconds / 1000.0;
        let measured = &world.flows[0];
        let sender = &measured.sender;
        Outcome {
            kbps: kbps(measured),
            competitor_kbps: world.flows.get(1).map_or(0.0, kbps),
            loss_rate: sender.lost as f64 / sender.next_packet.max(1) as f64,
            reductions: sender.reductions,
            mean_burst: sender.released as f64 / sender.bursts.max(1) as f64,
        }
    }
}

fn random_delay(rng: &mut Pcg32, bound: Duration) -> Duration {
    Duration::from_nanos(rng.random_range(0..=bound.as_nanos() as u64))
}

enum Event {
    /// A sender starts, or a timer of its connection may be due.
    Wake { flow: usize },
    /// A packet reaches the queue of the shared link.
    Arrive { flow: usize, packet: u64 },
    /// The link finished serialising the packet at the head of its queue.
    Serialised { flow: usize, packet: u64 },
    /// A packet reaches its receiver.
    Deliver { flow: usize, packet: u64 },
    /// The delayed acknowledgement timer of a receiver expired.
    AckDelay { flow: usize },
    /// An acknowledgement reaches its sender.
    Acknowledge { flow: usize, ack: Ack },
}

struct Ack {
    largest: u64,
    /// Packets received since the previous acknowledgement, in ascending order.
    packets: Vec<u64>,
    delay: Duration,
}

#[derive(Default)]
struct Link {
    busy: bool,
    queue: VecDeque<(usize, u64)>,
}

struct Flow {
    sender: Sender,
    receiver: Receiver,
    /// Size of one packet on the shared link.
    wire: u64,
    /// When the previous packet of this flow reached the shared link.
    last_arrival: Instant,
    /// When the sender last handled an acknowledgement; later ones are not handled earlier.
    last_handled: Instant,
    /// Deadline of the wake-up already scheduled for the sender's timers.
    armed: Option<Instant>,
}

impl Flow {
    fn new(sender: Sender, receiver: Receiver, wire: u64, start: Instant) -> Self {
        Self {
            sender,
            receiver,
            wire,
            last_arrival: start,
            last_handled: start,
            armed: None,
        }
    }
}

struct World {
    events: BTreeMap<(Instant, u64), Event>,
    scheduled: u64,
    rng: Pcg32,
    jitter: Duration,
    queue: usize,
    link: Link,
    flows: Vec<Flow>,
    measure: Range<Instant>,
}

impl World {
    fn schedule(&mut self, at: Instant, event: Event) {
        self.events.insert((at, self.scheduled), event);
        self.scheduled += 1;
    }

    fn run(&mut self) {
        while let Some(((now, _), event)) = self.events.pop_first() {
            if now >= self.measure.end {
                break;
            }
            match event {
                Event::Wake { flow } => {
                    let state = &mut self.flows[flow];
                    if state.armed.is_some_and(|at| at <= now) {
                        state.armed = None;
                    }
                    state.sender.on_timeout(now);
                    self.transmit(flow, now);
                }
                Event::Arrive { flow, packet } => self.arrive(flow, packet, now),
                Event::Serialised { flow, packet } => {
                    self.schedule(now + LINK_DELAY, Event::Deliver { flow, packet });
                    match self.link.queue.pop_front() {
                        Some((flow, packet)) => self.serialise(flow, packet, now),
                        None => self.link.busy = false,
                    }
                }
                Event::Deliver { flow, packet } => {
                    let counted = self.measure.contains(&now);
                    let state = &mut self.flows[flow];
                    if counted {
                        state.receiver.delivered += u64::from(state.sender.packet_size);
                    }
                    match state.receiver.on_packet(packet, now) {
                        Response::Acknowledge(ack) => self.acknowledge(flow, ack, now),
                        Response::Delay(at) => self.schedule(at, Event::AckDelay { flow }),
                        Response::Nothing => {}
                    }
                }
                Event::AckDelay { flow } => {
                    if let Some(ack) = self.flows[flow].receiver.on_delay_expired(now) {
                        self.acknowledge(flow, ack, now);
                    }
                }
                Event::Acknowledge { flow, ack } => {
                    self.flows[flow].sender.on_ack(now, &ack);
                    self.transmit(flow, now);
                }
            }
        }
    }

    fn arrive(&mut self, flow: usize, packet: u64, now: Instant) {
        if !self.link.busy {
            self.link.busy = true;
            self.serialise(flow, packet, now);
        } else if self.link.queue.len() < self.queue {
            self.link.queue.push_back((flow, packet));
        }
    }

    fn serialise(&mut self, flow: usize, packet: u64, now: Instant) {
        let nanos = self.flows[flow].wire * 8 * 1_000_000_000 / LINK_BITS_PER_SECOND;
        self.schedule(
            now + Duration::from_nanos(nanos),
            Event::Serialised { flow, packet },
        );
    }

    /// The acknowledgement crosses the uncongested return path and waits for the sender's task.
    fn acknowledge(&mut self, flow: usize, ack: Ack, now: Instant) {
        let late = random_delay(&mut self.rng, self.jitter);
        let state = &mut self.flows[flow];
        let at = (now + LINK_DELAY + late).max(state.last_handled);
        state.last_handled = at;
        self.schedule(at, Event::Acknowledge { flow, ack });
    }

    /// Lets the sender transmit what it may, puts that on the link and re-arms its timers.
    fn transmit(&mut self, flow: usize, now: Instant) {
        let state = &mut self.flows[flow];
        let packets = state.sender.poll_transmit(now);
        let mut arrivals = Vec::with_capacity(packets.len());
        for packet in packets {
            let at = now.max(state.last_arrival + ACCESS_SPACING);
            state.last_arrival = at;
            arrivals.push((at, packet));
        }
        let deadline = state.sender.next_timeout();
        let arm = deadline.filter(|&at| state.armed.is_none_or(|armed| at < armed));
        if arm.is_some() {
            state.armed = arm;
        }
        for (at, packet) in arrivals {
            self.schedule(at, Event::Arrive { flow, packet });
        }
        if let Some(at) = arm {
            let late = random_delay(&mut self.rng, self.jitter);
            self.schedule(at.max(now) + late, Event::Wake { flow });
        }
    }
}

enum Response {
    Acknowledge(Ack),
    Delay(Instant),
    Nothing,
}

struct Receiver {
    ack_every: usize,
    /// Packets acknowledged at once from the first one that arrives above a hole.
    prompt_after_gap: usize,
    max_ack_delay: Duration,
    /// Whether acknowledgements carry how long the largest packet was held back.
    reports_delay: bool,
    largest: Option<(u64, Instant)>,
    pending: Vec<u64>,
    prompt: usize,
    delay_expires: Option<Instant>,
    delivered: u64,
}

impl Receiver {
    fn new(
        ack_every: usize,
        prompt_after_gap: usize,
        max_ack_delay: Duration,
        reports_delay: bool,
    ) -> Self {
        Self {
            ack_every,
            prompt_after_gap,
            max_ack_delay,
            reports_delay,
            largest: None,
            pending: Vec::new(),
            prompt: 0,
            delay_expires: None,
            delivered: 0,
        }
    }

    fn on_packet(&mut self, packet: u64, now: Instant) -> Response {
        let expected = self.largest.map_or(0, |(largest, _)| largest + 1);
        if packet > expected {
            self.prompt = self.prompt_after_gap;
        }
        if packet >= expected {
            self.largest = Some((packet, now));
        }
        self.pending.push(packet);
        if self.prompt > 0 || self.pending.len() >= self.ack_every {
            self.prompt = self.prompt.saturating_sub(1);
            return self
                .take(now)
                .map_or(Response::Nothing, Response::Acknowledge);
        }
        if self.delay_expires.is_none() {
            let at = now + self.max_ack_delay;
            self.delay_expires = Some(at);
            return Response::Delay(at);
        }
        Response::Nothing
    }

    fn on_delay_expired(&mut self, now: Instant) -> Option<Ack> {
        self.delay_expires
            .is_some_and(|at| at <= now)
            .then(|| self.take(now))
            .flatten()
    }

    fn take(&mut self, now: Instant) -> Option<Ack> {
        self.delay_expires = None;
        let (largest, received) = self.largest?;
        if self.pending.is_empty() {
            return None;
        }
        Some(Ack {
            largest,
            packets: std::mem::take(&mut self.pending),
            delay: if self.reports_delay {
                now - received
            } else {
                Duration::ZERO
            },
        })
    }
}

/// The sending half of a connection with a never-ending stream to send: the congestion
/// controller, the pacer and loss recovery, driven as the connection drives them.
struct Sender {
    controller: Box<dyn Controller>,
    pacer: Option<Pacer>,
    rtt: RttEstimator,
    packet_size: u16,
    packet_threshold: u64,
    time_threshold: f32,
    persistent_congestion_threshold: u32,
    peer_max_ack_delay: Duration,

    /// Send times of the packets neither acknowledged nor declared lost.
    sent: BTreeMap<u64, Instant>,
    next_packet: u64,
    in_flight: u64,
    app_limited: bool,
    largest_acked: Option<u64>,
    largest_acked_sent: Instant,
    last_sent: Instant,
    first_packet_after_rtt_sample: Option<u64>,
    loss_time: Option<Instant>,
    loss_detection: Option<Instant>,
    pacing: Option<Instant>,
    pto_count: u32,
    loss_probes: u32,

    lost: u64,
    reductions: u64,
    bursts: u64,
    released: u64,
}

impl Sender {
    /// The sender of a connection with the default transport configuration.
    fn measured(config: &TransportConfig, now: Instant) -> Self {
        let mut controller = config
            .congestion_factory()
            .build(now, config.get_initial_mtu());
        // Path MTU discovery settles before the transfer is far along.
        controller.on_mtu_update(DATAGRAM_SIZE);
        let pacer = Pacer::starting(
            config.initial_rtt,
            controller.initial_window(),
            config.get_initial_mtu(),
            now,
        );
        Self::new(
            controller,
            Some(pacer),
            DATAGRAM_SIZE,
            QUIC_MAX_ACK_DELAY,
            config,
            now,
        )
    }

    /// An unpaced loss-based sender, because that is what a bulk TCP transfer on the same link
    /// is.
    fn competitor(config: &TransportConfig, rival: Rival, now: Instant) -> Self {
        let controller: Box<dyn Controller> = match rival {
            Rival::Cubic => Box::new(ReferenceCubic::new(SEGMENT_SIZE)),
            Rival::Reno => TransportConfig::default()
                .with_congestion_control(CongestionControl::NewReno)
                .congestion_factory()
                .build(now, SEGMENT_SIZE),
        };
        Self::new(controller, None, SEGMENT_SIZE, Duration::ZERO, config, now)
    }

    fn new(
        controller: Box<dyn Controller>,
        pacer: Option<Pacer>,
        packet_size: u16,
        peer_max_ack_delay: Duration,
        config: &TransportConfig,
        now: Instant,
    ) -> Self {
        Self {
            controller,
            pacer,
            rtt: RttEstimator::new(config.initial_rtt),
            packet_size,
            packet_threshold: u64::from(config.packet_threshold),
            time_threshold: config.time_threshold,
            persistent_congestion_threshold: config.persistent_congestion_threshold,
            peer_max_ack_delay,
            sent: BTreeMap::new(),
            next_packet: 0,
            in_flight: 0,
            app_limited: false,
            largest_acked: None,
            largest_acked_sent: now,
            last_sent: now,
            first_packet_after_rtt_sample: None,
            loss_time: None,
            loss_detection: None,
            pacing: None,
            pto_count: 0,
            loss_probes: 0,
            lost: 0,
            reductions: 0,
            bursts: 0,
            released: 0,
        }
    }

    /// Builds every datagram congestion control and pacing admit at `now`, one segmented
    /// transmit after another, and returns their packet numbers.
    fn poll_transmit(&mut self, now: Instant) -> Vec<u64> {
        let size = u64::from(self.packet_size);
        let mut packets = Vec::new();
        loop {
            let mut blocked = false;
            let mut datagrams = 0;
            // A datagram is charged to the window and the pacer only once the next is admitted.
            let mut untracked = 0;
            while datagrams < SEGMENTS_PER_TRANSMIT {
                if self.loss_probes == 0 {
                    let window = self.controller.window();
                    let bytes_to_send = size + untracked;
                    if self.in_flight + bytes_to_send > window {
                        blocked = true;
                        break;
                    }
                    if let Some(pacer) = &mut self.pacer
                        && let Some(at) = pacer.delay(
                            self.rtt.get(),
                            bytes_to_send,
                            self.packet_size,
                            window,
                            now,
                        )
                    {
                        self.pacing = Some(at);
                        blocked = true;
                        break;
                    }
                }
                if untracked > 0 {
                    packets.push(self.finish_packet(now));
                }
                self.loss_probes = self.loss_probes.saturating_sub(1);
                untracked = size;
                datagrams += 1;
            }
            if untracked > 0 {
                packets.push(self.finish_packet(now));
            }
            self.app_limited = datagrams == 0 && !blocked;
            if datagrams == 0 {
                break;
            }
            self.controller
                .on_sent(now, datagrams as u64 * size, self.next_packet - 1);
            self.set_loss_detection_timer();
            if blocked {
                break;
            }
        }
        if !packets.is_empty() {
            self.bursts += 1;
            self.released += packets.len() as u64;
        }
        packets
    }

    fn finish_packet(&mut self, now: Instant) -> u64 {
        let packet = self.next_packet;
        self.next_packet += 1;
        self.sent.insert(packet, now);
        self.in_flight += u64::from(self.packet_size);
        self.last_sent = now;
        if let Some(pacer) = &mut self.pacer {
            pacer.on_transmit(self.packet_size);
        }
        packet
    }

    fn on_ack(&mut self, now: Instant, ack: &Ack) {
        let largest_sent = self.sent.get(&ack.largest).copied();
        let new_largest = self.largest_acked.is_none_or(|packet| ack.largest > packet);
        if new_largest {
            self.largest_acked = Some(ack.largest);
            if let Some(sent) = largest_sent {
                self.largest_acked_sent = sent;
            }
        }

        let mut largest_newly_acked = None;
        for &packet in &ack.packets {
            if let Some(sent) = self.sent.remove(&packet) {
                self.in_flight -= u64::from(self.packet_size);
                self.controller.on_ack(
                    now,
                    sent,
                    u64::from(self.packet_size),
                    self.app_limited,
                    &self.rtt,
                );
                largest_newly_acked = Some(packet);
            }
        }
        if largest_newly_acked.is_none() {
            return;
        }
        self.controller
            .on_end_acks(now, self.in_flight, self.app_limited, largest_newly_acked);

        if new_largest && largest_sent.is_some() {
            let ack_delay = ack.delay.min(self.peer_max_ack_delay);
            self.rtt.update(
                ack_delay,
                now.saturating_duration_since(self.largest_acked_sent),
            );
            self.first_packet_after_rtt_sample
                .get_or_insert(self.next_packet);
        }

        self.detect_lost_packets(now, true);
        self.pto_count = 0;
        self.set_loss_detection_timer();
    }

    fn pto(&self) -> Duration {
        self.rtt.pto_base() + self.peer_max_ack_delay
    }

    fn detect_lost_packets(&mut self, now: Instant, due_to_ack: bool) {
        let Some(largest_acked) = self.largest_acked else {
            return;
        };
        let scaled = self.rtt.conservative().as_secs_f64() * f64::from(self.time_threshold);
        let loss_delay = Duration::from_secs_f64(scaled).max(TIMER_GRANULARITY);
        let congestion_period = self.pto() * self.persistent_congestion_threshold;

        let mut lost = Vec::new();
        let mut largest_lost_sent = None;
        let mut persistent_congestion_start: Option<Instant> = None;
        let mut in_persistent_congestion = false;
        let mut previous = None;
        self.loss_time = None;
        for (&packet, &sent) in self.sent.range(..largest_acked) {
            if previous != Some(packet.wrapping_sub(1)) {
                persistent_congestion_start = None;
            }
            let too_old = now.saturating_duration_since(sent) >= loss_delay;
            if too_old || largest_acked >= packet + self.packet_threshold {
                lost.push(packet);
                largest_lost_sent = Some(sent);
                if due_to_ack {
                    match persistent_congestion_start {
                        Some(start) if sent - start > congestion_period => {
                            in_persistent_congestion = true;
                        }
                        None if self
                            .first_packet_after_rtt_sample
                            .is_some_and(|first| first < packet) =>
                        {
                            persistent_congestion_start = Some(sent);
                        }
                        _ => {}
                    }
                }
            } else {
                let next = sent + loss_delay;
                self.loss_time = Some(self.loss_time.map_or(next, |at| at.min(next)));
                persistent_congestion_start = None;
            }
            previous = Some(packet);
        }

        let Some(largest_lost_sent) = largest_lost_sent else {
            return;
        };
        let size = u64::from(self.packet_size);
        for packet in &lost {
            self.sent.remove(packet);
            self.in_flight -= size;
        }
        self.lost += lost.len() as u64;
        let window = self.controller.window();
        self.controller.on_congestion_event(
            now,
            largest_lost_sent,
            in_persistent_congestion,
            lost.len() as u64 * size,
        );
        if self.controller.window() < window {
            self.reductions += 1;
        }
    }

    fn set_loss_detection_timer(&mut self) {
        self.loss_detection = self.loss_time.or_else(|| {
            let backoff = 2u32.pow(self.pto_count.min(16));
            (!self.sent.is_empty()).then(|| self.last_sent + self.pto() * backoff)
        });
    }

    /// Handles whichever of the pacing and loss detection timers is due.
    fn on_timeout(&mut self, now: Instant) {
        if self.pacing.is_some_and(|at| at <= now) {
            self.pacing = None;
        }
        if self.loss_detection.is_none_or(|at| at > now) {
            return;
        }
        if self.loss_time.is_some() {
            self.detect_lost_packets(now, false);
        } else if !self.sent.is_empty() {
            self.loss_probes = 2;
            self.pto_count = self.pto_count.saturating_add(1);
        }
        self.set_loss_detection_timer();
    }

    fn next_timeout(&self) -> Option<Instant> {
        match (self.pacing, self.loss_detection) {
            (Some(pacing), Some(loss)) => Some(pacing.min(loss)),
            (pacing, loss) => pacing.or(loss),
        }
    }
}

/// CUBIC as RFC 9438 section 4 specifies it, counting the window in segments.
#[derive(Clone)]
struct ReferenceCubic {
    segment: f64,
    cwnd: f64,
    ssthresh: f64,
    cwnd_prior: f64,
    w_max: f64,
    w_est: f64,
    k: f64,
    epoch: Option<Instant>,
    recovery_start: Option<Instant>,
}

impl ReferenceCubic {
    const BETA: f64 = 0.7;
    const C: f64 = 0.4;
    const INITIAL_WINDOW: f64 = 10.0;
    const MINIMUM_WINDOW: f64 = 2.0;

    fn new(segment: u16) -> Self {
        Self {
            segment: f64::from(segment),
            cwnd: Self::INITIAL_WINDOW,
            ssthresh: f64::INFINITY,
            cwnd_prior: 0.0,
            w_max: 0.0,
            w_est: 0.0,
            k: 0.0,
            epoch: None,
            recovery_start: None,
        }
    }

    fn w_cubic(&self, t: f64) -> f64 {
        Self::C.mul_add((t - self.k).powi(3), self.w_max)
    }

    fn in_recovery(&self, sent: Instant) -> bool {
        self.recovery_start.is_some_and(|start| sent <= start)
    }
}

impl Controller for ReferenceCubic {
    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if app_limited || self.in_recovery(sent) {
            return;
        }
        let segments_acked = bytes as f64 / self.segment;
        if self.cwnd < self.ssthresh {
            self.cwnd += segments_acked;
            return;
        }
        let epoch = if let Some(epoch) = self.epoch {
            epoch
        } else {
            self.epoch = Some(now);
            self.w_max = self.cwnd;
            self.w_est = self.cwnd;
            self.cwnd_prior = self.cwnd;
            self.k = 0.0;
            now
        };
        let t = now.saturating_duration_since(epoch).as_secs_f64();
        let alpha = if self.w_est >= self.cwnd_prior {
            1.0
        } else {
            3.0 * (1.0 - Self::BETA) / (1.0 + Self::BETA)
        };
        self.w_est += alpha * segments_acked / self.cwnd;
        if self.w_cubic(t) < self.w_est {
            self.cwnd = self.cwnd.max(self.w_est);
        } else {
            let target = self
                .w_cubic(t + rtt.get().as_secs_f64())
                .clamp(self.cwnd, 1.5 * self.cwnd);
            self.cwnd = ((target - self.cwnd) / self.cwnd).mul_add(segments_acked, self.cwnd);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        if self.in_recovery(sent) {
            return;
        }
        self.recovery_start = Some(now);
        self.w_max = if self.cwnd < self.w_max {
            self.cwnd * (1.0 + Self::BETA) / 2.0
        } else {
            self.cwnd
        };
        self.cwnd_prior = self.cwnd;
        self.ssthresh = (self.cwnd * Self::BETA).max(Self::MINIMUM_WINDOW);
        self.cwnd = self.ssthresh;
        self.w_est = self.cwnd;
        self.k = ((self.w_max - self.cwnd).max(0.0) / Self::C).cbrt();
        self.epoch = Some(now);
        if is_persistent_congestion {
            self.cwnd = Self::MINIMUM_WINDOW;
            self.epoch = None;
            self.recovery_start = None;
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.segment = f64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        (self.cwnd * self.segment) as u64
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        (Self::INITIAL_WINDOW * self.segment) as u64
    }
}
