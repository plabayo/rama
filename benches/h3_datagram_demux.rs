//! Time spent in the HTTP/3 datagram demultiplexer's critical sections, which the connection
//! runs under its datagram lock, as the number of registered requests grows.

use rama::{bytes::Bytes, http::core::h3::fuzz::DemuxDriver};

mod bench_alloc;

fn main() {
    divan::main();
}

/// Deliver one datagram to a registered request and take it back out.
#[divan::bench(args = [1, 256, 4096])]
fn deliver_and_take(bencher: divan::Bencher, registered: usize) {
    let mut driver = DemuxDriver::new(registered);
    let payload = Bytes::from_static(&[7; 64]);
    let mut index = 0;
    bencher.bench_local(|| {
        index += 1;
        let taken = driver.deliver_and_take(index, &payload);
        assert!(taken.is_some());
    });
}

/// A datagram that beats its request: held, adopted on registration, taken, released.
#[divan::bench(args = [1, 4096])]
fn adopt_and_take(bencher: divan::Bencher, registered: usize) {
    let mut driver = DemuxDriver::new(registered);
    let payload = Bytes::from_static(&[7; 64]);
    bencher.bench_local(|| {
        let taken = driver.adopt_and_take(&payload);
        assert!(taken.is_some());
    });
}

/// A datagram over the full byte budget: the largest queue gives up its oldest, as many
/// requests' queues fill.
#[divan::bench(args = [1, 256, 4096])]
fn deliver_over_budget(bencher: divan::Bencher, registered: usize) {
    let mut driver = DemuxDriver::saturated(registered, 0);
    let payload = Bytes::from_static(&[7; 64]);
    let mut index = 0;
    bencher.bench_local(|| {
        index += 1;
        driver.deliver_to(index, &payload);
    });
}

/// As [`deliver_over_budget`], beside a growing set of held datagrams.
#[divan::bench(args = [16, 1024])]
fn deliver_over_budget_beside_held(bencher: divan::Bencher, held: usize) {
    let mut driver = DemuxDriver::saturated(256, held);
    let payload = Bytes::from_static(&[7; 64]);
    let mut index = 0;
    bencher.bench_local(|| {
        index += 1;
        driver.deliver_to(index, &payload);
    });
}

/// A datagram over the full budget when only one of many registered requests has a queue, as
/// when idle handles stay registered: finding the largest queue skips the empty ones.
#[divan::bench(args = [1, 256, 4096])]
fn deliver_over_budget_beside_idle_registrations(bencher: divan::Bencher, registered: usize) {
    let mut driver = DemuxDriver::filled(registered, 1, 64 * 1200);
    let payload = Bytes::from_static(&[7; 64]);
    bencher.bench_local(|| {
        driver.deliver_to(0, &payload);
    });
}

/// One datagram of 64 KiB over a full 256 KiB budget of small queued datagrams: one admission
/// evicts dozens of them, oldest of the largest queue first.
#[divan::bench(args = [1, 256, 4096])]
fn one_large_datagram_evicts_many(bencher: divan::Bencher, registered: usize) {
    let large = Bytes::from(vec![7; 64 * 1024]);
    bencher
        .with_inputs(|| DemuxDriver::filled(registered, registered, 256 * 1024))
        .bench_local_refs(|driver| driver.deliver_to(0, &large));
}
