//! Time spent in the HTTP/3 datagram demultiplexer's critical sections, which the connection
//! runs under its datagram lock, as the number of registered requests grows.

use rama::{bytes::Bytes, http::core::h3::fuzz::DemuxDriver};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

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
