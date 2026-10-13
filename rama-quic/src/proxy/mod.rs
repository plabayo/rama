//! QUIC interception: inspect an association's Initial flight, then forward it untouched or
//! terminate it and relay the established connections.

mod peek;
pub use peek::{
    DEFAULT_QUIC_PEEK_TIMEOUT, InputWithQuicClientHello, NoQuicRejectError,
    PeekQuicClientHelloService,
};

mod relay;
pub use relay::QuicRelay;
