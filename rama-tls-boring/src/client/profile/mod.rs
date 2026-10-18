//! UA adapters above the native TLS connector.
//!
//! Wire compilation produces ordinary TLS configuration extensions. Register the
//! connection compiler with the common UA connect modifier around the native TLS
//! connector; native transport and handshake code never inspect counted profiles.

pub mod compiler;
pub mod wire;

#[cfg(test)]
mod tests;
