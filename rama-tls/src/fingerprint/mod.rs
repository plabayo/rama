//! fingerprint implementations for the network surface

mod ja4;

pub use ja4::{Ja4, Ja4ComputeError, Ja4S};

mod peet;

pub use peet::{PeetComputeError, PeetPrint};

mod ja3;

pub use ja3::{Ja3, Ja3ComputeError};

mod ja3s;
pub use ja3s::{Ja3S, Ja3SComputeError};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{
        parse_client_hello_handshake,
        test_support::{hello_for, record},
    };

    // JA4 marks a domain destination by the presence of extension 0x0000, whatever it carries.
    #[test]
    fn an_ip_literal_sni_fingerprints_like_the_same_hello_with_a_dns_name() {
        let parse = |name| parse_client_hello_handshake(&record(&hello_for(name, 0))).unwrap();
        let (domain, ip) = (parse("example.com"), parse("10.20.30.40"));
        let ja4 = Ja4::compute_from_client_hello(&ip).unwrap().to_string();
        assert_eq!(&ja4[3..4], "d", "{ja4}");
        assert_eq!(
            ja4,
            Ja4::compute_from_client_hello(&domain).unwrap().to_string()
        );
        assert_eq!(
            format!("{:x}", Ja3::compute_from_client_hello(&ip).unwrap()),
            format!("{:x}", Ja3::compute_from_client_hello(&domain).unwrap())
        );
        assert_eq!(
            PeetPrint::compute_from_client_hello(&ip)
                .unwrap()
                .to_string(),
            PeetPrint::compute_from_client_hello(&domain)
                .unwrap()
                .to_string()
        );
    }
}
