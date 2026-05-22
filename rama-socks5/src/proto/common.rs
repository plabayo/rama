use super::AddressType;
use byteorder::{BigEndian, ReadBytesExt};
use rama_core::bytes::BufMut;
use rama_core::error::BoxError;
use rama_net::address::{Domain, Host, HostWithPort};
use std::{io::Read, net::IpAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Compute the length of an authority,
/// used in the context of buffer allocation
/// in function of writing a socks5 protocol element.
pub(super) fn authority_length(authority: &HostWithPort) -> usize {
    // Same dispatch order as `write_authority_to_buf`: IP first, then
    // Domain (with `Uninterpreted` bridging). Non-promotable hosts
    // (sub-delim reg-name, IPvFuture) fail at write time — we count
    // them as `1 + 0` so the caller's buffer is large enough for the
    // header byte the writer would emit before erroring.
    2 + if let Ok(ip) = authority.host.try_as_ip() {
        match ip {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        }
    } else if let Ok(domain) = authority.host.try_as_domain() {
        1 + domain.len()
    } else {
        1
    }
}

#[derive(Debug)]
pub(super) enum ReadError {
    IO(std::io::Error),
    UnexpectedByte { pos: usize, byte: u8 },
    Unexpected(BoxError),
}

impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}
impl From<BoxError> for ReadError {
    fn from(value: BoxError) -> Self {
        Self::Unexpected(value)
    }
}

/// Read the authority from a Socks5 protocol element.
pub(super) async fn read_authority<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<HostWithPort, ReadError> {
    let address_type: AddressType = r.read_u8().await?.into();
    let host: Host = match address_type {
        AddressType::IpV4 => {
            let mut array = [0u8; 4];
            r.read_exact(&mut array).await?;
            IpAddr::from(array).into()
        }
        AddressType::DomainName => {
            let n = r.read_u8().await?;
            if n == 0 {
                return Err(ReadError::UnexpectedByte { pos: 4, byte: n });
            }
            let mut raw = vec![0u8; n as usize];
            r.read_exact(raw.as_mut_slice()).await?;
            Domain::try_from(raw)
                .map_err(rama_core::error::ErrorExt::into_box_error)?
                .into()
        }
        AddressType::IpV6 => {
            let mut array = [0u8; 16];
            r.read_exact(&mut array).await?;
            IpAddr::from(array).into()
        }
        AddressType::Unknown(b) => {
            return Err(ReadError::UnexpectedByte { pos: 3, byte: b });
        }
    };
    let port = r.read_u16().await?;

    Ok((host, port).into())
}

/// Read the authority from a Socks5 protocol element.
pub(super) fn read_authority_sync<R: Read>(r: &mut R) -> Result<HostWithPort, ReadError> {
    let address_type: AddressType = r.read_u8()?.into();
    let host: Host = match address_type {
        AddressType::IpV4 => {
            let mut array = [0u8; 4];
            r.read_exact(&mut array)?;
            IpAddr::from(array).into()
        }
        AddressType::DomainName => {
            let n = r.read_u8()?;
            if n == 0 {
                return Err(ReadError::UnexpectedByte { pos: 4, byte: n });
            }
            let mut raw = vec![0u8; n as usize];
            r.read_exact(raw.as_mut_slice())?;
            Domain::try_from(raw)
                .map_err(rama_core::error::ErrorExt::into_box_error)?
                .into()
        }
        AddressType::IpV6 => {
            let mut array = [0u8; 16];
            r.read_exact(&mut array)?;
            IpAddr::from(array).into()
        }
        AddressType::Unknown(b) => {
            return Err(ReadError::UnexpectedByte { pos: 3, byte: b });
        }
    };
    let port = r.read_u16::<BigEndian>()?;

    Ok((host, port).into())
}

/// Write the authority into the (usually pre-allocated) buffer.
///
/// Tries [`Host::try_as_ip`] first (cheapest — no allocation), then
/// [`Host::try_as_domain`] (allocates only for the `Uninterpreted`
/// bridge). Errors with `io::ErrorKind::InvalidInput` for hosts that
/// promote to neither — SOCKS5 has no representation for sub-delim
/// reg-names, IPvFuture literals, or empty hosts.
pub(super) fn write_authority_to_buf<B: BufMut>(
    authority: &HostWithPort,
    buf: &mut B,
) -> Result<(), std::io::Error> {
    if let Ok(ip) = authority.host.try_as_ip() {
        match ip {
            IpAddr::V4(addr) => {
                buf.put_u8(AddressType::IpV4.into());
                buf.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.put_u8(AddressType::IpV6.into());
                buf.put_slice(&addr.octets());
            }
        }
    } else if let Ok(domain) = authority.host.try_as_domain() {
        let bytes = domain.as_str().as_bytes();
        if bytes.len() > 255 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "SOCKS5 DomainName is u8-length-prefixed; domain exceeds 255 bytes",
            ));
        }
        buf.put_u8(AddressType::DomainName.into());
        buf.put_u8(bytes.len() as u8);
        buf.put_slice(bytes);
    } else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "SOCKS5 cannot encode host: not promotable to Domain or IpAddr",
        ));
    }
    buf.put_u16(authority.port);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::proto::{test_write_read_eq, test_write_read_sync_eq};
    use rama_net::address::Host;
    use tokio::io::{AsyncWrite, AsyncWriteExt};

    use super::*;

    #[test]
    fn test_authority_length() {
        for (authority, expected_length) in [
            (HostWithPort::local_ipv4(1248), 4 + 2),
            (HostWithPort::local_ipv6(42), 16 + 2),
            (HostWithPort::new(Host::EXAMPLE_NAME, 1), 1 + 11 + 2),
        ] {
            let length = authority_length(&authority);
            assert_eq!(expected_length, length, "authority: {authority}");
        }
    }

    #[tokio::test]
    async fn test_authority_write_read_eq() {
        #[derive(Debug, PartialEq, Eq)]
        struct SocksAuthority(HostWithPort);

        impl SocksAuthority {
            async fn read_from<R>(r: &mut R) -> Result<Self, ReadError>
            where
                R: AsyncRead + Unpin,
            {
                let authority = read_authority(r).await?;
                Ok(Self(authority))
            }

            async fn write_to<W>(&self, w: &mut W) -> Result<(), std::io::Error>
            where
                W: AsyncWrite + Unpin,
            {
                let mut v = Vec::new();
                write_authority_to_buf(&self.0, &mut v)?;
                w.write_all(&v).await
            }
        }

        test_write_read_eq!(SocksAuthority(HostWithPort::local_ipv4(1)), SocksAuthority);
        test_write_read_eq!(SocksAuthority(HostWithPort::local_ipv6(42)), SocksAuthority);
        test_write_read_eq!(
            SocksAuthority(HostWithPort::example_domain_with_port(1450)),
            SocksAuthority
        );
    }

    #[test]
    fn test_authority_write_read_sync_eq() {
        #[derive(Debug, PartialEq, Eq)]
        struct SocksAuthority(HostWithPort);

        impl SocksAuthority {
            fn read_from_sync<R>(r: &mut R) -> Result<Self, ReadError>
            where
                R: Read,
            {
                let authority = read_authority_sync(r)?;
                Ok(Self(authority))
            }

            fn write_to_sync<W>(&self, w: &mut W) -> Result<(), std::io::Error>
            where
                W: Write,
            {
                let mut v = Vec::new();
                write_authority_to_buf(&self.0, &mut v)?;
                w.write_all(&v)
            }
        }

        test_write_read_sync_eq!(SocksAuthority(HostWithPort::local_ipv4(1)), SocksAuthority);
        test_write_read_sync_eq!(SocksAuthority(HostWithPort::local_ipv6(42)), SocksAuthority);
        test_write_read_sync_eq!(
            SocksAuthority(HostWithPort::example_domain_with_port(1450)),
            SocksAuthority
        );
    }

    // ---- Uninterpreted host promotion fallback (audit M3 / C13) ----------
    //
    // The wire writer was retrofitted to try `Domain::try_from(host)` and
    // emit the canonical ACE form rather than the raw pct-encoded bytes —
    // a pct-encoded reg-name reaches the SOCKS5 server as a normal
    // DomainName, not as bytes the server has no chance of resolving.

    /// Build a `Host::Uninterpreted(_)` via the URI parser — the only
    /// public path for constructing this variant from a cross-crate
    /// test (`UninterpretedHost::from_validated_bytes` is crate-private
    /// to `rama-net`).
    fn parse_uninterpreted_host(uri_input: &str) -> Host {
        let uri = rama_net::uri::Uri::parse(uri_input).expect("valid URI");
        uri.host().expect("authority present").into_owned()
    }

    #[test]
    fn socks5_write_authority_promotes_pct_encoded_reg_name_to_domain() {
        // `exa%6Dple.com` (Uninterpreted) → after `Domain::try_from`
        // pct-decode → `example.com` on the wire.
        let host = parse_uninterpreted_host("http://exa%6Dple.com/");
        assert!(matches!(host, Host::Uninterpreted(_)));
        let auth = HostWithPort::new(host, 443);
        let mut buf = Vec::new();
        write_authority_to_buf(&auth, &mut buf).unwrap();
        // First byte is the DomainName address-type tag, second is the
        // length-prefix, then the bytes. Recovered bytes must be the
        // canonical `example.com`, not the pct-encoded source.
        assert_eq!(buf[0], u8::from(super::AddressType::DomainName));
        assert_eq!(buf[1] as usize, b"example.com".len());
        assert_eq!(&buf[2..2 + b"example.com".len()], b"example.com");
    }

    #[test]
    fn socks5_write_authority_rejects_subdelim_host_unpromotable() {
        // Sub-delim reg-name doesn't promote to a Domain *or* IpAddr —
        // SOCKS5 has no representation for it. Encoder errors rather
        // than emitting raw bytes the wire-level grammar can't carry.
        let host = parse_uninterpreted_host("http://tag,with,commas/");
        assert!(matches!(host, Host::Uninterpreted(_)));
        let auth = HostWithPort::new(host, 8080);
        let mut buf = Vec::new();
        let err = write_authority_to_buf(&auth, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn socks5_write_authority_empty_uninterpreted_host_errors() {
        // `file:///path` surfaces `Host::Uninterpreted(b"")` from the URI
        // parser — SOCKS5 has no representation for an empty host, so
        // the encoder must refuse rather than emit a zero-length
        // DomainName (which the reader correctly rejects).
        let host = rama_net::uri::Uri::parse("file:///tmp/socket")
            .unwrap()
            .host()
            .unwrap()
            .into_owned();
        let auth = HostWithPort::new(host, 80);
        let mut buf = Vec::new();
        let err = write_authority_to_buf(&auth, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
}
