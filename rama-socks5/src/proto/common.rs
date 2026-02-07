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
    2 + match &authority.host {
        Host::Name(domain) => 1 + domain.len(),
        Host::Address(ip_addr) => match ip_addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        },
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
            Domain::try_from(raw)?.into()
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
            Domain::try_from(raw)?.into()
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
pub(super) fn write_authority_to_buf<B: BufMut>(authority: &HostWithPort, buf: &mut B) {
    match &authority.host {
        Host::Name(domain) => {
            buf.put_u8(AddressType::DomainName.into());
            debug_assert!(domain.len() <= 255);
            buf.put_u8(domain.len() as u8);
            buf.put_slice(domain.as_str().as_bytes());
        }
        Host::Address(ip_addr) => match ip_addr {
            IpAddr::V4(addr) => {
                buf.put_u8(AddressType::IpV4.into());
                buf.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                buf.put_u8(AddressType::IpV6.into());
                buf.put_slice(&addr.octets());
            }
        },
    }
    buf.put_u16(authority.port);
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
                write_authority_to_buf(&self.0, &mut v);
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
                write_authority_to_buf(&self.0, &mut v);
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
}
