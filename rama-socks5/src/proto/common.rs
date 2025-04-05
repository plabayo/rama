use std::net::IpAddr;

use super::AddressType;
use bytes::BufMut;
use rama_core::error::OpaqueError;
use rama_net::address::{Authority, Domain, Host};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) fn authority_length(authority: &Authority) -> usize {
    2 + match authority.host() {
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
    Unexpected(OpaqueError),
}

impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::IO(value)
    }
}
impl From<OpaqueError> for ReadError {
    fn from(value: OpaqueError) -> Self {
        Self::Unexpected(value)
    }
}

pub(super) async fn read_authority<R: AsyncRead + Unpin>(
    r: &mut R,
) -> Result<Authority, ReadError> {
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
            let mut raw = Vec::with_capacity(n as usize);
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

pub(super) fn write_authority_to_buf<B: BufMut>(authority: &Authority, buf: &mut B) {
    match authority.host() {
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
    buf.put_u16(authority.port());
}
