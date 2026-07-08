use super::encoding::{DecodeError, Decodeable, FallibleBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Request,
    Response,
    Data,
    Unknown(u8),
}

// A trait for types that can be messages of a ttrpc frame
pub trait Message {
    const TYPE_ID: MessageType;
}

impl From<MessageType> for u8 {
    fn from(value: MessageType) -> Self {
        match value {
            MessageType::Request => 1,
            MessageType::Response => 2,
            MessageType::Data => 3,
            MessageType::Unknown(ty) => ty,
        }
    }
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Response,
            3 => Self::Data,
            ty => Self::Unknown(ty),
        }
    }
}

#[derive(Clone, Debug)]
pub struct FallibleBytesMessage {
    pub ty: MessageType,
    pub bytes: FallibleBuf,
}

impl FallibleBytesMessage {
    pub fn decode<Msg: Message + Decodeable>(&self) -> Result<Msg, DecodeError> {
        if self.ty != Msg::TYPE_ID {
            let msg = format!(
                "Wrong message type: expected {:?}, found {:?}",
                Msg::TYPE_ID,
                self.ty
            );
            return Err(DecodeError::InvalidInput(msg.into()));
        }
        Msg::decode(self.bytes.clone())
    }
}
