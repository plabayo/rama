//! Persistent bucket identity includes authorization and observed connection context.

use serde::{Deserialize, Serialize};

use crate::profile::{
    format::canonical::{
        CanonicalReader, CanonicalValue, CanonicalWriter, ProfileDataError, SCOPE_DOMAIN, ValueId,
    },
    model::identity::ConnectionContext,
};

/// References are content identities, never database surrogate IDs. The owning
/// store resolves and verifies their canonical bytes before admitting a bucket.
/// A missing flow identifies connection-level observations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileObservationScope {
    pub authorized: bool,
    pub profile: ValueId,
    pub flow: Option<ValueId>,
    pub connection: ConnectionContext,
    pub structure: ValueId,
}

impl ProfileObservationScope {
    pub fn canonical(&self, maximum_bytes: usize) -> Result<CanonicalValue, ProfileDataError> {
        let mut writer = CanonicalWriter::new(SCOPE_DOMAIN, maximum_bytes)?;
        writer.u8(u8::from(self.authorized))?;
        writer.bytes(&self.profile.0)?;
        match self.flow {
            None => writer.u8(0)?,
            Some(flow) => {
                writer.u8(1)?;
                writer.bytes(&flow.0)?;
            }
        }
        self.connection.encode(&mut writer)?;
        writer.bytes(&self.structure.0)?;
        Ok(writer.finish())
    }

    pub fn from_canonical(
        value: &CanonicalValue,
        maximum_bytes: usize,
    ) -> Result<Self, ProfileDataError> {
        value.verify(SCOPE_DOMAIN, maximum_bytes)?;
        let mut reader = CanonicalReader::new(&value.bytes, SCOPE_DOMAIN)?;
        let authorized = match reader.u8()? {
            0 => false,
            1 => true,
            _ => return Err(ProfileDataError::Invalid("scope authorization tag")),
        };
        let profile = read_id(&mut reader)?;
        let flow = match reader.u8()? {
            0 => None,
            1 => Some(read_id(&mut reader)?),
            _ => return Err(ProfileDataError::Invalid("scope flow presence")),
        };
        let connection = ConnectionContext::decode(&mut reader)?;
        let structure = read_id(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            authorized,
            profile,
            flow,
            connection,
            structure,
        })
    }
}

fn read_id(reader: &mut CanonicalReader<'_>) -> Result<ValueId, ProfileDataError> {
    let bytes = reader.bytes(32)?;
    Ok(ValueId(bytes.try_into().map_err(|_error| {
        ProfileDataError::Invalid("scope identity length")
    })?))
}

#[cfg(test)]
mod tests;
