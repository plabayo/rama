//! Resolve profile, flow and component ownership before a counting transaction.

use super::{
    CanonicalValue, CaptureLevel, CapturedSlotKind, ConnectionContext, FlowKey, HeaderCapture,
    HeaderCapturePolicy, JointCapture, JointCaptureLimits, ProfileDataError, ProfileKey,
    ProfileObservationScope,
};

#[derive(Debug, Clone)]
pub struct ProfileCapture {
    pub profile: ProfileKey,
    pub flow: Option<FlowKey>,
    pub connection: ConnectionContext,
    pub joint: JointCapture,
}

/// One complete tuple and one bucket per observed component. Identity is resolved
/// before storage; stores still verify equal-hash bytes and authorization on load.
#[derive(Debug, Clone)]
pub struct PreparedProfileCapture {
    pub profile: CanonicalValue,
    pub flow: Option<CanonicalValue>,
    pub buckets: Box<[ProfileBucketInput]>,
}

#[derive(Debug, Clone)]
pub struct ProfileBucketInput {
    pub scope: CanonicalValue,
    pub structure: CanonicalValue,
    pub value: CanonicalValue,
}

impl ProfileCapture {
    pub fn prepare(
        &self,
        authorized: bool,
        limits: JointCaptureLimits,
    ) -> Result<PreparedProfileCapture, ProfileDataError> {
        if self.joint.slots.is_empty() {
            return Err(ProfileDataError::Incomplete("empty profile capture"));
        }
        match (self.joint.level, &self.flow) {
            (CaptureLevel::Connection, None) => {}
            (
                CaptureLevel::Request,
                Some(FlowKey::Http {
                    version,
                    connection,
                    ..
                }),
            ) => {
                if connection != &self.connection {
                    return Err(ProfileDataError::Invalid("flow connection context"));
                }
                // Canonicalizing the joint first bounds and validates every leaf.
                self.joint.canonical(limits)?;
                for slot in &self.joint.slots {
                    if slot.kind == CapturedSlotKind::Headers {
                        let policy = HeaderCapturePolicy {
                            fields: limits.value_bytes,
                            bytes: limits.value_bytes,
                            overrides: Box::default(),
                        };
                        if HeaderCapture::from_canonical(&slot.value, &policy)?.version != *version
                        {
                            return Err(ProfileDataError::Invalid("flow header protocol"));
                        }
                    }
                }
            }
            _ => return Err(ProfileDataError::Invalid("capture flow ownership")),
        }
        let value = self.joint.canonical(limits)?;
        let structure = self.joint.structural(limits)?;
        let profile = self.profile.canonical(limits.value_bytes)?;
        let flow = self
            .flow
            .as_ref()
            .map(|flow| flow.canonical(limits.value_bytes))
            .transpose()?;
        let bucket = |value, structure: CanonicalValue| -> Result<_, ProfileDataError> {
            let scope = ProfileObservationScope {
                authorized,
                profile: profile.id,
                flow: flow.as_ref().map(|flow| flow.id),
                connection: self.connection.clone(),
                structure: structure.id,
            }
            .canonical(limits.value_bytes)?;
            Ok(ProfileBucketInput {
                scope,
                structure,
                value,
            })
        };
        let mut buckets = Vec::new();
        buckets.push(bucket(value, structure)?);
        for slot in &self.joint.slots {
            buckets.push(bucket(
                slot.value.clone(),
                slot.structural(limits.value_bytes)?,
            )?);
        }
        Ok(PreparedProfileCapture {
            profile,
            flow,
            buckets: buckets.into(),
        })
    }
}

#[cfg(test)]
mod tests;
