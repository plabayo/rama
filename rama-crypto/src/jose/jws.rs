use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use rama_core::error::{ErrorContext as _, OpaqueError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
/// When used with serde this will serialize to null
pub struct Empty;

#[derive(Default)]
/// [`JWSBuilder`] should be used when manually creating a [`JWS`]
pub struct JWSBuilder<U = ()> {
    protected_header: String,
    unprotected_header: Option<U>,
    payload: String,
}

impl<U: std::fmt::Debug> std::fmt::Debug for JWSBuilder<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JWS")
            .field("protected_header", &self.protected_header)
            .field("unprotected_header", &self.unprotected_header)
            .field("payload", &self.payload)
            .finish()
    }
}

impl<U: PartialEq> PartialEq for JWSBuilder<U> {
    fn eq(&self, other: &Self) -> bool {
        self.protected_header == other.protected_header
            && self.unprotected_header == other.unprotected_header
            && self.payload == other.payload
    }
}

impl<U: Eq> Eq for JWSBuilder<U> {}

impl JWSBuilder<()> {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<U> JWSBuilder<U> {
    pub fn with_payload<T: AsRef<[u8]>>(mut self, payload: T) -> Self {
        let payload = BASE64_URL_SAFE_NO_PAD.encode(payload);
        self.payload = payload;
        self
    }

    pub fn with_protected_header<T: Serialize>(
        mut self,
        mut header: T,
        signer: &impl Signer<T, U>,
    ) -> Self {
        signer.set_protected_header(&mut header);
        let header = serde_json::to_vec(&header).expect("Failed to serialize JWS Protected Header");
        let header = BASE64_URL_SAFE_NO_PAD.encode(header);
        self.protected_header = header;
        self
    }

    pub fn with_unprotected_header<T: Serialize, X>(
        self,
        mut header: T,
        signer: &impl Signer<X, T>,
    ) -> JWSBuilder<T> {
        signer.set_unprotected_header(&mut header);
        JWSBuilder {
            payload: self.payload,
            protected_header: self.protected_header,
            unprotected_header: Some(header),
        }
    }

    fn signed_data(&self) -> String {
        format!("{}.{}", self.protected_header, self.payload)
    }
}

impl JWSBuilder<()> {
    /// Generate compact serialization of this [`JWS`]
    ///
    /// This only available if there is no unprotected header set
    pub fn builder_compact<P>(
        &self,
        signer: &impl Signer<P, ()>,
    ) -> Result<JWSCompact, OpaqueError> {
        let signing_input = self.signed_data();

        let signature = signer.sign(&self.signed_data())?;
        let signature = BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref());

        Ok(JWSCompact(format!("{signing_input}.{signature}")))
    }
}

impl<U> JWSBuilder<U> {
    /// Build the final [`JWS`]
    pub fn build<P>(self, signer: &impl Signer<P, U>) -> Result<JWS<U>, OpaqueError> {
        let signature = signer.sign(&self.signed_data())?;
        let signature = BASE64_URL_SAFE_NO_PAD.encode(signature.as_ref());

        Ok(JWS {
            protected: self.protected_header,
            header: self.unprotected_header,
            payload: self.payload,
            signature,
        })
    }
}

/// [`Signer`] implements all methods which are needed to sign our JWS requests,
/// and add the needed info to our JOSE headers (JOSE headers = protected + unprotected headers)
pub trait Signer<P, U> {
    type Signature: AsRef<[u8]>;

    /// Modify protected headers to included info about algorithm used
    ///
    /// Because we want everything fully typed the type `P` should be
    /// specified by the implementer or implement a trait to provide
    /// access to the needed header keys
    fn set_protected_header(&self, _header: &mut P) {}

    /// Modify unprotected headers to included info about algorithm used
    ///
    /// Because we want everything fully typed the type `U` should be
    /// specified by the implementer or implement a trait to provide
    /// access to the needed header keys
    fn set_unprotected_header(&self, _header: &mut U) {}

    fn sign(&self, data: &str) -> Result<Self::Signature, OpaqueError>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JWSCompact(String);

#[derive(Serialize, Deserialize)]
pub struct JWS<U> {
    #[serde(skip_serializing_if = "String::is_empty")]
    protected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<U>,
    #[serde(skip_serializing_if = "String::is_empty")]
    payload: String,
    signature: String,
}

impl JWS<()> {
    pub fn builder() -> JWSBuilder<()> {
        JWSBuilder::new()
    }

    pub fn as_compact(&self) -> String {
        format!("{}.{}.{}", self.protected, self.payload, self.signature)
    }
}

impl<U> JWS<U> {
    pub fn decoded(&self) -> Result<DecodedJWS<&U>, OpaqueError> {
        self.try_into()
    }

    pub fn into_decoded(self) -> Result<DecodedJWS<U>, OpaqueError> {
        self.try_into()
    }

    pub fn signed_data(&self) -> String {
        format!("{}.{}", self.protected, self.payload)
    }
}

impl<U> TryFrom<JWS<U>> for DecodedJWS<U> {
    type Error = OpaqueError;
    fn try_from(value: JWS<U>) -> Result<Self, Self::Error> {
        Ok(DecodedJWS {
            signed_data: value.signed_data(),
            signature: value.signature,
            header: value.header,
            payload: BASE64_URL_SAFE_NO_PAD
                .decode(&value.payload)
                .context("decode payload")?,
            protected: BASE64_URL_SAFE_NO_PAD
                .decode(&value.protected)
                .context("decode protected header")?,
        })
    }
}

impl<'a, U> TryFrom<&'a JWS<U>> for DecodedJWS<&'a U> {
    type Error = OpaqueError;

    fn try_from(value: &'a JWS<U>) -> Result<Self, Self::Error> {
        Ok(DecodedJWS {
            signed_data: value.signed_data(),
            signature: value.signature.clone(),
            header: value.header.as_ref(),
            payload: BASE64_URL_SAFE_NO_PAD
                .decode(&value.payload)
                .context("decode payload")?,
            protected: BASE64_URL_SAFE_NO_PAD
                .decode(&value.protected)
                .context("decode protected header")?,
        })
    }
}

#[derive(Debug, PartialEq, Deserialize)]
#[serde(try_from = "JWS<U>")]
pub struct DecodedJWS<U> {
    // We store signed data from [`JWS`] so we dont have to recalculate it, but technically
    // we this could be skipped
    signed_data: String,
    signature: String,
    protected: Vec<u8>,
    header: Option<U>,
    payload: Vec<u8>,
}

impl<U> DecodedJWS<U> {
    pub fn protected<'de, 'a: 'de, T: Deserialize<'de>>(
        &'a self,
    ) -> Result<Option<T>, OpaqueError> {
        if self.protected.is_empty() {
            Ok(None)
        } else {
            Ok(Some(
                serde_json::from_slice(&self.protected).context("Deserialize protected headers")?,
            ))
        }
    }

    pub fn protected_raw(&self) -> &[u8] {
        &self.protected
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn header(&self) -> Option<&U> {
        self.header.as_ref()
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn signed_data(&self) -> &str {
        &self.signed_data
    }

    pub fn verify(&self, verifier: &impl Verifier<U>) -> Result<(), OpaqueError> {
        verifier.verify(self)
    }
}

impl<U: std::fmt::Debug> std::fmt::Debug for JWS<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JWS")
            .field("protected", &self.protected)
            .field("header", &self.header)
            .field("payload", &self.payload)
            .field("signature", &self.signature)
            .finish()
    }
}

pub trait Verifier<U> {
    fn verify(&self, decoded_jws: &DecodedJWS<U>) -> Result<(), OpaqueError>;
}

#[cfg(test)]
mod tests {
    use tokio_test::assert_err;

    use super::*;

    #[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct AcmeProtected<'a> {
        alg: Option<&'a str>,
        nonce: &'a str,
    }

    #[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Random<'a> {
        data: &'a str,
    }

    struct DummyKey;

    impl<U> Signer<AcmeProtected<'_>, U> for DummyKey {
        type Signature = Vec<u8>;

        fn set_protected_header(&self, header: &mut AcmeProtected) {
            header.alg = Some("test_algo");
        }

        fn sign(&self, data: &str) -> Result<Self::Signature, OpaqueError> {
            let mut out = data.as_bytes().to_vec();
            out.push(33);
            Ok(out)
        }
    }

    impl<U> Verifier<U> for DummyKey {
        fn verify(&self, decoded_jws: &DecodedJWS<U>) -> Result<(), OpaqueError> {
            let original = decoded_jws.signed_data().as_bytes();

            let signature = BASE64_URL_SAFE_NO_PAD
                .decode(decoded_jws.signature())
                .context("decode signature")?;

            if original.len() + 1 != signature.len() {
                Err(OpaqueError::from_display(
                    "signature should add single u8 to original slice",
                ))
            } else if original[..] != signature[..original.len()] {
                Err(OpaqueError::from_display("original data should be equal"))
            } else if signature[signature.len() - 1] != 33 {
                Err(OpaqueError::from_display(
                    "last element in signature should be 33",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn can_serialize_and_deserialize() {
        let nonce = "random".to_owned();
        let protected = AcmeProtected {
            nonce: &nonce,
            alg: None,
        };

        let something = "something_random".to_owned();
        let header = Random { data: &something };

        let payload = "something".to_owned();

        let signer = DummyKey;

        let jws = JWSBuilder::new()
            .with_payload(payload.clone())
            .with_protected_header(protected.clone(), &signer)
            .with_unprotected_header(header.clone(), &signer)
            .build(&signer)
            .unwrap();

        let encoded = serde_json::to_string(&jws).unwrap();
        let jws_received = serde_json::from_str::<JWS<Random>>(&encoded).unwrap();

        // This will be set by our signer
        let mut expected_protected = protected.clone();
        expected_protected.alg = Some("test_algo");

        assert_eq!(jws.protected, jws_received.protected);
        assert_eq!(jws.header, jws_received.header);
        assert_eq!(jws.payload, jws_received.payload);

        let decoded_jws = jws_received.decoded().unwrap();

        let received_payload = String::from_utf8(decoded_jws.payload().to_vec()).unwrap();
        let received_protected = decoded_jws.protected::<AcmeProtected>().unwrap().unwrap();
        let received_header = decoded_jws.header().unwrap();

        assert_eq!(payload, received_payload);
        assert_eq!(expected_protected, received_protected);
        assert_eq!(&&header, received_header);

        // Shortcut to skip creating received jws should be the same, but this skips verify the
        let short_decoded = serde_json::from_str::<DecodedJWS<Random>>(&encoded).unwrap();

        let short_payload = String::from_utf8(short_decoded.payload().to_vec()).unwrap();
        let short_protected = short_decoded.protected::<AcmeProtected>().unwrap().unwrap();
        let short_header = short_decoded.header().unwrap();

        assert_eq!(payload, short_payload);
        assert_eq!(expected_protected, short_protected);
        assert_eq!(&header, short_header);

        decoded_jws.verify(&signer).unwrap();
    }

    #[test]
    fn empty_vs_none() {
        let signer = DummyKey;

        let protected = AcmeProtected {
            nonce: "somthing",
            alg: None,
        };

        let jws = JWS::builder()
            .with_protected_header(protected.clone(), &signer)
            .build(&signer)
            .unwrap();

        assert_eq!(jws.payload, "".to_owned());

        let jws = JWS::builder()
            .with_protected_header(protected, &signer)
            .with_payload(serde_json::to_vec(&Empty).unwrap())
            .build(&signer)
            .unwrap();
        assert_eq!(jws.payload, "bnVsbA".to_owned());
    }

    #[test]
    fn tampering_should_be_detected() {
        // This is a very basic signer without and real logic behind it,
        // this test is just here to make sure we detected changes
        let nonce = "random".to_owned();
        let protected = AcmeProtected {
            nonce: &nonce,
            alg: None,
        };

        let payload = "something".to_owned();

        let signer = DummyKey;

        let jws = JWSBuilder::new()
            .with_payload(payload.clone())
            .with_protected_header(protected.clone(), &signer)
            .build(&signer)
            .unwrap();

        let encoded = serde_json::to_string(&jws).unwrap();

        // Something should fail in this part
        let server = move |encoded: String| {
            let received = serde_json::from_str::<JWS<Random>>(&encoded).context("decode jws")?;
            let decoded = received.decoded()?;
            decoded.verify(&signer)?;
            Ok::<_, OpaqueError>(())
        };

        println!("len: {}", encoded.len());
        for i in 0..encoded.len() - 1 {
            let mut encoded: String = encoded.clone();
            encoded.insert(i, 't');
            assert_err!(server(encoded), "failed at {i}");
        }
    }
}
