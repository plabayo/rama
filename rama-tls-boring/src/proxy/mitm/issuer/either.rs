use super::{BoringMitmCertIssuer, MitmIssuedCert};

use rama_boring::x509::X509;

macro_rules! impl_boring_cert_issuer_either {
    ($id:ident, $first:ident $(, $param:ident)* $(,)?) => {
        impl<$first, $($param,)*> BoringMitmCertIssuer for rama_core::combinators::$id<$first $(,$param)*>
        where
            $first: BoringMitmCertIssuer,
            $(
                $param: BoringMitmCertIssuer<Error: Into<$first::Error>>,
            )*
        {
            type Error = $first::Error;

            async fn issue_mitm_x509_cert(
                &self,
                original: X509,
            ) -> Result<MitmIssuedCert, Self::Error> {
                match self {
                    rama_core::combinators::$id::$first(issuer) => issuer.issue_mitm_x509_cert(original).await,
                    $(
                        rama_core::combinators::$id::$param(issuer) => issuer.issue_mitm_x509_cert(original).await.map_err(Into::into),
                    )*
                }
            }
        }
    };
}

rama_core::combinators::impl_either!(impl_boring_cert_issuer_either);
