use rama_error::{BoxError, ErrorContext};

use crate::extensions::ExtensionsMut;

use super::{ServiceMatch, ServiceMatcher};

macro_rules! impl_service_matcher_tuple {
    ($either:ident, $first_variant:ident => $first_ty:ident : $first_var:ident, $($variant:ident => $rest_ty:ident : $rest_var:ident),+ $(,)?) => {
        impl<Input, ModifiedInput, $first_ty, $($rest_ty),+> ServiceMatcher<Input>
            for ($first_ty, $($rest_ty),+)
        where
            Input: Send + ExtensionsMut + 'static,
            ModifiedInput: Send + 'static,
            $first_ty: ServiceMatcher<Input, Error: Into<BoxError>, ModifiedInput = ModifiedInput>,
            $(
                $rest_ty: ServiceMatcher<
                    ModifiedInput,
                    Error: Into<BoxError>,
                    ModifiedInput = ModifiedInput,
                >,
            )+
        {
            type Service = crate::combinators::$either<$first_ty::Service, $($rest_ty::Service),+>;
            type Error = BoxError;
            type ModifiedInput = ModifiedInput;

            async fn match_service(
                &self,
                input: Input,
            ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error> {
                let ($first_var, $($rest_var),+) = self;

                let ServiceMatch { input, service } = $first_var.match_service(input).await.into_box_error()?;
                if let Some(service) = service {
                    return Ok(ServiceMatch {
                        input,
                        service: Some(crate::combinators::$either::$first_variant(service)),
                    });
                }

                $(
                    let ServiceMatch { input, service } = $rest_var.match_service(input).await.into_box_error()?;
                    if let Some(service) = service {
                        return Ok(ServiceMatch {
                            input,
                            service: Some(crate::combinators::$either::$variant(service)),
                        });
                    }
                )+

                Ok(ServiceMatch {
                    input,
                    service: None,
                })
            }

            async fn into_match_service(
                self,
                input: Input,
            ) -> Result<ServiceMatch<Self::ModifiedInput, Self::Service>, Self::Error>
            where
                Input: Send,
            {
                let ($first_var, $($rest_var),+) = self;

                let ServiceMatch { input, service } = $first_var.into_match_service(input).await.into_box_error()?;
                if let Some(service) = service {
                    return Ok(ServiceMatch {
                        input,
                        service: Some(crate::combinators::$either::$first_variant(service)),
                    });
                }

                $(
                    let ServiceMatch { input, service } = $rest_var.into_match_service(input).await.into_box_error()?;
                    if let Some(service) = service {
                        return Ok(ServiceMatch {
                            input,
                            service: Some(crate::combinators::$either::$variant(service)),
                        });
                    }
                )+

                Ok(ServiceMatch {
                    input,
                    service: None,
                })
            }
        }
    };
}

impl_service_matcher_tuple!(Either, A => SM1: sm1, B => SM2: sm2);
impl_service_matcher_tuple!(Either3, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3);
impl_service_matcher_tuple!(Either4, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3, D => SM4: sm4);
impl_service_matcher_tuple!(Either5, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3, D => SM4: sm4, E => SM5: sm5);
impl_service_matcher_tuple!(Either6, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3, D => SM4: sm4, E => SM5: sm5, F => SM6: sm6);
impl_service_matcher_tuple!(Either7, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3, D => SM4: sm4, E => SM5: sm5, F => SM6: sm6, G => SM7: sm7);
impl_service_matcher_tuple!(Either8, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3, D => SM4: sm4, E => SM5: sm5, F => SM6: sm6, G => SM7: sm7, H => SM8: sm8);
impl_service_matcher_tuple!(Either9, A => SM1: sm1, B => SM2: sm2, C => SM3: sm3, D => SM4: sm4, E => SM5: sm5, F => SM6: sm6, G => SM7: sm7, H => SM8: sm8, I => SM9: sm9);
