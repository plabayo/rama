use rama::{
    Layer as _, Service,
    http::{
        Request, Response,
        layer::{
            compression::{CompressionLayer, predicate},
            map_response_body::MapResponseBodyLayer,
        },
        service::web::response::IntoResponse,
    },
    layer::ConsumeErrLayer,
    service::service_fn,
};
use std::convert::Infallible;

pub(in crate::cmd::serve::httptest) fn service()
-> impl Service<Request, Output = Response, Error = Infallible> {
    (
        ConsumeErrLayer::trace_as_debug(),
        MapResponseBodyLayer::new_boxed_streaming_body(),
        CompressionLayer::new().with_compress_predicate(predicate::Always::new()),
    )
        .into_layer(service_fn(async || {
            Ok::<_, Infallible>(
                r##"# Ethical principles of hacking

## motivation and limits

- Access to computers - and anything which might teach you something about
  the way the world really works - should be unlimited and total.
  Always yield to the Hands-On Imperative!

- All information should be free.

- Mistrust authority - promote decentralization.

- Hackers should be judged by their acting,
  not bogus criteria such as degrees, age, race, or position.

- You can create art and beauty on a computer.

- Computers can change your life for the better.

- Don't litter other people's data.

- Make public data available, protect private data.

Inspired by Steven Levy's book "Hackers: Heroes of the Computer Revolution",
and contributions by the Chaos Computer Club (CCC).
"##
                .into_response(),
            )
        }))
}
