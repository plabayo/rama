use super::*;
use rama_http::proto::h3::{
    observation::{FieldRepresentation, ObservedFieldRepresentation},
    qpack::encoding::Representation,
};

pub(super) struct QpackRequestSink {
    pub(super) extensions: Extensions,
    pub(super) calls: Arc<AtomicUsize>,
}

impl ExtensionsRef for QpackRequestSink {
    fn extensions(&self) -> &Extensions {
        &self.extensions
    }
}

impl Service<Request<()>> for QpackRequestSink {
    type Output = Request<()>;
    type Error = Infallible;

    async fn serve(&self, request: Request<()>) -> Result<Self::Output, Self::Error> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(request)
    }
}

#[tokio::test]
async fn request_modifier_installs_qpack_choices_and_reports_caller_conflicts() {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CallerPreferences {
        Absent,
        Fields,
        Base,
    }

    // Exercise the actual selector and modifier, with a native sink checking its output.
    for conflict in [
        CallerPreferences::Absent,
        CallerPreferences::Fields,
        CallerPreferences::Base,
    ] {
        let context = h3_emulation_context_with(
            None,
            vec![HeaderOccurrence {
                name: HeaderName::from_static("user-agent"),
                occurrence: 0,
                sensitive: false,
                representation: Some(ObservedFieldRepresentation {
                    representation: FieldRepresentation::LiteralDynamicName,
                    index: Some(27),
                    name_huffman: false,
                    value_huffman: false,
                    never_index: false,
                }),
                value: HeaderValueSource::Profile(b"captured-browser".to_vec().into()),
            }]
            .into(),
        );
        let connection = context
            .selected
            .connection(
                &ConnectionContext::default(),
                context.seed,
                context.connection_key,
            )
            .unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let inner = QpackRequestSink {
            extensions: Extensions::new(),
            calls: calls.clone(),
        };
        inner.extensions().insert(connection);
        inner
            .extensions()
            .insert(TargetHttpVersion(Version::HTTP_3));
        let request = Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .version(Version::HTTP_3)
            .body(())
            .unwrap();
        context.publish(request.extensions());
        if conflict == CallerPreferences::Fields {
            request.extensions().insert(HeaderPreferences::default());
        } else if conflict == CallerPreferences::Base {
            request.extensions().insert(FieldSectionBase::BeforeSection);
        }
        let request = ProfileEmulateHttpRequestModifier::new(inner)
            .serve(request)
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(request.headers()["user-agent"], "captured-browser");
        let differences = &request
            .extensions()
            .get_ref::<ProfilePreservationReport>()
            .unwrap()
            .differences;
        if conflict == CallerPreferences::Absent {
            assert!(differences.is_empty());
            assert_eq!(
                request.extensions().get_ref::<FieldSectionBase>(),
                Some(&FieldSectionBase::FromFieldPreferences)
            );
            let preferences = request.extensions().get_ref::<HeaderPreferences>().unwrap();
            let field = &preferences.headers["user-agent"];
            assert_eq!(
                field.representation,
                Representation::LiteralDynamicNameBeforeBase
            );
            assert_eq!(field.value_huffman, Some(false));
        } else if conflict == CallerPreferences::Fields {
            assert_eq!(
                differences.as_ref(),
                [ProfilePreservationDifference::LoweredProfileItem {
                    item: LoweredProfileItem::CallerQpackFieldPreferences
                }]
            );
            assert!(
                request
                    .extensions()
                    .get_ref::<HeaderPreferences>()
                    .unwrap()
                    .headers
                    .is_empty()
            );
            assert_eq!(
                request.extensions().get_ref::<FieldSectionBase>(),
                Some(&FieldSectionBase::FromFieldPreferences)
            );
        } else {
            assert_eq!(
                differences.as_ref(),
                [ProfilePreservationDifference::LoweredProfileItem {
                    item: LoweredProfileItem::CallerQpackBase
                }]
            );
            assert_eq!(
                request.extensions().get_ref::<FieldSectionBase>(),
                Some(&FieldSectionBase::BeforeSection)
            );
            assert!(request.extensions().contains::<HeaderPreferences>());
        }
    }
}
