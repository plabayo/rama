use crate::service::ServiceDefinitions;

/// The stubs generated for `input`, as a token string:
/// path separators are spaced out (`super :: EchoRequest`) and so are attributes (`# [doc = ...]`).
fn generate(input: &str) -> String {
    syn::parse_str::<ServiceDefinitions>(input)
        .and_then(ServiceDefinitions::generate)
        .unwrap()
        .to_string()
}

/// The error reported for `input`, which is expected to be rejected.
fn error(input: &str) -> String {
    syn::parse_str::<ServiceDefinitions>(input)
        .and_then(ServiceDefinitions::generate)
        .unwrap_err()
        .to_string()
}

const ECHO: &str = r#"
    package = "rama.examples.echo.v1";
    codec = JsonCodec;

    /// Echoes back what it is given.
    service Echo {
        /// Echo a message once.
        rpc UnaryEcho(EchoRequest) -> EchoResponse;
        rpc ServerStreamingEcho(EchoRequest) -> stream EchoResponse;
        rpc ClientStreamingEcho(stream EchoRequest) -> EchoResponse;
        rpc BidirectionalEcho(stream EchoRequest) -> stream EchoResponse;
    }
"#;

#[test]
fn service_generates_a_client_and_a_server_module() {
    let code = generate(ECHO);

    assert!(code.contains("pub mod echo_client"), "{code}");
    assert!(code.contains("pub struct EchoClient"), "{code}");
    assert!(code.contains("pub mod echo_server"), "{code}");
    assert!(code.contains("pub trait Echo"), "{code}");
    assert!(code.contains("pub struct EchoServer"), "{code}");
}

#[test]
fn method_names_are_snake_cased_and_routed_by_their_written_name() {
    let code = generate(ECHO);

    assert!(code.contains("pub async fn unary_echo"), "{code}");
    assert!(
        code.contains(r#""/rama.examples.echo.v1.Echo/UnaryEcho""#),
        "{code}"
    );
    assert!(code.contains("pub async fn bidirectional_echo"), "{code}");
    assert!(
        code.contains(r#""/rama.examples.echo.v1.Echo/BidirectionalEcho""#),
        "{code}"
    );
}

#[test]
fn streaming_markers_select_the_matching_call_shape() {
    let code = generate(ECHO);

    assert!(
        code.contains("self . inner . unary (req , path , codec)"),
        "{code}"
    );
    assert!(
        code.contains("self . inner . server_streaming (req , path , codec)"),
        "{code}"
    );
    assert!(
        code.contains("self . inner . client_streaming (req , path , codec)"),
        "{code}"
    );
    assert!(
        code.contains("self . inner . streaming (req , path , codec)"),
        "{code}"
    );
    // only the server streaming methods have a stream type to name
    assert!(code.contains("type ServerStreamingEchoStream"), "{code}");
    assert!(code.contains("type BidirectionalEchoStream"), "{code}");
    assert!(!code.contains("type UnaryEchoStream"), "{code}");
}

#[test]
fn types_resolve_from_the_module_invoking_the_macro() {
    let code = generate(
        r#"
        package = "test";
        codec = JsonCodec;
        service Tester {
            rpc Relative(EchoRequest) -> EchoResponse;
        }
        "#,
    );

    assert!(code.contains("super :: EchoRequest"), "{code}");
    assert!(code.contains("super :: EchoResponse"), "{code}");
    assert!(code.contains("super :: JsonCodec :: default ()"), "{code}");
}

#[test]
fn rooted_types_are_left_alone_and_self_is_rewritten() {
    let code = generate(
        r#"
        package = "test";
        codec = ::my_crate::JsonCodec;
        service Tester {
            rpc Rooted(crate::input::Request) -> ::std::string::String;
            rpc Explicit(self::Request) -> self::Response;
        }
        "#,
    );

    assert!(code.contains("crate :: input :: Request"), "{code}");
    assert!(!code.contains("super :: crate"), "{code}");
    assert!(code.contains(":: std :: string :: String"), "{code}");
    assert!(!code.contains("super :: std"), "{code}");
    assert!(
        code.contains(":: my_crate :: JsonCodec :: default ()"),
        "{code}"
    );
    // `self::Foo` names the invoking module, which is `super` from within the generated one
    assert!(code.contains("super :: Request"), "{code}");
    assert!(!code.contains("super :: self"), "{code}");
}

#[test]
fn generic_codecs_are_turbofished_and_their_arguments_qualified() {
    let code = generate(
        r#"
        package = "test";
        codec = SerdeCodec<JsonFormat>;
        service Tester {
            rpc DoThing(Input) -> Output;
        }
        "#,
    );

    assert!(
        code.contains("super :: SerdeCodec :: < super :: JsonFormat > :: default ()"),
        "{code}"
    );
}

#[test]
fn method_codec_overrules_the_service_codec() {
    let code = generate(
        r#"
        package = "test";
        codec = JsonCodec;
        service Tester {
            #[codec(OtherCodec)]
            rpc DoThing(Input) -> Output;
        }
        "#,
    );

    assert!(code.contains("super :: OtherCodec :: default ()"), "{code}");
    assert!(!code.contains("JsonCodec"), "{code}");
}

#[test]
fn client_and_server_generation_can_be_disabled() {
    let server_only = generate(&format!("client = false;\n{ECHO}"));
    assert!(
        !server_only.contains("pub mod echo_client"),
        "{server_only}"
    );
    assert!(server_only.contains("pub mod echo_server"), "{server_only}");

    let client_only = generate(&format!("server = false;\n{ECHO}"));
    assert!(client_only.contains("pub mod echo_client"), "{client_only}");
    assert!(
        !client_only.contains("pub mod echo_server"),
        "{client_only}"
    );
}

#[test]
fn doc_comments_and_deprecation_carry_over_to_the_stubs() {
    let code = generate(ECHO);
    assert!(
        code.contains(r#"# [doc = " Echoes back what it is given."]"#),
        "{code}"
    );
    assert!(
        code.contains(r#"# [doc = " Echo a message once."]"#),
        "{code}"
    );
    assert!(!code.contains("# [deprecated]"), "{code}");

    let code = generate(
        r#"
        package = "test";
        codec = JsonCodec;
        service Tester {
            #[deprecated]
            rpc DoThing(Input) -> Output;
        }
        "#,
    );
    assert!(code.contains("# [deprecated]"), "{code}");
}

#[test]
fn several_services_can_be_defined_at_once() {
    let code = generate(
        r#"
        package = "test";
        codec = JsonCodec;
        service First {
            rpc DoThing(Input) -> Output;
        }
        service Second {
            rpc DoThing(Input) -> Output;
        }
        "#,
    );

    assert!(code.contains("pub mod first_client"), "{code}");
    assert!(code.contains("pub mod second_client"), "{code}");
    // both live in one module, named after the services it wraps
    assert!(code.contains("mod __rama_grpc_first_second"), "{code}");
}

#[test]
fn a_definition_without_a_package_is_rejected() {
    assert!(
        error("codec = JsonCodec; service Tester { rpc DoThing(Input) -> Output; }")
            .contains("missing `package"),
    );
}

#[test]
fn a_method_without_any_codec_is_rejected() {
    assert!(
        error(r#"package = "test"; service Tester { rpc DoThing(Input) -> Output; }"#)
            .contains("no codec defined for this method"),
    );
}

#[test]
fn an_empty_definition_is_rejected() {
    assert!(error(r#"package = "test";"#).contains("expected at least one `service"));
    assert!(
        error(r#"package = "test"; codec = JsonCodec; service Tester {}"#)
            .contains("expected at least one `rpc"),
    );
}

#[test]
fn unknown_settings_and_attributes_are_rejected() {
    assert!(error(r#"packages = "test";"#).contains("expected"));
    assert!(error(r#"package = "test"; package = "other";"#).contains("duplicate setting"));
    assert!(
        error(r#"package = "test"; codec = JsonCodec; service Tester { #[what] rpc A(B) -> C; }"#)
            .contains("unsupported attribute"),
    );
    assert!(
        error(r#"package = "test"; codec = JsonCodec; #[deprecated] service Tester { rpc A(B) -> C; }"#)
            .contains("only doc comments are supported here"),
    );
}
