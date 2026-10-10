//! Exercise the collection worker and its production PostgreSQL adapter.

#[path = "../src/cmd/serve/fp"]
mod fp {
    mod collection;
    mod storage {
        mod counted;
        mod issuer;
        mod migrations;
        mod postgres;
        mod worker;
    }
}
