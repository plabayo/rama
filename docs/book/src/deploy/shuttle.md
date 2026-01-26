# 🚀 Rama x Shuttle

[![Crates.io](https://img.shields.io/crates/v/shuttle-rama.svg)](https://crates.io/crates/shuttle-rama)
[![Docs.rs](https://img.shields.io/docsrs/shuttle-rama/latest)](https://docs.rs/shuttle-rama/latest/shuttle_rama/index.html)

Shuttle (`https://www.shuttle.dev/`) was a Rust-native cloud development platform that allows you to deploy your app while handling all of the underlying infrastructure. Rama was
one of several officially supported frameworks available in Shuttle’s SDK crate collection.

<div class="book-article-image-center">
<img style="width: 90%" src="../img/shuttle_x_rama.jpg" alt="visual representation of Rama and Shuttle in harmony">
</div>

## What was Shuttle?

Shuttle was designed with a strong focus on developer experience, aimed to make application development and deployment as effortless as possible. Its powerful capabilities simplified resource provisioning. For example, provisioning a database was as easy as using a macro:

```rust
#[shuttle_runtime::main]
async fn main(
    // Automatically provisions a Postgres database
    // and provides an authenticated connection pool
    #[shuttle_shared_db::Postgres] pool: sqlx::PgPool,
) -> Result<impl shuttle_rama::ShuttleService, shuttle_rama::ShuttleError> {
    // Application code
}
```

With Shuttle, you were able to hit the ground running and quickly turn your ideas into real, deployable applications. It enabled rapid prototyping and deployment, helping you bring your vision to life faster than ever.

Sadly it no longer exists. In case you are a company which provides something similar,
do let us know, we would love to help you make rama one of the supported (network) frameworks.
