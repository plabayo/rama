# 🚫 Errors

> The greatest mistake is to imagine that we never err.
> — *Thomas Carlyle*.

Errors in Rust are often discussed through two lenses:

* **`Result<T, E>`**: A control flow type representing success (`Ok`) or failure (`Err`).
* **`std::error::Error`**: A trait for values that provide a description and an optional source (cause) chain.

A common point of confusion is that `E` in a `Result` is not required to implement the `Error` trait. In web services, for instance, a middleware might return `Result<Response, Response>`, where the `Err` variant is simply an early 403 Forbidden response—not a "failure" in the semantic sense.

In Rama, we aim for clarity: **If it is an error, it should behave like one.** This is particularly important for generic middleware that wraps an unknown service `S`. If the middleware fails, it needs a consistent way to report that failure, even if it cannot construct the specific error type used by `S`.

## Type Erasure with `BoxError`

When the specific concrete type of an error matters less than the fact that a failure occurred, Rama uses **`BoxError`**.

```rust
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;
```

This is a type-erased trait object used at abstraction boundaries. While you can *downcast* a `BoxError` to check for a specific type, keep in mind that standard downcasting only inspects the top-level wrapper, not the entire cause chain.

## Error Extension (`ErrorExt`)

The [`ErrorExt`] trait provides a powerful set of methods to enrich errors. It is implemented for any type that can be converted into a `BoxError`.

The primary goal of `ErrorExt` is to add **context** and **diagnostics** without losing the original error.

### Structured Context

Rama supports a "logfmt" style of context. When you add context, it is rendered as key-value pairs (or bare values), which are automatically quoted and escaped for log compatibility.

* **`context(value)`**: Adds a bare value to the error.
* **`context_field(key, value)`**: Adds a keyed field (e.g., `path="/tmp/logs"`).
* **Lazy Variants**: `with_context` and `with_context_field` allow you to provide a closure, ensuring the context is only computed if an error actually occurs.

### Backtraces

The `.backtrace()` method captures a stack trace at the moment of the call.

* **Standard Display (`{}`)**: Prints the error and its context.
* **Alternate Display (`{:#}`)**: Prints the error, the full context list, the cause chain, and the captured backtrace.

## Error Context on Containers (`ErrorContext`)

Often, you want to add context directly to a `Result` or an `Option` at the call site. The [`ErrorContext`] trait enables this:

* **For `Result<T, E>**`: Turns the error into a context-enriched `BoxError`.
* **For `Option<T>**`: Converts `None` into a `BoxError` (starting with the message "Option is None") and attaches your context.

### Examples

**Option Example:**

```rust
use rama_error::ErrorContext;

let value: Option<usize> = None;
// Short-circuit using '?' with enriched info
let value = value.context_field("user_id", 42).context("session missing")?;
```

**Result Example:**

```rust
use rama_error::{ErrorContext, ErrorExt};

fn perform_io() -> Result<(), std::io::Error> { 
    /* ... */ 
    Ok(())
}

let res = perform_io()
    .context_field("request_id", "abc-123")
    .with_context(|| "failed to process storage");

if let Err(err) = res {
    // Standard display: "io error | request_id="abc-123" "failed to process storage""
    eprintln!("{}", err);
}
```

## Error Composition

While `BoxError` is excellent for high-level reporting, you may want explicit, domain-specific error types for your own logic.

Rama does not force a specific macro-based approach. We recommend defining errors as standard Rust `structs` or `enums` and implementing `std::error::Error`. For background on modern error design, see [Sabrina Jewson’s "Errors in Rust"](https://sabrinajewson.org/blog/errors).

For complex HTTP errors, you can explore Rama's own [HTTP rejection macros](https://github.com/plabayo/rama/blob/main/rama-http/src/utils/macros/http_error.rs) as inspiration. And, as always, Rama plays well with community standards like `thiserror` or `anyhow` if they better fit your workflow.
