# HTTP Archive (HAR)

<div class="book-article-intro">
    <img src="../img/llama_har.jpg" alt="artistical representation of a llama carefully collecting and replaying HTTP requests and responses">
    <div>
        HTTP Archive, usually referred to as HAR, is a standardized JSON based format for recording HTTP interactions.
        It captures requests, responses, timing information, headers, payloads, and metadata in a single portable document.
        <p>— <a href="https://github.com/plabayo/rama/blob/main/rama-http/src/layer/har/spec.md">HAR Specification</a></p>
    </div>
</div>

## Description

A HAR file represents a chronological log of HTTP activity.
Each entry contains a full request and its corresponding response, including headers, body payloads, status codes, timing data, and optional comments.

HAR was originally designed for browser developer tools, but its usefulness extends far beyond debugging web pages.
Because it is deterministic and self contained, a HAR file can act as a **frozen snapshot of (HTTP) network behavior**.

Rama provides native support for working with HAR files, including converting them into strongly typed HTTP requests and responses.
This makes HAR a practical building block for testing, replay, inspection, and traffic analysis.

At its core, HAR is simply structured data.
While it is useful for inspection it is even more powerful if that data becomes executable.

## Why HAR Is Useful

HAR files are valuable because they decouple HTTP behavior from live systems.
Once captured, traffic can be reused without relying on external services or network conditions.

Common use cases include:

- **End to end testing** by replaying real world traffic against a local or staging server
- **Regression testing** to ensure changes do not alter observable HTTP behavior
- **Benchmarking** using realistic request patterns
- **Debugging** by inspecting exact payloads and headers that triggered a bug
- **Offline development** without relying on flaky or unavailable services
- **Security analysis** to review traffic for sensitive data or unexpected behavior

Unlike hand written mocks, HAR captures reality.
It includes edge cases, unusual headers, binary payloads, and timing patterns that are difficult to reproduce manually.

## Rama Support

Rama treats HAR as a first class citizen.

When the `http` feature is enabled, Rama allows you to:

- Deserialize HAR files into strongly typed Rust structures
- Convert HAR requests into
  [`rama::http::Request`](https://ramaproxy.org/docs/rama/http/struct.Request.html)
- Convert HAR responses into
  [`rama::http::Response`](https://ramaproxy.org/docs/rama/http/struct.Response.html)
- Replay traffic through a real HTTP client or server stack

Because Rama’s HTTP types are shared across client, server, and middleware layers, HAR replay integrates naturally with tracing, compression, retries, and other layers.

There is no separate mocking framework.
A HAR file simply becomes another source of HTTP traffic.

## Example: HAR Replay

Rama ships with a ready to run example called [`http_har_replay.rs`](https://github.com/plabayo/rama/blob/main/examples/http_har_replay.rs).

This example demonstrates how to:

1. Load a HAR file from disk or use a built in example
2. Convert each HAR entry into a real HTTP request
3. Replay requests against a local Rama server
4. Select responses based on request index
5. Print both requests and responses to stdout

The replay server does not need to understand the original application.
It simply rehydrates recorded responses and sends them back.

This pattern is especially useful for:

- Semi automated end to end tests
- Validating middleware behavior such as compression or retries
- Reproducing production issues locally
- Sharing minimal and reproducible bug reports

Because HAR captures payloads as text or base64, both textual and binary bodies are supported.

## Determinism and Control

HAR replay gives you deterministic behavior.
Every request and response is known in advance.

Combined with Rama’s layering model, you can easily:

- Inject artificial latency
- Add tracing or logging
- Modify headers or payloads
- Replay only a subset of entries
- Randomize selection based on a stable hash
- Forward or mock requests from within the (proxy) server, for some or all of incoming requests

This makes HAR a powerful tool for controlled experimentation.
