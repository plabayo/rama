# Contributing to rama

**Thank you for your interest in contributing to rama!**

This document will outline the basics of where to start if you wish to contribute to the project. There are many ways to help us out and and we appreciate all of them. We look forward to **your contribution!**

**Estimate 5 min read  — please read it all the way through**

## Code Of Conduct

Please read the
[Code of Conduct](./CODE_OF_CONDUCT.md) document as well

## Contribution Terms

When making a contribution you agree to the following terms:

- I understand these changes in full and will be able to respond to review comments.
- I have read the [Developer Certificate of Origin](https://developercertificate.org/) and certify my contribution under its conditions.

## Chat

You can join in our chat platforms to discuss development, issues or ask questions.

### [Discord](https://discord.gg/29EetaSYCD)

We have a Discord server, feel free to join it
if you wish to char with us, ask questions or discuss
anything rama related.

## Process

1. [File an issue](https://github.com/plabayo/rama/issues/new).
   The issue will be used to discuss the bug or feature and should be created before opening an MR.
   > Best to even wait on actually developing it as to make sure
   > that we're all aligned on what you're trying to contribute,
   > as to avoid having to reject your hard work and code.

In case you also want to help resolve it by contributing to the code base you would continue as follows:

2. Install Rust and configure correctly (https://www.rust-lang.org/tools/install).
3. [Fork the repo](https://github.com/plabayo/rama/fork) to your own GitHub account.
   This gives you a personal copy of rama that you are allowed to push to.
4. Clone _your fork_ (not the upstream repo): `git clone git@github.com:GITHUB_USERNAME/rama.git`
5. Change into the checked out source: `cd rama`
6. Add the upstream repo as a remote so you can stay in sync with it:
   `git remote add upstream https://github.com/plabayo/rama.git`
   > Your fork is now `origin` (where you push your work) and the main rama
   > repo is `upstream` (where you pull the latest changes from). Keep your
   > branch up to date with `git pull upstream main`.
7. Make changes on a branch and commit them to your fork.
   Please add a short summary and a detailed commit message for each commit.
   > Feel free to make as many commits as you want in your branch,
   > prior to making your MR ready for review, please clean up the git history
   > or else we will squash when merging
   > instead.
   > from your branch by rebasing and squashing relevant commits together,
   > with the final commits being minimal in number and detailed in their description.
8. To minimize friction, consider setting Allow edits from maintainers on the PR,
   which will enable project committers and automation to update your PR.
9. A maintainer will review the pull request and make comments.

   Prefer adding additional commits over amending and force-pushing
   since it can be difficult to follow code reviews when the commit history changes.

   Commits will be squashed when they're merged.

## Finding your way around the codebase

rama is a single workspace made up of 30+ crates. The good news is that you
almost never need to understand all of it — the crate name tells you which
"department" to walk into. Here is a map to help you find your starting point:

- **`rama-core`** — the foundation. It defines the `Service` and `Layer` traits
  (plus core utilities) that every other crate builds on. Read this first to
  understand how the pieces fit together.
- **HTTP** — the HTTP stack is split across several crates, from high-level to
  low-level. Most HTTP work happens in `rama-http`; you only go deeper when you
  need to change protocol behaviour:
  - `rama-http` — the HTTP services, layers and utilities you use day to day.
  - `rama-http-types` — shared HTTP types (request, response, headers, body).
  - `rama-http-headers` — typed HTTP headers.
  - `rama-http-backend` — the default HTTP client/server backend.
  - `rama-http-core` — the low-level HTTP/1 and HTTP/2 protocol implementation.
  - `rama-http-macros` — proc-macros (e.g. the type-safe HTML templating).
- **Transport & network** — `rama-net` (shared net types), `rama-tcp`,
  `rama-udp`, `rama-unix`.
- **TLS** — `rama-tls-boring` (BoringSSL, the default backend),
  `rama-tls-rustls`, `rama-tls-acme`.
- **Protocols & proxies** — `rama-dns`, `rama-socks5`, `rama-haproxy`,
  `rama-fastcgi`, `rama-ws`, `rama-grpc`, `rama-proxy`, `rama-ua`.
- **Tooling & glue** — `rama-cli` (the `rama` binary), `rama-macros`,
  `rama-error`, `rama-utils`, `rama-crypto`, `rama-tower`.

The full annotated list of every crate lives in the
[README](./README.md#--rama-crates). When in doubt, the crate name is the
department sign: HTTP work lives under one of the `rama-http*` crates, TLS under
`rama-tls-*`, and so on.

## Testing

All tests can be run locally against the latest Rust version (or whichever supported Rust version you're using on your development machine). However for contributor/developer purposes it is already sufficient if you check that your tests run
using the standard rust toolchain.

This way you can for example run the regular tests using:

```
cargo test --all-features --workspace
```

In case you do want to run most tests for your `rustc` version and platform,
you can do easily using the following command:

```bash
just qa
```

Before you can do this you do require the following to be installed:

* `Rust`, version 1.96 or beyond: <https://www.rust-lang.org/tools/install>
* `just` (to run _just_ (config) files): <https://just.systems/man/en/packages.html>

What you will also need to have installed is:

- `cmake`
- `clang` (`llvm`)

These are needed to compile the BoringSSL TLS backend (the `rama-tls-boring`
crate), a C/C++ library that rama uses for encryption. Because it is built from
source during setup, you need C/C++ build tools even though rama itself is
written in Rust. If `just qa` fails with a cryptic low-level compiler or linker
error, a missing `cmake` or `clang`/`llvm` is the most likely cause.

Once this is all done you should be able to run `just qa`.
When all these pass you can be pretty certain that all tests in the GitHub CI step
will also succeed. The difference still though is that GitHub Action will also run some of these tests on the MSRV and three platforms in total:

- Tier 1 platforms: MacOS, Linux and Windows
- Tier 2 platforms: Android and iOS
