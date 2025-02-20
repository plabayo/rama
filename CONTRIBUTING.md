# Contributing

1. [File an issue](https://github.com/plabayo/rama/issues/new).
   The issue will be used to discuss the bug or feature and should be created before opening an MR.
   > Best to even wait on actually developing it as to make sure
   > that we're all aligned on what you're trying to contribute,
   > as to avoid having to reject your hard work and code.

In case you also want to help resolve it by contributing to the code base you would continue as follows:

2. Install Rust and configure correctly (https://www.rust-lang.org/tools/install).
3. Clone the repo: `git clone https://github.com/plabayo/rama`
4. Change into the checked out source: `cd rama`
5. Fork the repo.
6. Set your fork as a remote: `git remote add fork git@github.com:GITHUB_USERNAME/rama.git`
7. Make changes, commit to your fork.
   Please add a short summary and a detailed commit message for each commit.
   > Feel free to make as many commits as you want in your branch,
   > prior to making your MR ready for review, please clean up the git history
   > from your branch by rebasing and squashing relevant commits together,
   > with the final commits being minimal in number and detailed in their description.
8. To minimize friction, consider setting Allow edits from maintainers on the PR,
   which will enable project committers and automation to update your PR.
9. A maintainer will review the pull request and make comments.

   Prefer adding additional commits over amending and force-pushing
   since it can be difficult to follow code reviews when the commit history changes.

   Commits will be squashed when they're merged.

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

* `Rust`, version 1.85 or beyond: <https://www.rust-lang.org/tools/install>
* `just` (to run _just_ (config) files): <https://just.systems/man/en/packages.html>
* `cargo hack`: <https://github.com/taiki-e/cargo-hack?tab=readme-ov-file#installation>

Once this is all done you should be able to run `just qa`.
When all these pass you can be pretty certain that all tests in the GitHub CI step
will also succeed. The difference still though is that GitHub Action will also run some of these tests on the MSRV (`1.85`) and three platforms in total: MacOS, Linux and Windows.
