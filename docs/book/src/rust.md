# Built with Rust

<div class="book-article-intro">
    <img src="./img/llama_rust.jpeg" alt="artistical representation of a llama on top of a crab">
    <div>
        Rama (ラマ) is built using <a href="https://www.rust-lang.org/">Rust</a>, a language empowering
        everyone to build reliable and efficient software. Rama is developed and maintained by
        <a href="https://plabayo.tech/">Plabayo</a>, a Free and Open Source software R&D and Consultancy studio,
        with a deep appreciation for Rust.
    </div>
</div>

Now it is very well possible that you learned about Rama because as a service framework it perfectly fits your needs,
or because your deep interest in proxy technology. Yet you might not be very familiar with Rust, or might not
know the language all. Or perhaps you did play around with Rust but aren't comfortable enough to start using
a crate such as Rama.

<https://rust-lang.guide/> is a FOSS guide created by Plabayo, the maintainers behind Rama, and
serves as a guide to get you from an absolute Rust Beginner to a true _Rustacean_ with a solid
understanding and deep appreciation for the language. Because Rust is truly one of those languages
that makes programming all fun and no sweat. It's the playfullnes that we love at Plabayo.

## Learning Rust

Becoming proficient in Rust requires the fulfillment of three pillars:

- Pillar I: Learn Rust and get your foundations right
  - [Learn Rust](https://rust-lang.guide/guide/learn-rust/index.html)
  - [Learn More Rust](https://rust-lang.guide/guide/learn-more-rust/index.html)
  - [Learn Async Rust](https://rust-lang.guide/guide/learn-async-rust/index.html)
  - [Study using the "Rust for Rustaceans: Idiomatic Programming for Experienced Developers" book](https://rust-lang.guide/guide/study-using-the-rust-for-rustaceans-idiomatic-programming-for-experienced-developers-book)
- Pillar II: Develop with Rust (Practical Experience)
  - [Study using the "Zero to Production in Rust" book](https://rust-lang.guide/guide/study-using-the-zero-to-production-in-rust-book)
  - [Contribute for the first time to an existing project](https://rust-lang.guide/guide/contribute-for-the-first-time-to-an-existing-project)
  - [Contribute an advanced feature to an existing project or start a project from scratch](https://rust-lang.guide/guide/contribute-an-advanced-feature-to-an-existing-project-or-start-a-project-from-scratch)
- Pillar III: Be part of the Rust Ecosystem:
  - [Next Steps](https://rust-lang.guide/guide/next-steps)

You can find the full version of that chapter at <https://rust-lang.guide/intro/learning-rust.html>.

Rama is developed with a multithreaded Async work-stealing runtime in mind, using Tokio. For ergonomic reasons it makes heavy
use of generics on top of that. Combining this with the fact that Rust still has some surfaces it has to smooth out,
makes it that you want to make sure you have a solid foundation of Rust, prior to being able to fully understand the Rama codebase.
