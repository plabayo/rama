# Why Rama

<div class="book-article-intro">
    <img src="./img/old_logo.png" alt="original (OG) rama logo">
    <div>
        <p>
            Developing specialised proxies, in Rust, but certainly also in other languages,
            falls currently in two categories:
        </p>
        <ol>
            <li>use an "off-the-shelf" solution;</li>
            <li>develop it yourself "from scratch".</li>
        </ol>
    </div>
</div>

(1) is usually in the form of using something like Nginx, Caddy or Envoy.
In most cases that means being limited to using what they offer,
and configure only using config files. Most of these technologies do
allow you to add custom code to it, but you're limited in the whats and hows.
On top of that you are still essentially stuck with the layers that they do offer
and that you cannot do without.

(2) works, gives you the full freedom of a child's seemingly infinite creativity.
However... having to do that once, twice, and more, becomes boring pretty quickly.
Despite how specialised your proxy might be, it will be pretty similar to many other proxies
out there, including the ones that you write yourself.

and this is where Rama comes in and hopes to be. It allows you to develop
network proxies, specialised for your use case, while still allowing to expose and reuse use
the parts of of the code not unique to that one little proxy idea.

## Alternatives

While there are a handful of proxies written in Rust, there are only two other Rust frameworks
specifically made for proxy purposes. All other proxy codebases are single purpose code bases,
some even just for learning purposes. Or are actually generic http/web libraries/frameworks
that facilitate proxy features as an extra.

[Cloudflare] has been working on a proxy service framework, named [`pingora`], since a couple of years already,
and on the 28th of February of 2024 they also open sourced it.

Rama is not for everyone, but we sure hope it is right for you.
If not, consider giving [`pingora`] a try, it might very well be the next best thing for you.

Secondly, [ByteDance] has an open source proxy framework written in Rust to developer forward
and reverse proxies alike, named [`g3proxy`].

[Cloudflare]: https://www.cloudflare.com/
[`pingora`]: https://github.com/cloudflare/pingora
[ByteDance]: https://www.bytedance.com/en/
[`g3proxy`]: https://github.com/bytedance/g3

## More than proxies

The initial development of Rama quickly showed us that many of the advantages
that developing on top of Rama also apply equally well to developing [web servers](./web_servers.md)
and [http clients](./http_clients.md):

* Use Async Method Traits;
* Reuse modular [Tower](https://github.com/tower-rs/tower)-like middleware using extensions as well as strongly typed state;
* Have the ability to be in full control of your web stack from Transport Layer (Tcp, Udp), through Tls and Http;
* Be able to trust that your incoming and outgoing Application Http data has not been modified (e.g. Http header casing and order is preserved);

Continue to read this book to learn more about using Rama for either of these purposes.