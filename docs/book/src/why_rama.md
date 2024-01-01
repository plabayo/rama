# Why Rama

Developing specialised proxies, in Rust, but certainly also in other languages,
falls currently in two categories:

1. use an "off-the-shelf" solution;
2. develop it yourself "from scratch".

(1) is usually in the form of using something like Nginx, Caddy or Envoy.
In most cases that means being limited to using what they offer,
and configure only using config files. Most of these technologies do
allow you to add custom code to it, but you're limited in the whats and hows.
On top of that you are still essentially stuck with the layers that they do offer
and that you cannot do without.

(2) works, gives you the full freedom of a child's infinite creativity.
However... having to do that once, twice, and more, becomes boring pretty quickly.
Despite how specialised your pxoxy might be, it will be pretty similar to many other proxies
out there, including the ones that you write yourself.

and this is where Rama comes in and hopes to be. It allows you to develop
network proxies, specialised for your use case, while still allowing to expose and reuse use
the parts of of the code not unique to that one little proxy idea.
