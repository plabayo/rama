# 🧦 SOCKS5 proxies

<div class="book-article-intro">
    <img src="../img/proxy_llama_socks5.jpeg" alt="artistical representation of rama socks5 proxy as llama carying cargo through space while wearing socks">
    <div>
        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus diam purus, semper at magna ut, venenatis sodales quam. Phasellus in semper enim. Nulla facilities. Vestibulum sed lectus sollicitudin, commodo nunc eget.
    </div>
</div>

There are currently
[no examples found in the `./examples` dir](https://github.com/plabayo/rama/tree/main/examples)
on how to create such a proxy using rama. If you are interested in contributing this
you can create an issue at <https://github.com/plabayo/rama/issues> and we'll
help you to get this shipped.

<div class="book-article-image-center">

```dot process
digraph {
    pad=0.2;
    "client" -> "proxy(rama)" [dir=both]
    "proxy(rama)" -> "server A" [dir=both]
    "proxy(rama)" -> "server B" [dir=both]
}
```

</div>

You'll notice that the above graph is the exact same one used in
[the http(s) Proxies chapter](./http.md). This is no coincidance,
as topology wise they are the same.

The key differences are:

- TODO
