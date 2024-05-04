# 👤 User Agent

> On the Web, a user agent is a software agent responsible for retrieving and
> facilitating end-user interaction with Web content. This includes all web browsers,
> such as Google Chrome and Safari, some email clients, standalone download managers
> like youtube-dl, and other command-line utilities like cURL.
>
> — [Wikipedia](https://en.wikipedia.org/wiki/User_agent).

Rama offers support to:

* Parse User Agent Header Strings: for the purpose of identifying the User Agent that created the incoming http request
* Emulate User Agents: for the purpose of distoring incoming proxy requests (see [Distortion Proxies](../proxies/distort.md))

More Information:

* ⛰️ The source code for User Agent (UA) support can be found at <https://github.com/plabayo/rama/tree/main/src/ua>;
* 📖 and the edge documentation for it can be found at <https://ramaproxy.org/docs/rama/ua/index.html>.

## Fingerprinting

Modern web stacks have often fingerprinting in place, usually by use of third party services, for the purpose of ad revenue and anti-bot measurements.

These fingerprints are layered and are generated on:

- the network layers: mostly IP, HTTP and TLS;
- the scripting layer: javascript engine + web API interaction;
- the [Web API](https://developer.mozilla.org/en-US/docs/Web/API) surface: compatibility, user agent- and host information.

By use of [upstream proxies](https://ramaproxy.org/docs/rama/proxy/trait.ProxyDB.html) and [distort proxies](../proxies/distort.md) you can effectively emulate the more common User Agents (UA), desired physical location and user profile.

Rama's UA emulation capabilities are powered by [its automated fingerprinting service](https://github.com/plabayo/rama/blob/main/rama-fp/browserstack/main.py) that is publicly available at <https://fp.ramaproxy.org/>. This infrastructure is sponsored by 💖 <https://fly.io/> and 💖 [BrowserStack](https://browserstack.com).

> 🔁 <https://echo.ramaproxy.org/> is another service publicly exposed.
> In contrast to the Fingerprinting Service it is aimed at developers
> and allows you to send any http request you wish in order to get an insight
> on the Tls Info and Http Request Info the server receives
> from you when making that request.
>
> ```bash
> curl -XPOST 'https://echo.ramaproxy.org/foo?bar=baz' \
>   -H 'x-magic: 42' --data 'whatever forever'
> ```
>
> Feel free to make use of while crafting distorted http requests,
> but please do so with moderation. In case you have ideas on how to improve
> the service, please let us know [by opening an issue](https://github.com/plabayo/rama/issues).
