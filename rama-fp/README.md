[![rama banner](../docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![rust version][rust-version-badge]][rust-version-url]
[![Build Status][actions-badge]][actions-url]

[![Discord][discord-badge]][discord-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]
[![Paypal Donation][paypal-badge]][paypal-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[rust-version-badge]: https://img.shields.io/badge/rustc-1.75+-blue?style=flat-square&logo=rust
[rust-version-url]: https://www.rust-lang.org
[actions-badge]: https://github.com/plabayo/rama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/rama/actions

[discord-badge]: https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white
[discord-url]: https://discord.gg/29EetaSYCD
[bmac-badge]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black
[bmac-url]: https://www.buymeacoffee.com/plabayo
[ghs-badge]: https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA
[ghs-url]: https://github.com/sponsors/plabayo
[paypal-badge]: https://img.shields.io/badge/paypal-contribution?style=for-the-badge&color=blue
[paypal-url]: https://www.paypal.com/donate/?hosted_button_id=P3KCGT2ACBVFE

🦙 Rama (ラマ) is a modular service framework for the 🦀 Rust language to move and transform your network packets.
The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).

## rama-fp

`rama-fp` is a fingerprint web service and collector to facilate user agent emulation and validation.

Hosted (via <https://fly.io>) at:

- <http://fp.ramaproxy.org:80>
- <https://fp.ramaproxy.org:443>

Also hosted (via <https://fly.io>) as http/1.1 only:

- <http://h1.fp.ramaproxy.org:80>
- <https://h1.fp.ramaproxy.org:443>

Finally you can also use the Rama FP Service as an echo service for any
method, path, query, body, and so on:

- <http://echo.ramaproxy.org:80>
- <https://echo.ramaproxy.org:443>

Available at Docker Hub (latest main branch commit):

- <https://hub.docker.com/repository/docker/glendc/rama-fp>

### Developer instructions

#### Browserstack

We make use of [BrowserStack](https://www.browserstack.com/) to automatically do the fingerprint flow
for all domains above and that for the most recent browsers and operating systems.

> Note: [this script](./browserstack/main.py) does not seasonal updates,
> to take into account the latest mobile devices on the market, as this is a hardcoded list.

The script can be run locally using the `just browserstack-rama-fp` command,
for which you do need to have a valid username and access key in your environment variables.

However, we have [a cron job that runs this script daily at 18h](../.github/workflows/BrowserStack.yml), so there is no need to ever run it yourself.
It can also be triggered manually. Via [the Github Actions pane](https://github.com/plabayo/rama/actions).

> Dashboard: <https://automate.browserstack.com/dashboard/v2>

#### TLS Certificate

For now we manually generate Letsencrypt based TLS certifications.

Steps:

1. use [certbot](https://certbot.eff.org/instructions) to start process on dev host machine:
```sh
sudo certbot certonly --manual -d fp.ramaproxy.org
```
2. update the `RAMA_FP_ACME_DATA` SECRET in <https://fly.io> app config to enable and point to the new key/value ACME validation pair (format is `file_name,file_content`)
3. redeploy
4. press `enter` in process started in step (1)
5. copy key and cert files, found at and to be made available as secrets at:
  - `RAMA_FP_TLS_CRT`: `sudo cat /etc/letsencrypt/live/fp.ramaproxy.org/fullchain.pem | base64 | pbcopy`
  - `RAMA_FP_TLS_KEY`: `sudo cat /etc/letsencrypt/live/fp.ramaproxy.org/privkey.pem | base64 | pbcopy`

For now this process has to be repeated every 90 days, for both the `fp.*` and `h1.fp.*` subdomains.
We can probably automate this already using a manual github action flow, given that `certbot` can be used
from within docker and we can update secrets and redeploy using fly's API...

But for now, given this only takes 5 minutes we can probably live with this manual process.
Plus even better if we can add ACME support to rama's TLS capabilities and have it auto renew itself...
There is no github ticket about this, but feel free to contact _glendc_ by mail or discord if you want
to tackle this.
