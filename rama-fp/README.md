[![rama banner](../docs/img/rama_banner.jpeg)](https://ramaproxy.org/)

[![Crates.io][crates-badge]][crates-url]
[![Docs.rs][docs-badge]][docs-url]
[![MIT License][license-mit-badge]][license-mit-url]
[![Apache 2.0 License][license-apache-badge]][license-apache-url]
[![Build Status][actions-badge]][actions-url]

[![Discord][discord-badge]][discord-url]
[![Buy Me A Coffee][bmac-badge]][bmac-url]
[![GitHub Sponsors][ghs-badge]][ghs-url]

[crates-badge]: https://img.shields.io/crates/v/rama.svg
[crates-url]: https://crates.io/crates/rama
[docs-badge]: https://img.shields.io/docsrs/rama/latest
[docs-url]: https://docs.rs/rama/latest/rama/index.html
[license-mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[license-mit-url]: https://github.com/plabayo/rama/blob/main/LICENSE-MIT
[license-apache-badge]: https://img.shields.io/badge/license-APACHE-blue.svg
[license-apache-url]: https://github.com/plabayo/rama/blob/main/LICENSE-APACHE
[actions-badge]: https://github.com/plabayo/rama/workflows/CI/badge.svg
[actions-url]: https://github.com/plabayo/rama/actions?query=workflow%3ACI+branch%main

[discord-badge]: https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white
[discord-url]: https://discord.gg/29EetaSYCD
[bmac-badge]: https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black
[bmac-url]: https://www.buymeacoffee.com/plabayo
[ghs-badge]: https://img.shields.io/badge/sponsor-30363D?style=for-the-badge&logo=GitHub-Sponsors&logoColor=#EA4AAA
[ghs-url]: https://github.com/sponsors/plabayo

🦙 Rama (ラマ) is a modular proxy framework for the 🦀 Rust language to move and transform your network packets.
The reasons behind the creation of rama can be read in [the "Why Rama" chapter](https://ramaproxy.org/book/why_rama).

## rama-fp

`rama-fp` is a fingerprint web service and collector to facilate user agent emulation and validation.

Hosted (via <https://fly.io>) at:

- <http://fp.ramaproxy.org>
- <https://fp.ramaproxy.org>

Also hosted (via <https://fly.io>) as http/1.1 only:

- <http://h1.fp.ramaproxy.org>
- <https://h1.fp.ramaproxy.org>

Available at Docker Hub (latest main branch commit):

- <https://hub.docker.com/repository/docker/glendc/rama-fp>

### Developer instructions

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
  - `RAMA_FP_TLS_CRT`: `/etc/letsencrypt/live/fp.ramaproxy.org/fullchain.pem`
  - `RAMA_FP_TLS_KEY`: `/etc/letsencrypt/live/fp.ramaproxy.org/privkey.pem`

For now this process has to be repeated every 90 days, for both the `fp.*` and `h1.fp.*` subdomains.
We can probably automate this already using a manual github action flow, given that `certbot` can be used
from within docker and we can update secrets and redeploy using fly's API...

But for now, given this only takes 5 minutes we can probably live with this manual process.
Plus even better if we can add ACME support to rama's TLS capabilities and have it auto renew itself...
There is no github ticket about this, but feel free to contact _glendc_ by mail or discord if you want
to tackle this.
