## rama-fp

The code for rama-fp lives in rama-cli:

[/rama-cli/src/cmd/fp](../rama-cli/src/cmd/fp)

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
2. update the `RAMA_ACME_DATA` SECRET in <https://fly.io> app config to enable and point to the new key/value ACME validation pair (format is `file_name,file_content`)
3. redeploy: `fly deploy`
4. press `enter` in process started in step (1)
5. copy key and cert files, found at and to be made available as secrets at:
  - `RAMA_TLS_CRT`: `sudo cat /etc/letsencrypt/live/fp.ramaproxy.org/fullchain.pem | base64 | pbcopy`
  - `RAMA_TLS_KEY`: `sudo cat /etc/letsencrypt/live/fp.ramaproxy.org/privkey.pem | base64 | pbcopy`

For now this process has to be repeated every 90 days, for both the `fp.*` and `h1.fp.*` subdomains.
We can probably automate this already using a manual github action flow, given that `certbot` can be used
from within docker and we can update secrets and redeploy using fly's API...

But for now, given this only takes 5 minutes we can probably live with this manual process.
Plus even better if we can add ACME support to rama's TLS capabilities and have it auto renew itself...
There is no github ticket about this, but feel free to contact _glendc_ by mail or discord if you want
to tackle this.
