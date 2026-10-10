## rama-fp

The code for rama-fp lives in rama-cli:

[/rama-cli/src/cmd/serve/fp](../rama-cli/src/cmd/serve/fp)

### Profile export

`rama ua export` replaces the Python profile generator and shares the Rust
analyzer with proxy exports. Set `RAMA_FP_DATABASE_URL` and run:

```sh
rama ua export --import-legacy --authorized --replace --output profiles.json
```

The export includes the last 14 UTC day buckets, including today. Legacy import
writes only the additive counted schema; it preserves source rows, deduplicates
restarts and records changed rows as revisions with unknown historical counts.
`rama ua view profiles.json` inspects the resulting archive.

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
