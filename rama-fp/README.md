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
Each fp service also runs this bounded import in the background at startup.
Invalid fields leave valid neighbouring fields intact. Rejected revisions are
counted by category and checkpointed for 14 days, with at most 16,384 rejection
checkpoints per partition; database or quota failures stop that partition.
`rama ua view profiles.json` inspects the resulting archive.

### Developer instructions

#### Browserstack

We make use of [BrowserStack](https://www.browserstack.com/) to automatically do the fingerprint flow
for all domains above and that for the most recent browsers and operating systems.

> Note: [this script](./browserstack/main.py) does not seasonal updates,
> to take into account the latest mobile devices on the market, as this is a hardcoded list.

Install `browser_automation/requirements.txt`, then run
`just browserstack-rama-fp /path/to/new-evidence` with `BROWSERSTACK_USERNAME`,
`BROWSERSTACK_ACCESS_KEY` and `RAMA_FP_STORAGE_COOKIE` in the environment.
The nightly job uses this same command and uploads that one receipt directory.

Each cell records requested and resolved browser identity, its origin, successful
per-flow protocols and session/quit outcomes. Generic errors remain failed cells;
“unsupported” needs a separately verified provider disposition. Receipts contain
no cookies, session IDs or exception messages. Session start means the driver
context yielded; quit success means WebDriver's quit call returned. Neither is an
independent provider check. BrowserStack's passed annotation precedes quit;
only the local receipt and job pass require successful quit. Collection is not
packet/replay acceptance.

However, we have [a cron job that runs this script daily at 18h](../.github/workflows/BrowserStack.yml), so there is no need to ever run it yourself.
It can also be triggered manually. Via [the Github Actions pane](https://github.com/plabayo/rama/actions).

> Dashboard: <https://automate.browserstack.com/dashboard/v2>

Collection preparation holds a queue slot for at most five seconds while a handler
runs. Slow requests continue normally after their optional capture is discarded.

Each authorization partition has independent limits of 16,384 live runs, 16,384
legacy-import runs and 16,384 rejected legacy revisions. Legacy imports cannot
consume live run capacity. The default 1,048,576 bucket limit permits at most
285,212,672 counter and sample rows (16 counters and 256 samples per bucket);
canonical byte limits do not bound PostgreSQL row and index overhead.

Fingerprint collection terminates TLS and HTTP directly. An HTTP-terminating
proxy changes the observed client protocol and can add client-IP headers that
must not become browser profile fields.

QPACK samples retain instruction kinds and compression flags, but omit inserted
value lengths. Full-match static-table indices remain bounded protocol metadata,
including entries such as `:path: /` and `content-length: 0`; they are excluded
from request-owned header structures.

Startup import scans the retained legacy window to detect changed revisions;
checkpoints prevent duplicate counts. The keyset cursor uses the source column's
collation and primary-key index. Reads and writes have server-side timeouts.
