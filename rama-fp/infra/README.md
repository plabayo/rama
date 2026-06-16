# rama-fp infra

Fly.io deployment configs for the public rama demo services and supporting scripts.

## IP geolocation

The `ip`/`echo`/`fp` services optionally enrich responses with IP geolocation
(MaxMind GeoLite2 + IP2Location LITE, served side-by-side). Opt-in via
`RAMA_IP_GEO_DB`; without it the services run unchanged.

[`geoip_sync.sh`](./scripts/geoip_sync.sh) fetches the databases. It needs three
free credentials:

| Variable                                    | From |
| ------------------------------------------- | ---- |
| `MAXMIND_ACCOUNT_ID` + `MAXMIND_LICENSE_KEY` | <https://www.maxmind.com/en/geolite2/signup> → Manage License Keys |
| `IP2LOCATION_TOKEN`                          | <https://lite.ip2location.com> → account Download page |

```sh
# test locally
./scripts/geoip_sync.sh download ./.geoip
export RAMA_IP_GEO_DB="geolite2=./.geoip/GeoLite2-City.mmdb+./.geoip/GeoLite2-ASN.mmdb;ip2location=./.geoip/IP2Location-LITE-DB11.mmdb"
cargo run -p rama-cli -- serve ip --bind 127.0.0.1:8080

# first-time / full rollout to Fly: per app, in parallel — one `geoip` volume
# per machine, deploy the mount, then push the databases
fly auth login && ./scripts/geoip_sync.sh rollout

# later: just refresh the data on already-mounted volumes
./scripts/geoip_sync.sh sync
```

`rollout` and `sync` run all apps concurrently and retry every Fly call (flyctl's
shared agent can crash under parallelism). The `geoip` mount + `RAMA_IP_GEO_DB`
are declared in each app's `fly.toml`, and the services treat a missing/unsynced
database as "no geo" rather than a startup error — so order is not load-bearing.

> IP2Location LITE caps a token at **5 downloads / 24h**; if that (or any
> download) fails, the script reuses the previously fetched file and carries on.
