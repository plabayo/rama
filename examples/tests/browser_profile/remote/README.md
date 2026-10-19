# Remote readiness

This owner uses one temporary Machine in an existing FP app, one high TCP/UDP
port, private PostgreSQL storage and the shared standard-browser journey. It
retrieves private decoded evidence and runs the existing strict local replay.
It does not change the app's public listeners or use its production database.

Review the plan before executing:

```sh
just test-browser-profile-remote OUTPUT remote-cells.json APP IMAGE_DIGEST
# After reviewing the image/config, supply the immutable local Rama executable:
just test-browser-profile-remote OUTPUT remote-cells.json APP IMAGE_DIGEST RAMA true
```

Use a fresh output directory. The helper image must be built with the supplied
Dockerfile from reviewed immutable Rama/tools images. Install the ordinary
browser automation Python requirements locally. BrowserStack credentials stay
in the caller's private `~/.config/rama/browserstack.env`; no storage cookie is
loaded or sent.

Start with `readiness.cells.json` (H2 desktop/mobile). H1/H2/H3 cells preserve
the actual operation protocols; H3 discovery remains a separate verified operation. Neither
these tool tests nor a high-port readiness pass closes the full remote matrix
or public-port H3 acceptance.

The controller records requested and available actual browser identity,
source/native correlation, independent wire checks, replay and cleanup. Unknown
or ambiguous operations fail. Raw native CIDs are redacted; native peer/request
streams and independent wire CID continuity provide separate evidence.

Limits are four cells, 180 seconds per cell, 300 seconds idle and 1800 seconds
per owner, with bounded private files. Cleanup independently stops owned
processes, removes keys, destroys the exact Machine and checks the original
Machine configurations. Successful `driver.quit()` is recorded separately from
provider-side absence, which is not independently verified.
