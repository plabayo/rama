"""Small public-safe cell receipts; never serialize WebDriver/provider objects."""

from html import escape
import json
from urllib.parse import quote, quote_plus

IDENTITY_FIELDS = (
    "browserName",
    "browserVersion",
    "os",
    "osVersion",
    "deviceName",
    "platformName",
)
FLOW_NAMES = {"navigate", "fetch", "xhr", "ws", "form", "form_get"}
SITE_KINDS = {"same-site", "cross-site"}
SITE_FLOW_NAMES = {
    "image", "style", "script", "frame", "fetch", "xhr", "ws", "navigate", "form"
}
# Subresource transports come from resource timing, which a browser may withhold.
SITE_TIMED_FLOWS = {"image", "style", "script", "frame"}


def secret_forms(secrets):
    forms = {
        form
        for value in secrets
        if value
        for form in (value, escape(value), quote(value, safe=""), quote_plus(value))
    }
    # The final scan sees JSON text, including escaped quotes, backslashes and Unicode.
    return forms | {json.dumps(form)[1:-1] for form in forms}


def identity(capabilities, *, secrets):
    """Keep only bounded resolved/requested identity strings; absent stays absent.

    In particular, do not infer a resolved mobile browser version or device from
    its requested configuration. Provider capability maps can contain secrets.
    """
    sensitive = secret_forms(secrets)
    return {
        key: (
            value
            if (
                isinstance(value, str)
                and len(value) <= 128
                and value.isprintable()
                and not any(secret in value for secret in sensitive)
            )
            else None
        )
        for key in IDENTITY_FIELDS
        for value in (capabilities.get(key),)
    }


def checked_protocols(values):
    """Accept only complete six-flow evidence, including the actual WS transport."""
    if set(values) != FLOW_NAMES or any(
        value not in ("h1", "h2", "h3") for value in values.values()
    ):
        raise ValueError("invalid cell protocol receipt")
    return dict(values)


def checked_partial_protocols(values):
    """The completed flows of an unsupported cell: a nonempty subset, never WebSocket."""
    if (
        not values
        or not set(values) <= FLOW_NAMES - {"ws"}
        or any(value not in ("h1", "h2", "h3") for value in values.values())
    ):
        raise ValueError("invalid partial protocol receipt")
    return dict(values)


def checked_site_protocols(values, *, websocket=True):
    """Every flow sent to the same-site and cross-site hosts of an HTTPS cell.

    Only a WebSocket the browser cannot use on this origin (``websocket`` False)
    may be absent.
    """
    if not isinstance(values, dict) or set(values) != SITE_KINDS:
        raise ValueError("invalid site protocol receipt")
    required = SITE_FLOW_NAMES if websocket else SITE_FLOW_NAMES - {"ws"}
    for flows in values.values():
        if (
            not isinstance(flows, dict)
            or not required <= set(flows) <= SITE_FLOW_NAMES
            or any(
                value not in ("h1", "h2", "h3")
                and not (value == "unknown" and flow in SITE_TIMED_FLOWS)
                for flow, value in flows.items()
            )
        ):
            raise ValueError("invalid site protocol receipt")
    return {site: dict(flows) for site, flows in values.items()}


def write_receipt(path, receipt, *, secrets):
    """Fail closed before writing malformed flow evidence or credential material."""
    protocols = receipt["protocols"]
    if protocols is not None:
        checked_protocols(protocols)
    if "completed_protocols" in receipt:
        checked_partial_protocols(receipt["completed_protocols"])
    if receipt.get("site_protocols") is not None:
        checked_site_protocols(
            receipt["site_protocols"], websocket=protocols is not None
        )
    for visit in receipt.get("visits", ()):
        if visit["status"] == "passed":
            checked_protocols(visit["protocols"])
        if visit.get("site_protocols") is not None:
            checked_site_protocols(
                visit["site_protocols"], websocket=visit["status"] == "passed"
            )
    data = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if any(secret in data for secret in secret_forms(secrets)):
        raise ValueError("private material in cell receipt")
    with path.open("x") as output:
        output.write(data)
    path.chmod(0o600)
