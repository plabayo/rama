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


def write_receipt(path, receipt, *, secrets):
    """Fail closed before writing malformed flow evidence or credential material."""
    protocols = receipt["protocols"]
    if protocols is not None:
        checked_protocols(protocols)
    if "completed_protocols" in receipt:
        checked_partial_protocols(receipt["completed_protocols"])
    data = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if any(secret in data for secret in secret_forms(secrets)):
        raise ValueError("private material in cell receipt")
    with path.open("x") as output:
        output.write(data)
    path.chmod(0o600)
