"""Wire observations in the form exported profiles retain; mirrors rama-ua's read form."""

PRE_SHARED_KEY_EXTENSION = 41
KEY_SHARE_EXTENSION = 51
# Extensions whose value lists number their own GREASE slots.
GREASE_LIST_EXTENSIONS = frozenset((10, 13, 34, 43, 50))
NETWORK_HINT_NAMES = frozenset(("downlink", "rtt", "ect"))


def is_grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def numbered(values):
    """Replace each GREASE value by its slot, as the profile numbers them."""
    result, slot = [], 0
    for value in values:
        if is_grease(value):
            if slot == 16:
                raise ValueError("too many TLS GREASE slots")
            value = 0x0A0A + 0x1010 * slot
            slot += 1
        result.append(value)
    return result


def tls_read_form(capture, scope):
    """A decoded ClientHello as the given profile scope retains it."""
    identifiers = numbered([extension["id"] for extension in capture["extensions"]])
    extensions = []
    for identifier, extension in zip(identifiers, capture["extensions"]):
        value = extension["value"]
        if identifier in GREASE_LIST_EXTENSIONS and "U16List" in value:
            value = {"U16List": numbered(value["U16List"])}
        elif identifier == KEY_SHARE_EXTENSION and "KeyShares" in value:
            shares = value["KeyShares"]
            groups = numbered([share["group"] for share in shares])
            value = {
                "KeyShares": [
                    {**share, "group": group} for share, group in zip(shares, groups)
                ]
            }
        extensions.append({"id": identifier, "value": value})
    if scope.get("shuffled_tls_extensions", False):
        extensions.sort(
            key=lambda extension: (
                extension["id"] == PRE_SHARED_KEY_EXTENSION,
                extension["id"],
            )
        )
    return {**capture, "ciphers": numbered(capture["ciphers"]), "extensions": extensions}


def is_network_hint(name):
    return name.lower() in NETWORK_HINT_NAMES


def hint_combinations(scope):
    """The hint value combinations a scope draws from, one per observed request."""
    return {
        tuple((name, tuple(value)) for name, value in hint["fields"])
        for hint in scope.get("network_hints", ())
    }
