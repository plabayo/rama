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


def native_replay_reference(archive):
    """Project only a reference TCP offer for a profile with one captured TCP HTTP version."""
    names = {"HTTP/1.1": b"http/1.1", "HTTP/2.0": b"h2"}

    def project(capture, protocol):
        if capture.get("transport") == "Tcp":
            extensions = capture["extensions"]
            offer = next((ext["value"]["Protocols"] for ext in extensions if ext["id"] == 16), [])
            if protocol not in offer or offer == [protocol]:
                return capture
            projected = []
            for ext in extensions:
                if ext["id"] == 16:
                    ext = {**ext, "value": {"Protocols": [protocol]}}
                elif ext["id"] in (17513, 17613):
                    settings = [item for item in ext["value"]["Protocols"] if item == protocol]
                    if not settings:
                        continue
                    ext = {**ext, "value": {"Protocols": settings}}
                projected.append(ext)
            return {**capture, "extensions": projected}
        if "slots" in capture:
            return {**capture, "slots": [
                {**slot, "capture": project(slot["capture"], protocol)}
                if slot["kind"] == "TcpTls" else slot for slot in capture["slots"]
            ]}
        return capture

    profiles = []
    for profile in archive["profiles"]:
        versions = {
            scope["flow"]["Http"]["version"]
            for scope in profile["scopes"]
            if "Http" in (scope.get("flow") or {})
        } - {"HTTP/3.0"}
        if len(versions) == 1 and (version := next(iter(versions))) in names:
            protocol = list(names[version])
            scopes = []
            for scope in profile["scopes"]:
                variants = [
                    {**variant, "capture": project(variant["capture"], protocol)}
                    for variant in scope["variants"]
                ]
                scopes.append({**scope, "variants": variants})
            profile = {**profile, "scopes": scopes}
        profiles.append(profile)
    return {**archive, "profiles": profiles}
