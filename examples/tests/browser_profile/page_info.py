"""Read native request facts from a complete owned page response."""

from html.parser import HTMLParser
import re

from native_h3_response import decoded_body

MAX_PAGE_BYTES = 1024 * 1024


class RequestTables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.rows, self.cells, self.text = [], None, None, None
        self.headings, self.heading, self.heading_text = [], None, None

    def handle_starttag(self, tag, attrs):
        if tag == "h2":
            self.heading_text = []
        elif tag == "table":
            if self.rows is not None:
                raise ValueError("nested page table")
            self.rows = []
        elif self.rows is not None and tag == "tr":
            self.cells = []
        elif self.cells is not None and tag == "td":
            self.text = []

    def handle_data(self, text):
        if self.heading_text is not None:
            self.heading_text.append(text)
        if self.text is not None:
            self.text.append(text)

    def handle_endtag(self, tag):
        if tag == "h2" and self.heading_text is not None:
            self.heading = "".join(self.heading_text)
            self.heading_text = None
        elif tag == "td" and self.text is not None:
            self.cells.append("".join(self.text))
            self.text = None
        elif tag == "tr" and self.cells is not None:
            self.rows.append(self.cells)
            self.cells = None
        elif tag == "table" and self.rows is not None:
            self.tables.append(self.rows)
            self.headings.append(self.heading)
            self.rows = None


def request_info(page):
    if not isinstance(page, str) or len(page.encode()) > MAX_PAGE_BYTES:
        raise ValueError("bounded driver-observed page required")
    parser = RequestTables()
    parser.feed(page)
    parser.close()
    required = {"Version", "Method", "Scheme", "Authority", "Path", "Socket Address"}
    candidates = []
    for table in parser.tables:
        selected = [row for row in table if len(row) == 2 and row[0] in required]
        if {row[0] for row in selected} == required:
            if len(selected) != len(required):
                raise ValueError("duplicate native Request Info row")
            candidates.append(dict(selected))
    if len(candidates) != 1:
        raise ValueError("missing or ambiguous native Request Info table")
    value = candidates[0]
    return {
        name: value[label]
        for name, label in dict(
            version="Version",
            method="Method",
            scheme="Scheme",
            authority="Authority",
            path="Path",
            peer_addr="Socket Address",
        ).items()
    }


def response_object(frames):
    heads = [block for block in frames if block.from_server and block.headers]
    if len(heads) != 1 or dict(heads[0].headers).get(":status") != "200":
        raise ValueError("one successful source response required")
    coding = [
        value for name, value in heads[0].headers if name.lower() == "content-encoding"
    ]
    if len(coding) > 1:
        raise ValueError("ambiguous source content coding")
    return decoded_body(
        b"".join(block.data for block in frames if block.from_server),
        coding[0] if coding else None,
    )


def request_headers(page):
    """Preserve the server-rendered header order, multiplicity and spelling."""
    if not isinstance(page, str) or len(page.encode()) > MAX_PAGE_BYTES:
        raise ValueError("bounded native header page required")
    parser = RequestTables()
    parser.feed(page)
    parser.close()
    candidates = [
        table
        for heading, table in zip(parser.headings, parser.tables)
        if heading == "🚗 Http Headers"
    ]
    if len(candidates) != 1 or parser.rows is not None:
        raise ValueError("missing or ambiguous native Http Headers table")
    rows = candidates[0]
    if (
        not rows
        or len(rows) > 256
        or any(
            len(row) != 2 or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", row[0])
            for row in rows
        )
    ):
        raise ValueError("invalid native header row")
    return tuple(tuple(row) for row in rows)
