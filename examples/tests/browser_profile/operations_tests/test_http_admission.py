"""All six H1 operations bind raw Host, native peers and complete bodies."""

from copy import deepcopy
from dataclasses import replace
import unittest
import xml.etree.ElementTree as ET

import zstandard

from capture_fields import compare_capture_fields
from flows import FLOWS, request_authority
from operations_tests.http_fixtures import JOINT, ORIGIN, field, inspected, journey
from operations import OperationLedger
from admission import admit
from wire import parse_pdml


class HttpAdmissionTests(unittest.TestCase):
    def test_h1_host_joint_request_pins_and_driver_native_attribution(self):
        document, page = journey()
        raw = ET.tostring(document)
        blocks = parse_pdml(raw, "mixed", 65320, include_data=True)
        planned = OperationLedger.from_driver(
            blocks, page["protocols"], ORIGIN, page["report_url"]
        )
        self.assertEqual(
            set(admit(raw, blocks, page, ORIGIN, operations=planned)["flows"]),
            set(FLOWS),
        )
        source = inspected(blocks)
        self.assertEqual(
            compare_capture_fields(source, blocks, operations=planned)[
                "requests_checked"
            ],
            6,
        )
        bound = planned.with_joints(
            {"h1": {"connection_joints": {1: JOINT, 4: JOINT}}}
        ).with_requests(source, blocks, {})
        self.assertTrue(all(operation.request for operation in bound.operations))
        changed = deepcopy(page)
        changed["page_results"]["xhr"]["fp"]["request_info"][
            "peer_addr"
        ] = "198.51.100.8:65345"
        with self.assertRaisesRegex(ValueError, "packet/native association"):
            admit(raw, blocks, changed, ORIGIN, operations=planned)
        head = next(
            block for block in blocks if not block.from_server and block.stream == 10
        )
        with self.assertRaisesRegex(ValueError, "authority"):
            request_authority(
                replace(head, headers=head.headers + (("HOST", "other.test"),))
            )

    def test_native_response_decoding_keeps_encoded_zstd_and_header_case(self):
        document, page = journey()
        response = next(
            proto
            for proto in document.findall("packet/proto[@name='http']")
            if proto.find("field[@name='http.request_in'][@show='10']") is not None
        )
        payload = response.find("field[@name='http.file_data']")
        body = zstandard.ZstdCompressor().compress(bytes.fromhex(payload.get("value")))
        payload.set("value", body.hex())
        payload.set("size", str(len(body)))
        length = next(
            node
            for node in response.findall("field[@name='http.response.line']")
            if bytes.fromhex(node.get("value")).startswith(b"Content-Length:")
        )
        raw = ("Content-Length: " + str(len(body)) + "\r\n").encode()
        length.set("value", raw.hex())
        length.set("size", str(len(raw)))
        field(response, "http.response.line", b"CoNtEnT-EnCoDiNg: zstd\r\n", raw=True)
        raw = ET.tostring(document)
        blocks = parse_pdml(raw, "mixed", 65320, include_data=True)
        planned = OperationLedger.from_driver(
            blocks, page["protocols"], ORIGIN, page["report_url"]
        )
        self.assertEqual(
            set(admit(raw, blocks, page, ORIGIN, operations=planned)["flows"]),
            set(FLOWS),
        )
