"""Bounded, independent HTTP/1 browser-flow wire checks and replay inputs."""
import base64
import csv
from dataclasses import dataclass
import difflib
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys

FLOWS = ('navigate', 'fetch', 'xhr', 'ws', 'form')
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class Request:
    method: str
    uri: str
    headers: tuple
    body: bytes
    bindings: dict

    def wire_tuple(self):
        return self.method, self.uri, self.headers, self.body


def field_rows(path, port, display_filter, fields):
    require(path.stat().st_size <= 40 * 1024 * 1024, 'capture byte limit')
    args = ['tshark', '-r', str(path), '-d', f'tcp.port=={port},http',
            '-Y', display_filter, '-T', 'fields', '-E', 'header=y', '-E', 'quote=d',
            '-E', 'separator=\t', '-E', 'aggregator=\x1f']
    for field in fields:
        args += ['-e', field]
    text = subprocess.check_output(args, text=True, timeout=15)
    require(len(text) <= 4 * 1024 * 1024, 'decoded field byte limit')
    rows = list(csv.DictReader(io.StringIO(text), delimiter='\t'))
    require(len(rows) <= 4096, 'decoded row limit')
    return rows


def header_lines(value):
    return [line.removesuffix(r'\r\n') for line in value.split('\x1f') if line]


def decode_rows(requests, responses, port, reference):
    replies = {}
    for row in responses:
        frame = row['http.request_in']
        require(frame not in replies, 'ambiguous response association')
        replies[frame] = row
    output = {}
    for row in requests:
        method, uri = row['http.request.method'], row['http.request.uri']
        if reference and method == 'GET' and (uri.startswith('/assets/') or uri == '/favicon.ico'):
            continue
        flow = ('navigate' if uri == '/report' and method == 'GET' else
                'fetch' if re.fullmatch(r'/api/fetch/number/[0-9]+', uri) and method == 'POST' else
                'xhr' if re.fullmatch(r'/api/xml/number/[0-9]+', uri) and method == 'POST' else
                'form' if uri == '/form' and method == 'POST' else
                'ws' if uri == '/api/ws' and method == 'GET' else None)
        require(flow is not None, f'unexpected request: {method} {uri}')
        require(row['http.request.version'] == 'HTTP/1.1', 'wire protocol')
        authority = f'127.0.0.1:{port}'
        require(row['http.host'] == authority, 'loopback authority')
        body = bytes.fromhex(row['http.file_data'])
        require(len(body) <= 65536, 'request body limit')
        normalized, bindings = [], {}
        key = None
        host_count = 0
        for line in header_lines(row['http.request.line']):
            name, raw = line.split(':', 1)
            value = raw.lstrip(' \t')
            prefix = raw[:len(raw) - len(value)]
            lower = name.lower()
            require(lower not in ('cookie', 'authorization', 'proxy-authorization', 'transfer-encoding'),
                    'fixture requires credential-free, fixed-length requests')
            if lower in ('connection', 'content-type', 'content-length', 'origin', 'sec-websocket-protocol', 'sec-websocket-extensions'):
                require(lower not in bindings, 'duplicate request-owned field')
                bindings[lower] = value
            if lower == 'host':
                host_count += 1
                require(value == authority, 'Host binding')
                value = '<authority>'
            elif lower == 'origin' and value != 'null':
                require(value == 'http://' + authority, 'Origin binding')
                value = 'http://<authority>'
            elif lower == 'sec-websocket-key':
                require(flow == 'ws' and key is None, 'unexpected WebSocket key')
                key = value
                require(len(base64.b64decode(value, validate=True)) == 16, 'WebSocket key length')
                value = '<websocket-key>'
            normalized.append(name + ':' + prefix + value)
        require(host_count == 1, 'single Host field')
        if 'content-length' in bindings:
            require(bindings['content-length'].isdecimal() and int(bindings['content-length']) == len(body),
                    'Content-Length binding')
        else:
            require(not body, 'missing request framing')
        reply = replies.get(row['frame.number'])
        require(reply is not None, 'missing response')
        require(reply['http.response.code'] == ('101' if flow == 'ws' else '200'), 'response status')
        if flow == 'ws':
            require(key is not None, 'missing WebSocket key')
            accepts = [line.split(':', 1)[1].strip() for line in header_lines(reply['http.response.line'])
                       if line.split(':', 1)[0].lower() == 'sec-websocket-accept']
            expected = base64.b64encode(hashlib.sha1((key + GUID).encode('ascii')).digest()).decode('ascii')
            require(accepts == [expected], 'WebSocket accept binding')
        output.setdefault(flow, []).append(Request(method, uri, tuple(normalized), body, bindings))
    require(set(output) == set(FLOWS), 'five-flow coverage')
    for flow, rows in output.items():
        require(len(rows) == 1 or (reference and flow == 'navigate' and len(rows) <= 8),
                'ambiguous repeated flow')
    return output


def read_capture(path, port, reference):
    responses = field_rows(path, port, 'http.response',
                           ['http.request_in', 'http.response.code', 'http.response.line'])
    requests = field_rows(path, port, 'http.request',
                          ['frame.number', 'http.request.method', 'http.request.uri',
                           'http.request.version', 'http.host', 'http.request.line', 'http.file_data'])
    return decode_rows(requests, responses, port, reference)


def replay_args(rama, archive, output, port, flow, request):
    args = [str(rama), 'send', f'--emulate={archive}', '--emulate-initiator', flow,
            '--emulate-seed', '01' * 32, '--emulate-connection-key', '02' * 32,
            '--emulate-request-key', '03' * 32, '--http1.1', '--request', request.method]
    for name in ('connection', 'content-type', 'content-length', 'origin', 'sec-websocket-extensions'):
        if name not in request.bindings:
            continue
        value = request.bindings[name]
        if name == 'origin' and value != 'null':
            value = f'http://127.0.0.1:{port}'
        args += ['--header', name + ': ' + value]
    if request.body:
        body = request.body.decode('utf-8')
        require('\0' not in body and not body.startswith('@'), 'literal UTF-8 fixture body')
        args += ['--data', body]
    if flow == 'ws':
        protocols = [value.strip() for value in request.bindings.get('sec-websocket-protocol', '').split(',')]
        require(protocols == ['a', 'b'], 'fixture WebSocket protocols')
        args += ['--subprotocol', ','.join(protocols)]
    else:
        args += ['--fail', '--output', str(output)]
    scheme = 'ws' if flow == 'ws' else 'http'
    return args + [f'{scheme}://127.0.0.1:{port}' + request.uri]


def compare(reference, replay):
    require(set(reference) == set(FLOWS) == set(replay), 'five-flow comparison coverage')
    reports = []
    for flow in FLOWS:
        require(len(replay[flow]) == 1, 'one replay request per flow')
        observed = replay[flow][0]
        matched = any(observed.wire_tuple() == candidate.wire_tuple() for candidate in reference[flow])
        reports.append({'flow': flow, 'match': matched,
                        'body_match': any(observed.body == candidate.body for candidate in reference[flow]),
                        'differences': [] if matched else list(difflib.unified_diff(
                            reference[flow][0].headers, observed.headers, lineterm=''))})
    return reports


def main(root, reference_port, replay_port):
    reports = compare(read_capture(root / 'reference-wire.pcapng', reference_port, True),
                      read_capture(root / 'replay-wire.pcapng', replay_port, False))
    report = {'scope': 'HTTP/1 five-flow request header tuples and bodies',
              'normalization': 'validated Host/Origin authorities and WebSocket nonce with checked response accept',
              'limits': 'credential-free same-origin fixture; no TLS, H2, H3 or distribution claim',
              'comparisons': reports}
    (root / 'wire-comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    require(all(item['match'] for item in reports), 'five-flow wire mismatch; see wire-comparison.json')
    print(json.dumps({'result': 'PASS', 'flows': list(FLOWS), 'scope': report['scope']}))


if __name__ == '__main__':
    main(Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
