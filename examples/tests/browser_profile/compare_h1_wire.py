"""Independent tshark comparison of isolated HTTP/1 request headers."""
import csv
import io
import json
from pathlib import Path
import re
import subprocess
import sys


def decode_requests(text, port):
    rows = list(csv.DictReader(io.StringIO(text), delimiter='\t'))
    selected = [row for row in rows if row['http.request.method'] == 'GET'
                and row['http.request.uri'] == '/report']
    if not selected:
        raise ValueError('no decoded GET /report')
    result = []
    for row in selected:
        if row['http.request.version'] != 'HTTP/1.1':
            raise ValueError('incorrect wire protocol')
        if row['http.host'] != f'127.0.0.1:{port}':
            raise ValueError('incorrect request-owned authority')
        lines = row['http.request.line'].split('\x1f')
        if len(lines) < 4:
            raise ValueError('missing decoded HTTP header lines')
        lines = [re.sub(r'(?i)^(host:\s*)127\.0\.0\.1:\d+',
                        r'\1<request-authority>', line) for line in lines]
        result.append(lines)
    return result


def compare(reference, replay):
    if len(replay) != 1:
        raise ValueError('replay request count')
    if replay[0] not in reference:
        raise ValueError('wire header names/order/values differ from retained browser requests')
    return len(replay[0])


def main(root, reference_port, replay_port):
    def requests(label, port):
        args = ['tshark', '-r', str(root/(label+'.pcapng')), '-d', f'tcp.port=={port},http',
                '-Y', 'http.request', '-T', 'fields', '-E', 'header=y', '-E', 'quote=d',
                '-E', 'separator=\t', '-E', 'aggregator=\x1f']
        for field in ['http.request.method', 'http.request.uri', 'http.request.version',
                      'http.host', 'http.request.line']:
            args += ['-e', field]
        text = subprocess.check_output(args, text=True, timeout=10)
        (root/(label+'.tsv')).write_text(text)
        return decode_requests(text, port)

    reference = requests('reference-wire', reference_port)
    replay = requests('replay-wire', replay_port)
    header_count = compare(reference, replay)
    report = {
        'result': 'PASS',
        'scope': 'independent tshark HTTP/1 GET /report header names, order and values',
        'reference_requests': len(reference), 'replay_requests': len(replay),
        'header_count': header_count,
        'normalization': 'Host value only; verified separately against each listener',
        'limits': 'No TLS, HTTP/2, HTTP/3 or distribution coverage claim',
    }
    (root/'wire-comparison.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main(Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
