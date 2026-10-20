#!/usr/bin/env python3
"""Capture direct, forwarded and intercepted H3 with an independent tshark oracle.

This checks forwarding integrity and decoded exchanges. It does not certify
browser-profile equivalence; that requires the profile comparison matrix.
"""
import argparse
from collections import Counter
import copy
import csv
import io
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time


# HTTP field values cannot contain this control byte; commas are ordinary data.
OCCURRENCE_SEPARATOR = "\x1f"


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=40, **kwargs)


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def listen(process, path, text):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        data = path.read_text()
        match = re.search(re.escape(text) + r"127\.0\.0\.1:(\d+)", data)
        if match:
            return int(match.group(1))
        if process.poll() is not None:
            raise RuntimeError(data)
        time.sleep(.05)
    raise TimeoutError(path)


def decode_rows(decoded):
    return list(csv.DictReader(io.StringIO(decoded), delimiter='\t'))


def require(condition, message):
    # Verdicts must hold under `python -O` too, which strips assert statements.
    if not condition:
        raise AssertionError(message)


def check(rows, mode, origin, proxy):
    def initial_to(port):
        return [r['udp.payload'] for r in rows
                if r['udp.dstport'] == str(port)
                and '1' in r['tls.handshake.type'].split(OCCURRENCE_SEPARATOR)]
    origin_initial = initial_to(origin)
    if mode == 'forwarded':
        # CID-based state suppresses duplicate decoding at the egress tuple.
        # Every emitted datagram must come intact from the corresponding peer;
        # cancelled speculative ingress attempts need not reach the origin.
        ingress = Counter(r['udp.payload'] for r in rows if r['udp.dstport'] == str(proxy))
        upstream = Counter(r['udp.payload'] for r in rows if r['udp.dstport'] == str(origin))
        replies = Counter(r['udp.payload'] for r in rows if r['udp.srcport'] == str(origin))
        delivered = Counter(r['udp.payload'] for r in rows if r['udp.srcport'] == str(proxy))
        require(upstream and not (upstream - ingress), 'forwarded client datagram changed or duplicated')
        require(delivered and not (delivered - replies), 'forwarded reply changed or duplicated')
        origin_initial = list(upstream)
    require(origin_initial, 'no upstream ClientHello decoded or matched')
    require(any('200' in r['http3.headers.status'].split(OCCURRENCE_SEPARATOR) for r in rows), 'no H3 200 decoded')
    require(any(r['http3.settings.id'] for r in rows), 'no H3 SETTINGS decoded')
    require(any('h3' in r['tls.handshake.extensions_alpn_str'].split(OCCURRENCE_SEPARATOR) for r in rows), 'no h3 ALPN')
    if mode != 'direct':
        ingress_initial = initial_to(proxy)
        require(ingress_initial, 'no ingress ClientHello decoded')
        if mode == 'terminated':
            require(ingress_initial[0] != origin_initial[0], 'intercepted connection was forwarded')
            require(any(('x-rama-mitm', 'h3') in zip(r['http3.header.header.name'].split(OCCURRENCE_SEPARATOR), r['http3.headers.header.value'].split(OCCURRENCE_SEPARATOR)) for r in rows), 'no relay marker decoded')
    return {'mode': mode, 'packets': len(rows), 'upstream_datagrams_matched' if mode == 'forwarded' else 'upstream_client_hello_datagrams': len(origin_initial), 'passed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--interface', default='lo0' if sys.platform == 'darwin' else 'lo')
    args = parser.parse_args()
    args.bin_dir = args.bin_dir.resolve()
    args.output = args.output.resolve()
    args.output.mkdir(parents=True, exist_ok=False)
    cert, key = args.output/'origin.pem', args.output/'origin-key.pem'
    try:
        run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost',
             '-addext','subjectAltName=DNS:localhost','-keyout',str(key),'-out',str(cert)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        reports = []
        for mode in ['direct','forwarded','terminated']:
            directory = args.output/mode
            directory.mkdir()
            environment = dict(os.environ, RUST_LOG="info", SSLKEYLOGFILE=str(directory/'tls.keys'))
            processes, files = [], []
            marker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            marker.bind(("127.0.0.1", 0))
            marker_port = marker.getsockname()[1]
            def start(command, name):
                path = directory/name
                stream = path.open('w')
                files.append(stream)
                process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT, env=environment)
                processes.append(process)
                return process, path
            try:
                server, log = start([str(args.bin_dir/'http3_client_server'),'server','--listen','127.0.0.1:0','--cert',str(cert),'--key',str(key)], 'server.log')
                origin = listen(server, log, 'HTTP/3 listening on ')
                proxy = None
                trust = cert
                if mode != 'direct':
                    command = [str(args.bin_dir/'quic_h3_mitm_proxy'),'--listen','127.0.0.1:0','--upstream',f'127.0.0.1:{origin}','--upstream-ca',str(cert),'--ca-out',str(directory/'mitm.pem')]
                    if mode == 'terminated':
                        command += ['--intercept','localhost']
                        trust = directory/'mitm.pem'
                    relay, log = start(command, 'relay.log')
                    proxy = listen(relay, log, 'QUIC MITM proxy listening on ')
                capture, capture_log = start(['dumpcap','-i',args.interface,'-a','duration:5','-f',f'udp port {marker_port} or udp port {origin}' + (f' or udp port {proxy}' if proxy else ''),'-w',str(directory/'wire.pcapng')], 'dumpcap.log')
                deadline = time.monotonic() + 10
                while not ((directory/'wire.pcapng').exists() and 'File:' in capture_log.read_text()):
                    if capture.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(capture_log.read_text())
                    time.sleep(.05)
                marker.sendto(b'rama-wire-ready', ('127.0.0.1', marker_port))
                while 'Packets:' not in capture_log.read_text():
                    if capture.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('capture readiness marker was not observed')
                    time.sleep(.05)
                with (directory/'client.log').open('w') as output:
                    run([str(args.bin_dir/'http3_client_server'),'client','--ca',str(trust),'--url',f'https://localhost:{proxy or origin}/','--count','1'],stdout=output,stderr=subprocess.STDOUT,env=environment)
                capture.wait(timeout=10)
                if capture.returncode != 0:
                    raise RuntimeError(capture_log.read_text())
            finally:
                marker.close()
                for process in reversed(processes):
                    stop(process)
                for stream in files:
                    stream.close()
                if sys.exc_info()[0] is not None:
                    (directory/'tls.keys').unlink(missing_ok=True)
            fields = ['udp.srcport','udp.dstport','udp.payload','quic.version','tls.handshake.type','tls.handshake.extensions_alpn_str','http3.settings.id','http3.settings.value','http3.headers.status','http3.header.header.name','http3.headers.header.value']
            command = ['tshark','-r',str(directory/'wire.pcapng'),'-o',f'tls.keylog_file:{directory / "tls.keys"}','-d',f'udp.port=={origin},quic','-T','fields','-E','header=y','-E','quote=d','-E','separator=\t','-E',f'aggregator={OCCURRENCE_SEPARATOR}']
            if proxy:
                command += ['-d',f'udp.port=={proxy},quic']
            for field in fields:
                command += ['-e',field]
            try:
                decoded = run(command, capture_output=True, text=True).stdout
            finally:
                (directory/'tls.keys').unlink(missing_ok=True)
            (directory/'wire.tsv').write_text(decoded)
            rows = decode_rows(decoded)
            report = check(rows, mode, origin, proxy)
            controls = ['status', 'settings']
            if mode == 'forwarded':
                controls += ['client_payload', 'reply_payload']
            if mode == 'terminated':
                controls += ['marker']
            for control in controls:
                changed = copy.deepcopy(rows)
                if control in ('client_payload', 'reply_payload'):
                    field, port = ('udp.dstport', origin) if control == 'client_payload' else ('udp.srcport', proxy)
                    next(row for row in changed if row[field] == str(port))['udp.payload'] += '00'
                else:
                    field = {'status': 'http3.headers.status', 'settings': 'http3.settings.id', 'marker': 'http3.header.header.name'}[control]
                    for row in changed:
                        row[field] = ''
                try:
                    check(changed, mode, origin, proxy)
                except AssertionError:
                    pass
                else:
                    raise RuntimeError(f'{mode} oracle accepted negative control {control}')
            report['negative_controls_rejected'] = controls
            reports.append(report)
            print(json.dumps(reports[-1]), flush=True)
        (args.output/'report.json').write_text(json.dumps(reports,indent=2)+'\n')
    finally:
        key.unlink(missing_ok=True)


if __name__ == '__main__':
    if not __debug__:
        raise RuntimeError('Run without -O: this verification tool requires assertions')
    main()
