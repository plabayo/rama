"""Isolated Chrome H1 capture/export/replay; exact retained membership only."""
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import time
import sys

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

HERE = Path(__file__).resolve().parent
rama = Path(os.environ['RAMA_ROUNDTRIP_BINARY'])
require(os.environ['DATABASE_URL'] == os.environ['PR10_CAPTURE_DATABASE_URL'], 'database isolation')
require(os.environ['RAMA_FP_DATABASE_URL'] == os.environ['PR10_CAPTURE_DATABASE_URL'], 'fp database isolation')
require('host=127.0.0.1 ' in os.environ['DATABASE_URL'], 'loopback database required')
root = Path(os.environ['RAMA_ROUNDTRIP_OUTPUT'])
print(f'capture evidence: {root}', flush=True)
processes, streams = [], []

def start(command, name):
    path = root/name
    stream = path.open('w')
    streams.append(stream)
    process = subprocess.Popen(command, stdout=stream, stderr=subprocess.STDOUT,
                               env=dict(os.environ, RUST_LOG='info', NO_COLOR='1'), start_new_session=True)
    processes.append(process)
    (root/'processes.json').write_text(json.dumps([item.pid for item in processes]))
    return process, path

def ready(process, log, pattern):
    deadline = time.monotonic()+40
    while time.monotonic() < deadline:
        text = re.sub(r'\x1b\[[0-9;]*m', '', log.read_text())
        match = re.search(pattern, text)
        if match: return int(match.group(1))
        if process.poll() is not None: raise RuntimeError(text[-2000:])
        time.sleep(.05)
    raise TimeoutError(log)

def stop(process):
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGINT)
        try: process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)

def capture_wire(port, label):
    capture, log = start(['dumpcap', '-i', os.environ['RAMA_ROUNDTRIP_INTERFACE'], '-a', 'duration:60', '-f',
                          f'tcp port {port} or udp port {marker_port}',
                          '-w', str(root/(label+'.pcapng'))], label+'-dumpcap.log')
    deadline = time.monotonic()+10
    while not ((root/(label+'.pcapng')).exists() and 'File:' in log.read_text()):
        if capture.poll() is not None or time.monotonic()>deadline:
            raise RuntimeError('capture did not start')
        time.sleep(.02)
    marker.sendto(b'rama-h1-capture-ready', ('127.0.0.1', marker_port))
    while 'Packets:' not in log.read_text():
        if capture.poll() is not None or time.monotonic()>deadline:
            raise RuntimeError('capture readiness marker not seen')
        time.sleep(.02)
    return capture

def finish_capture(capture, label, port):
    # Fast CLI requests can finish before BPF's next buffer delivery. Wait for
    # the independent decoder to see the complete request before stopping.
    marker.sendto(b'rama-h1-capture-finished', ('127.0.0.1', marker_port))
    deadline = time.monotonic()+10
    while True:
        decoded = subprocess.run(['tshark', '-r', str(root/(label+'.pcapng')),
                                  '-d', f'tcp.port=={port},http', '-Y',
                                  'http.request.method == "GET" && http.request.uri == "/report"',
                                  '-T', 'fields', '-e', 'http.request.method'],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, timeout=3)
        if 'GET' in decoded.stdout:
            break
        if capture.poll() is not None or time.monotonic()>deadline:
            raise RuntimeError('packet capture did not receive the complete request')
        time.sleep(.05)
    stop(capture)
    require(capture.returncode == 0, 'capture failed')

marker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
marker.bind(('127.0.0.1', 0))
marker_port = marker.getsockname()[1]

def interrupted(number, _frame):
    raise InterruptedError(number)

signal.signal(signal.SIGINT, interrupted)
signal.signal(signal.SIGTERM, interrupted)

try:
    server, log = start([str(rama), 'serve', 'fp', '--bind', '127.0.0.1:0', '--http-version', 'h1'], 'fp.log')
    port = ready(server, log, r'network\.local\.port[= ]+(\d+)')
    reference_wire = capture_wire(port, 'reference-wire')
    browser, log = start([os.environ['RAMA_ROUNDTRIP_CHROME'], '--headless=new', '--remote-debugging-port=0', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check', f'--user-data-dir={root / "browser-profile"}'], 'chrome.log')
    active_port = root/'browser-profile/DevToolsActivePort'
    deadline = time.monotonic()+20
    while not active_port.exists():
        if browser.poll() is not None or time.monotonic() >= deadline: raise RuntimeError(log.read_text()[-2000:])
        time.sleep(.05)
    browser_port, browser_path = active_port.read_text().splitlines()[:2]
    result = subprocess.check_output(['node', str(HERE/'chrome_cdp.mjs'), f'ws://127.0.0.1:{browser_port}{browser_path}', f'http://127.0.0.1:{port}/report', str(root/'page.html')], text=True, timeout=40)
    result = json.loads(result)
    require('report' in (root/'page.html').read_text().lower(), 'fp page not rendered')
    stop(browser)
    stop(server)
    finish_capture(reference_wire, 'reference-wire', port)
    require(server.returncode == 0, 'fp capture did not drain')
    with (root/'export.log').open('w') as output:
        subprocess.run([str(rama), 'ua', 'export', '--output', str(root/'profiles.json')], check=True,
                       stdout=output, stderr=subprocess.STDOUT, timeout=30)
    archive = json.loads((root/'profiles.json').read_text())
    require(archive['profiles'], 'reference profile not captured')
    (root/'summary.json').write_text(json.dumps({'scope':'Chrome H1 capture/export and strict replay; see comparison.json for exact membership results', 'profiles':len(archive['profiles']), 'browser':result['browser']},indent=2)+'\n')
    print(f'Chrome H1 capture/export: {len(archive["profiles"])} profiles', flush=True)
    subprocess.run(['docker', 'exec', os.environ['PR10_TEST_PG_CONTAINER'], 'createdb', '-U', 'postgres', 'rama_fp_m5_replay'], check=True, timeout=10)
    source_dsn = os.environ['PR10_CAPTURE_DATABASE_URL']
    require('dbname=rama_fp_m5_test' in source_dsn, 'unexpected database identity')
    replay_dsn = source_dsn.replace('dbname=rama_fp_m5_test', 'dbname=rama_fp_m5_replay')
    for key in ['DATABASE_URL', 'RAMA_FP_DATABASE_URL', 'PR10_CAPTURE_DATABASE_URL']:
        os.environ[key] = replay_dsn
    replay, log = start([str(rama), 'serve', 'fp', '--bind', '127.0.0.1:0', '--http-version', 'h1'], 'fp-replay.log')
    replay_port = ready(replay, log, r'network\.local\.port[= ]+(\d+)')
    replay_wire = capture_wire(replay_port, 'replay-wire')
    with (root/'rama-replay.log').open('w') as output:
        subprocess.run([str(rama), 'send', f'--emulate={root / "profiles.json"}', '--http1.1', '--header', 'Connection: keep-alive', '--output', str(root/'replay-body.bin'), f'http://127.0.0.1:{replay_port}/report'], check=True, stdout=output, stderr=subprocess.STDOUT, timeout=30)
    stop(replay)
    finish_capture(replay_wire, 'replay-wire', replay_port)
    require(replay.returncode == 0, 'fp replay did not drain')
    with (root/'export-replay.log').open('w') as output:
        subprocess.run([str(rama), 'ua', 'export', '--output', str(root/'replay-profiles.json')], check=True, stdout=output, stderr=subprocess.STDOUT, timeout=30)
    replay_archive = json.loads((root/'replay-profiles.json').read_text())
    require(replay_archive['profiles'], 'no replay profile captured')
    with (root/'comparison.json').open('w') as output:
        subprocess.run([str(rama), 'ua', 'compare', '--literal', '--allow-partial-coverage', str(root/'profiles.json'), str(root/'replay-profiles.json')], check=True, stdout=output, timeout=30)
    subprocess.run([sys.executable, str(HERE/'compare_h1_wire.py'), str(root), str(port), str(replay_port)], check=True, timeout=20)

finally:
    marker.close()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, signal.SIG_IGN)
    for process in processes:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGINT)
    deadline = time.monotonic() + 10
    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=max(.01, deadline-time.monotonic()))
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
    for stream in streams: stream.close()
    import shutil
    shutil.rmtree(root/'browser-profile', ignore_errors=True)
