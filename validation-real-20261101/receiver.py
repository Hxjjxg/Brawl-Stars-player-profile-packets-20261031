"""Loopback-only JSONL/BIN receiver. Standard Python library; no Frida dependency."""
import argparse
import datetime as dt
import hmac
import json
from pathlib import Path
import re
import secrets
import socket
import socketserver
import struct
import threading

BASE = Path(__file__).resolve().parent
PROTOCOL = 'lasercn-jsonl-v1'
MAX_BODY = 4 * 1024 * 1024
MAX_LINE = MAX_BODY * 2 + 65536
IDS = {15081: 'c2s', 24113: 's2c'}


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def read_record(stream, limit=MAX_LINE):
    line = stream.readline(limit + 1)
    if not line:
        return None
    if len(line) > limit or not line.endswith(b'\n'):
        raise ValueError('oversized-or-incomplete-record')
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError('record-must-be-object')
    return value


class Receiver(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, config):
        self.config = config
        self.folder = BASE / config.get('output', 'captures')
        self.folder.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(4)
        self.state = {'service': PROTOCOL, 'listening': True, 'connections': 0, 'activeConnections': 0, 'frames': 0,
                      'lastSession': None, 'lastPhase': None, 'lastError': None}
        super().__init__(('127.0.0.1', config['port']), Handler)

    def update(self, **values):
        with self.lock:
            self.state.update(values)
            (BASE / 'receiver-state.json').write_bytes(encoded(self.state))

    def snapshot(self):
        with self.lock:
            return dict(self.state)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        # Never log an exception that could echo an incoming credential/payload.
        self.update(lastError='client-handler-failed')


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(30)
        files = {}
        log = None
        summary = None
        try:
            hello = read_record(self.rfile, 4096)
            token = hello.get('token') if hello else None
            if not isinstance(token, str) or not hmac.compare_digest(token, self.server.config['token']):
                raise ValueError('authentication-failed')
            if hello.get('kind') == 'control':
                action = hello.get('action')
                if action not in ('status', 'stop'):
                    raise ValueError('invalid-control-action')
                self.wfile.write(encoded(self.server.snapshot()))
                if action == 'stop':
                    threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            stem = hello.get('sessionStem', '')
            if hello.get('kind') != 'hello' or hello.get('protocol') != PROTOCOL or not re.fullmatch(
                    r'lasercn-plain-\d{10,16}-\d{1,10}', stem):
                raise ValueError('invalid-handshake')
            folder = self.server.folder / (stem + '-' + secrets.token_hex(4))
            folder.mkdir(exist_ok=False)
            log = (folder / (stem + '.jsonl')).open('xb')
            summary = {'frames': 0, 'countsById': {}, 'session': str(folder), 'closed': False,
                       'lastPhase': 'connected', 'lastError': None}
            (folder / 'summary.json').write_bytes(encoded(summary))
            self.server.update(lastSession=str(folder), lastPhase='connected', lastError=None)
            with self.server.lock:
                self.server.state['connections'] += 1
                self.server.state['activeConnections'] += 1
            self.wfile.write(encoded({'kind': 'ready', 'protocol': PROTOCOL}))
            print('PHONE CONNECTED: ' + str(folder), flush=True)
            while True:
                record = read_record(self.rfile)
                if record is None:
                    break
                kind = record.get('kind')
                if kind == 'frame':
                    mid, version = record.get('id'), record.get('version')
                    size, sequence = record.get('length'), record.get('sequence')
                    if type(mid) is not int or mid not in IDS or type(version) is not int or not 0 <= version <= 65535:
                        raise ValueError('invalid-frame-id-or-version')
                    if record.get('direction') != IDS[mid] or sequence != summary['frames'] + 1:
                        raise ValueError('invalid-frame-direction-or-sequence')
                    if type(size) is not int or not 0 <= size <= MAX_BODY:
                        raise ValueError('invalid-body-length')
                    body_hex = record.get('bodyHex')
                    if not isinstance(body_hex, str) or len(body_hex) != size * 2 or not re.fullmatch('[0-9a-fA-F]*', body_hex):
                        raise ValueError('invalid-body-hex')
                    body = bytes.fromhex(body_hex)
                    name = stem + '-' + IDS[mid] + '-' + str(mid) + '.bin'
                    if record.get('binaryFile') != name or record.get('binaryLength') != size + 7:
                        raise ValueError('invalid-binary-reference')
                    if name not in files:
                        files[name] = (folder / name).open('xb')
                    binary = files[name]
                    if record.get('binaryOffset') != binary.tell():
                        raise ValueError('invalid-binary-offset')
                    binary.write(struct.pack('>H', mid) + size.to_bytes(3, 'big') + struct.pack('>H', version) + body)
                    binary.flush()
                    log.write(encoded(record)); log.flush()
                    summary['frames'] += 1
                    key = str(mid)
                    summary['countsById'][key] = summary['countsById'].get(key, 0) + 1
                    with self.server.lock:
                        self.server.state['frames'] += 1
                    self.wfile.write(encoded({'kind': 'ack', 'frames': summary['frames']}))
                elif kind in ('session', 'status', 'event', 'stop'):
                    if 'token' in record:
                        raise ValueError('unexpected-token-in-capture')
                    log.write(encoded(record)); log.flush()
                    if kind in ('status', 'stop'):
                        summary['lastPhase'] = record.get('phase')
                        self.server.update(lastPhase=summary['lastPhase'])
                    if kind == 'stop':
                        break
                else:
                    raise ValueError('unknown-record-kind')
                (folder / 'summary.json').write_bytes(encoded(summary))
        except (ValueError, OSError, UnicodeError) as error:
            # Error category only: never echo untrusted text, tokens, or plaintext.
            reason = 'record-or-connection-error:' + type(error).__name__
            self.server.update(lastError=reason)
            if summary is not None:
                summary['lastError'] = reason
            print(reason, flush=True)
        finally:
            for file in files.values():
                file.close()
            if log:
                log.close()
            if summary is not None:
                summary['closed'] = True
                (Path(summary['session']) / 'summary.json').write_bytes(encoded(summary))
                with self.server.lock:
                    self.server.state['activeConnections'] -= 1
                self.server.update(lastPhase='disconnected')
                print('PHONE DISCONNECTED; saved frames=' + str(summary['frames']), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=BASE / 'receiver-config.json')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--serve', action='store_true')
    group.add_argument('--status', action='store_true')
    group.add_argument('--stop', action='store_true')
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding='utf-8'))
    if not re.fullmatch('[0-9a-f]{64}', config['token']) or not 1024 <= config['port'] <= 65535:
        raise SystemExit('Invalid receiver config')
    if not args.serve:
        with socket.create_connection(('127.0.0.1', config['port']), timeout=3) as connection:
            connection.sendall(encoded({'kind': 'control', 'token': config['token'],
                                        'action': 'stop' if args.stop else 'status'}))
            print(json.dumps(read_record(connection.makefile('rb'), 65536), ensure_ascii=False))
        return
    with Receiver(config) as server:
        server.update(port=config['port'], output=str(server.folder))
        print(f'LISTENING 127.0.0.1:{config["port"]}; Python sockets only; no Frida. Output: {server.folder}', flush=True)
        try:
            server.serve_forever(poll_interval=0.2)
        except KeyboardInterrupt:
            pass
        finally:
            server.update(listening=False)


if __name__ == '__main__':
    main()
