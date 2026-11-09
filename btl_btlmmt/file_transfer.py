"""Bounded file blocks, incremental SHA-256 and safe destination publication."""
import hashlib
import os
import re
import tempfile
import threading
import time
from pathlib import Path

FILE_BLOCK_SIZE = 256 * 1024
MAX_FILE_SIZE = 1024 * 1024 * 1024


def validate_file_id(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{32}', value) is None:
        raise ValueError('Invalid file transfer ID')
    return value


def validate_filename(name):
    if (not isinstance(name, str) or not 1 <= len(name) <= 120
            or name in ('.', '..') or name[-1] in ' .'
            or any(ord(c) < 32 or c in '<>:"/\\|?*' for c in name)
            or name.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL',
                                            *[f'COM{i}' for i in range(1, 10)],
                                            *[f'LPT{i}' for i in range(1, 10)]}):
        raise ValueError('Unsafe file name')
    return name


class FileReceiver:
    def __init__(self, directory, events, *, max_file_size=MAX_FILE_SIZE, timeout=60):
        self.directory = Path(directory).resolve()
        self.events = events
        self.max_file_size = max_file_size
        self.timeout = timeout
        self.active = {}
        self.lock = threading.RLock()
        self.closed = False

    def handle(self, header, body):
        with self.lock:
            if self.closed:
                raise ConnectionError('File receiver closed')
            transfer_id = validate_file_id(header.get('file_id'))
            sender = header['sender']
            session = header.get('sender_session')
            if not isinstance(session, str) or len(session) != 64:
                raise ValueError('Invalid sender session')
            key = (session, transfer_id)
            op = header['op']
            if op == 'file_begin':
                name = validate_filename(header.get('name'))
                size = header.get('size')
                if type(size) is not int or not 0 <= size <= self.max_file_size or body:
                    raise ValueError('Invalid file size or metadata')
                if len(self.active) >= 8 or key in self.active:
                    raise ValueError('Too many transfers or duplicate transfer ID')
                self.directory.mkdir(parents=True, exist_ok=True)
                target = self.directory / (transfer_id + '_' + name)
                if target.exists():
                    raise FileExistsError('Destination already exists')
                fd, temp = tempfile.mkstemp(prefix='.part-', dir=self.directory)
                self.active[key] = dict(file=os.fdopen(fd, 'wb'), temp=Path(temp),
                                        target=target, size=size, offset=0, sender=sender,
                                        digest=hashlib.sha256(), updated=time.monotonic())
                return {'file_id': transfer_id, 'offset': 0}
            state = self.active.get(key)
            if state is None:
                raise ValueError('Unknown file transfer')
            try:
                if op == 'file_block':
                    if (type(header.get('offset')) is not int or header['offset'] != state['offset']
                            or not 0 < len(body) <= FILE_BLOCK_SIZE
                            or state['offset'] + len(body) > state['size']):
                        raise ValueError('Invalid file block offset or size')
                    state['file'].write(body)
                    state['digest'].update(body)
                    state['offset'] += len(body)
                    state['updated'] = time.monotonic()
                    return {'file_id': transfer_id, 'offset': state['offset']}
                if op == 'file_end':
                    digest = state['digest'].hexdigest()
                    if body or state['offset'] != state['size'] or header.get('sha256') != digest:
                        raise ValueError('File size or SHA-256 mismatch')
                    if self.events.full():
                        raise BufferError('File event queue is full')
                    state['file'].flush()
                    os.fsync(state['file'].fileno())
                    state['file'].close()
                    # Atomic, no-overwrite publication (same directory/filesystem).
                    os.link(state['temp'], state['target'])
                    state['temp'].unlink()
                    del self.active[key]
                    result = {'type': 'file', 'sender': sender, 'file_id': transfer_id,
                              'path': str(state['target']), 'size': state['size'], 'sha256': digest}
                    self.events.put_nowait(result)
                    return {'file_id': transfer_id, 'size': state['size'], 'sha256': digest}
                if op == 'file_abort':
                    self._discard(key)
                    return {'file_id': transfer_id, 'aborted': True}
                raise ValueError('Unknown file operation')
            except (OSError, ValueError, BufferError):
                self._discard(key)
                raise

    def _discard(self, key):
        state = self.active.get(key)
        if state is not None:
            try:
                state['file'].close()
            finally:
                state['temp'].unlink(missing_ok=True)
            self.active.pop(key, None)

    def discard_sender(self, sender):
        with self.lock:
            for key, state in list(self.active.items()):
                if state['sender'] == sender:
                    self._discard(key)

    def expire(self):
        with self.lock:
            for key, state in list(self.active.items()):
                if time.monotonic() - state['updated'] >= self.timeout:
                    self._discard(key)

    def close(self):
        with self.lock:
            self.closed = True
            for key in list(self.active):
                self._discard(key)
