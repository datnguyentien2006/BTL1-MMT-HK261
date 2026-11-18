"""Disk-backed web uploads and an offline UDP delivery outbox."""
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import threading

from file_transfer import FileReceiver, validate_file_id, validate_filename
from protocol import validate_username


class UploadStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self._warned = set()

    def _read(self, job_id):
        validate_file_id(job_id)
        path = self.root / (job_id + '.json')
        try:
            return json.loads(path.read_text('utf-8'))
        except FileNotFoundError as exc:
            raise ValueError('Upload job not found') from exc
        except (OSError, ValueError) as exc:
            raise ValueError('Upload checkpoint is unreadable') from exc

    def save(self, job):
        FileReceiver._save_checkpoint(self.root / (job['id'] + '.json'), job)

    def jobs(self, sender=None):
        with self.lock:
            rows = []
            for path in self.root.glob('*.json'):
                try:
                    row = json.loads(path.read_text('utf-8'))
                    if not isinstance(row, dict) or not {'id', 'sender', 'state'} <= row.keys():
                        raise ValueError('Incomplete upload checkpoint')
                    if sender is None or row['sender'] == sender:
                        rows.append(row)
                except (OSError, ValueError, TypeError):
                    if path.name not in self._warned:
                        self._warned.add(path.name)
                        logging.warning('Ignoring unreadable upload checkpoint %s', path.name)
                    continue
            return rows

    # Keep completed jobs bounded; their files are already delivered and removed.
    def _prune_done(self, rows, keep=200):
        done = [row for row in rows if row['state'] == 'done']
        if len(done) <= keep:
            return rows
        def age(row):
            path = self.root / (row['id'] + '.json')
            try:
                return path.stat().st_mtime
            except OSError:
                return 0
        for row in sorted(done, key=age)[:len(done) - keep]:
            (self.root / (row['id'] + '.json')).unlink(missing_ok=True)
            shutil.rmtree(self.root / row['id'], ignore_errors=True)
            rows.remove(row)
        return rows

    def begin(self, sender, target, name, size, key):
        validate_username(sender)
        validate_username(target)
        validate_filename(name)
        validate_file_id(key)
        if type(size) is not int or not 0 <= size <= 1024 ** 3:
            raise ValueError('Maximum file size is 1 GiB')
        with self.lock:
            rows = self._prune_done(self.jobs())
            for row in rows:
                if row['sender'] == sender and row['key'] == key:
                    if (row['target'], row['filename'], row['total']) != (target, name, size):
                        raise ValueError('Resume file metadata changed')
                    return row
            active = [row for row in rows if row['state'] != 'done']
            if len(active) >= 1000 or sum(r['total'] for r in active) + size > 10 * 1024 ** 3:
                raise BufferError('Upload storage quota reached')
            job_id = secrets.token_hex(16)
            directory = self.root / job_id
            directory.mkdir()
            (directory / name).write_bytes(b'')
            row = dict(id=job_id, key=key, sender=sender, target=target, filename=name,
                       total=size, offset=0, sent=0, state='uploading', error=None)
            self._save_progress(row)
            return row

    def path(self, row):
        return self.root / row['id'] / row['filename']

    def chunk(self, sender, job_id, offset, data):
        with self.lock:
            row = self._read(job_id)
            if row['sender'] != sender:
                raise ValueError('Upload does not belong to this user')
            if type(offset) is not int or offset < 0 or not 0 < len(data) <= 256 * 1024:
                raise ValueError('Invalid upload chunk')
            if row['state'] != 'uploading' or offset + len(data) > row['total']:
                raise ValueError('Upload is already queued or chunk exceeds file size')
            with self.path(row).open('r+b') as output:
                if offset < row['offset']:
                    output.seek(offset)
                    if offset + len(data) > row['offset'] or output.read(len(data)) != data:
                        raise ValueError('Selected file does not match uploaded data')
                    return row
                if offset != row['offset']:
                    raise ValueError('Unexpected chunk offset')
                output.seek(offset)
                output.write(data)
                output.truncate()
                output.flush()
                os.fsync(output.fileno())
            row['offset'] += len(data)
            self._save_progress(row)
            return row

    def _save_progress(self, row):
        if row['offset'] == row['total']:
            row['state'] = 'waiting'
        self.save(row)

    def finish(self, sender, job_id):
        with self.lock:
            row = self._read(job_id)
            if row['sender'] != sender or row['offset'] != row['total']:
                raise ValueError('Upload is incomplete or belongs to another user')
            if row['state'] == 'uploading':
                self._save_progress(row)
            return row

    def update(self, job_id, **fields):
        with self.lock:
            row = self._read(job_id)
            row.update(fields)
            self.save(row)
            return row
