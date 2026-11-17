"""Disk-backed web uploads and an offline UDP delivery outbox."""
import hashlib
import json
from pathlib import Path
import secrets
import threading

from file_transfer import FileReceiver, validate_file_id, validate_filename
from protocol import validate_username


class UploadStore:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()

    def _read(self, job_id):
        validate_file_id(job_id)
        return json.loads((self.root / (job_id + '.json')).read_text('utf-8'))

    def save(self, job):
        FileReceiver._save_checkpoint(self.root / (job['id'] + '.json'), job)

    def jobs(self, sender=None):
        with self.lock:
            rows = [json.loads(p.read_text('utf-8')) for p in self.root.glob('*.json')]
            return [r for r in rows if sender is None or r['sender'] == sender]

    def begin(self, sender, target, name, size, key):
        validate_username(sender)
        validate_username(target)
        validate_filename(name)
        validate_file_id(key)
        if type(size) is not int or not 0 <= size <= 1024 ** 3:
            raise ValueError('Maximum file size is 1 GiB')
        with self.lock:
            rows = self.jobs()
            for row in rows:
                if row['sender'] == sender and row['key'] == key:
                    if (row['target'], row['filename'], row['total']) != (target, name, size):
                        raise ValueError('Resume file metadata changed')
                    return row
            if len(rows) >= 1000 or sum(r['total'] for r in rows if r['state'] != 'done') + size > 10 * 1024 ** 3:
                raise BufferError('Upload storage quota reached')
            job_id = secrets.token_hex(16)
            directory = self.root / job_id
            directory.mkdir()
            (directory / name).write_bytes(b'')
            row = dict(id=job_id, key=key, sender=sender, target=target, filename=name,
                       total=size, offset=0, sent=0, state='uploading', error=None)
            self.save(row)
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
                import os
                os.fsync(output.fileno())
            row['offset'] += len(data)
            self.save(row)
            return row

    def finish(self, sender, job_id):
        with self.lock:
            row = self._read(job_id)
            if row['sender'] != sender or row['offset'] != row['total']:
                raise ValueError('Upload is incomplete or belongs to another user')
            if row['state'] == 'uploading':
                with self.path(row).open('rb') as source:
                    row['sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
                row['state'] = 'waiting'
                self.save(row)
            return row

    def update(self, job_id, **fields):
        with self.lock:
            row = self._read(job_id)
            row.update(fields)
            self.save(row)
            return row
