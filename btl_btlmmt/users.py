"""Persistent username profiles; this is not password authentication."""
import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3

from protocol import validate_username

DEFAULT_DB = Path(__file__).resolve().parent / 'data' / 'users.sqlite3'


class UserStore:
    def __init__(self, path=DEFAULT_DB):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db, db:
            db.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL,
                login_count INTEGER NOT NULL DEFAULT 1
            )''')

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=1)
        db.row_factory = sqlite3.Row
        return db

    def record_login(self, username):
        username = validate_username(username)
        with closing(self._connect()) as db, db:
            db.execute('''INSERT INTO users
                (username, created_at, last_login_at, login_count)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                           strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), 1)
                ON CONFLICT(username) DO UPDATE SET
                    last_login_at = excluded.last_login_at,
                    login_count = users.login_count + 1''', (username,))

    def list_users(self):
        with closing(self._connect()) as db:
            return [dict(row) for row in db.execute(
                'SELECT username, created_at, last_login_at, login_count '
                'FROM users ORDER BY username')]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='List saved username profiles (UTC timestamps)')
    parser.add_argument('--db', default=str(DEFAULT_DB))
    args = parser.parse_args()
    print(json.dumps(UserStore(args.db).list_users(), ensure_ascii=False, indent=2))
