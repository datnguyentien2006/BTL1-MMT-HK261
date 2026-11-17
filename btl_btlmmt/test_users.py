import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from users import UserStore


class UserStoreTests(unittest.TestCase):
    def test_survives_reopening_and_updates_existing_user(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'nested' / 'users.sqlite3'
            store = UserStore(path)
            store.record_login('alice')
            first = store.list_users()[0]
            reopened = UserStore(path)
            reopened.record_login('alice')
            row = reopened.list_users()[0]
            self.assertEqual(row['username'], 'alice')
            self.assertEqual(row['created_at'], first['created_at'])
            self.assertGreaterEqual(row['last_login_at'], first['last_login_at'])
            self.assertEqual(row['login_count'], 2)
            self.assertEqual(len(reopened.list_users()), 1)

    def test_invalid_username_does_not_create_profile(self):
        with tempfile.TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / 'users.sqlite3')
            with self.assertRaises(ValueError):
                store.record_login("'; DROP TABLE users;--")
            self.assertEqual(store.list_users(), [])

    def test_concurrent_updates_preserve_login_count(self):
        with tempfile.TemporaryDirectory() as folder:
            store = UserStore(Path(folder) / 'users.sqlite3')
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(store.record_login, ['alice'] * 12))
            self.assertEqual(store.list_users()[0]['login_count'], 12)


if __name__ == '__main__':
    unittest.main()
