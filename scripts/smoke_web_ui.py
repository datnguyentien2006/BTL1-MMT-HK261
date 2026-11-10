"""Optional real-browser smoke test: pip install playwright; uses installed Edge.
Run from repository root: python -B scripts/smoke_web_ui.py
"""
from functools import partial
from pathlib import Path
import sys
import tempfile
import threading

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'btl_btlmmt'))
from client import CollaborationClient
from security import create_identity, client_context, server_context
from server import CollaborationServer
from web_ui.server_web import Bridge, WebHTTPServer
from playwright.sync_api import sync_playwright, expect


def main():
    with tempfile.TemporaryDirectory() as temp:
        cert, key = create_identity(Path(temp) / 'keys')
        backend = CollaborationServer('127.0.0.1', 0, 0, tls_context=server_context(cert, key))
        backend_thread = threading.Thread(target=backend.start)
        backend_thread.start()
        assert backend.ready.wait(3)
        bridge = Bridge(partial(CollaborationClient, server_tcp_port=backend.tcp_port,
                                 tls_context=client_context(cert)), Path(temp) / 'received')
        web = WebHTTPServer(('127.0.0.1', 0), bridge)
        web_thread = threading.Thread(target=web.serve_forever)
        web_thread.start()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(channel='msedge', headless=True)
                contexts = [browser.new_context(viewport={'width': 1440, 'height': 900}) for _ in range(2)]
                alice, bob = [context.new_page() for context in contexts]
                errors = []
                for page, username in ((alice, 'alice'), (bob, 'bob')):
                    page.on('pageerror', lambda error: errors.append(str(error)))
                    page.goto(f'http://127.0.0.1:{web.server_port}')
                    page.locator('#login-username').fill(username)
                    page.locator('#login-button').click()
                    expect(page.locator('#chat-screen')).to_be_visible()
                expect(alice.locator('#peer-count')).to_have_text('2')
                alice.locator('.peer-item').filter(has_text='bob').click()
                message = '<img src=x onerror=alert(1)> chat safely rendered'
                alice.locator('#message-input').fill(message)
                alice.locator('#send-button').click()
                bob.locator('.peer-item').filter(has_text='alice').click()
                expect(bob.locator('.msg-bubble')).to_have_text(message)
                assert bob.locator('#chat-messages img').count() == 0
                alice.locator('.peer-item').first.click()
                alice.locator('#message-input').fill('broadcast browser test')
                alice.locator('#send-button').click()
                bob.locator('.peer-item').first.click()
                expect(bob.locator('.msg-bubble')).to_have_text('broadcast browser test')
                alice.locator('.peer-item').filter(has_text='bob').click()
                content = bytes(range(256)) * 4096
                alice.locator('#file-input').set_input_files({'name': 'gui_up.bin',
                    'mimeType': 'application/octet-stream', 'buffer': content})
                alice.locator('#upload-button').click()
                expect(alice.locator('#progress-state')).to_have_text('Hoàn tất', timeout=30000)
                expect(alice.locator('#progress-percent')).to_have_text('100%')
                bob.locator('.peer-item').filter(has_text='alice').click()
                with bob.expect_download() as download_info:
                    bob.get_by_role('button', name='Tải file: gui_up.bin').click()
                download = download_info.value
                assert download.suggested_filename == 'gui_up.bin'
                target = Path(temp) / 'downloaded.bin'
                download.save_as(target)
                assert target.read_bytes() == content
                images = ROOT / 'docs/images'
                images.mkdir(exist_ok=True)
                alice.screenshot(path=str(images / 'web-ui-smoke.png'), full_page=True)
                bob.get_by_role('button', name='Đăng Xuất').click()
                expect(bob.locator('#login-screen')).to_be_visible()
                expect(alice.locator('#peer-count')).to_have_text('1')
                assert not errors, errors
                browser.close()
                print('PASS browser: login, live peers, unicast/broadcast, safe text, upload progress, download hash/name, logout')
        finally:
            web.shutdown()
            web.server_close()
            web_thread.join(3)
            bridge.close()
            backend.stop()
            backend_thread.join(7)


if __name__ == '__main__':
    main()
