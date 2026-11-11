import os
import socket
import sys
import json
import base64
import uuid
import time
import threading
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from client import CollaborationClient


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip


class WebClientBridge(CollaborationClient):
    def __init__(self, username: str):
        super().__init__(username)
        self.message_history = []
        self.history_lock = threading.Lock()
        # Lưu tiến độ truyền: task_id -> {"progress": int, "status": str, "filename": str}
        self.file_transfers = {}
        self.transfers_lock = threading.Lock()

    def _handle_chat_packet(self, pkt):
        super()._handle_chat_packet(pkt)
        data = pkt.decode_json()
        sender = data.get("sender")
        content = data.get("content")
        target_user = data.get("target_user")
        is_broadcast = (pkt.msg_type == 0x31)

        with self.history_lock:
            self.message_history.append({
                "sender": sender,
                "target": "all" if is_broadcast else (target_user if target_user else self.username),
                "content": content,
                "type": "broadcast" if is_broadcast else "unicast",
                "time": time.strftime("%H:%M")
            })

    def _handle_file_chunk(self, pkt):
        stream_id = pkt.stream_id
        f_info = self.active_file_receivers.get(stream_id)
        is_completing = False
        filename = ""
        sender = ""

        if f_info:
            if len(f_info["chunks"]) + 1 == f_info["total_chunks"]:
                is_completing = True
                filename = f_info["filename"]
                sender = f_info["sender"]

        super()._handle_file_chunk(pkt)

        if is_completing:
            with self.history_lock:
                self.message_history.append({
                    "sender": sender,
                    "target": self.username,
                    "content": f"📎 Đã nhận tệp: {filename}",
                    "type": "file",
                    "filename": filename,
                    "time": time.strftime("%H:%M")
                })


active_sessions = {}
sessions_lock = threading.Lock()


class HTTPRequestHandler(SimpleHTTPRequestHandler):
    def get_client_session(self):
        session_id = self.headers.get('X-Session-ID')
        if session_id:
            with sessions_lock:
                return active_sessions.get(session_id)
        return None

    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path

        if path in ("/", "/index.html"):
            self.path = "/templates/index.html"
            return super().do_GET()

        elif path == "/api/status":
            client = self.get_client_session()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            if not client or not client.is_running:
                data = {"logged_in": False}
            else:
                with client.history_lock:
                    msgs = list(client.message_history)
                data = {
                    "logged_in": True,
                    "username": client.username,
                    "peers": [{"user": u, "ip": info["ip"], "udp_port": info["udp_port"]} for u, info in client.peers.items()],
                    "messages": msgs
                }
            self.wfile.write(json.dumps(data).encode("utf-8"))
            return

        elif path == "/api/progress":
            client = self.get_client_session()
            task_id = self.headers.get('X-Task-ID')
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            if not client or not task_id:
                self.wfile.write(json.dumps({"progress": 0, "status": "unknown"}).encode("utf-8"))
                return

            with client.transfers_lock:
                info = client.file_transfers.get(task_id, {"progress": 0, "status": "idle"})
            self.wfile.write(json.dumps(info).encode("utf-8"))
            return

        return super().do_GET()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        if path == "/api/login":
            try:
                data = json.loads(body.decode("utf-8"))
                username = data.get("username", "").strip()
                if not username:
                    raise ValueError("Tên đăng nhập không được rỗng")

                new_client = WebClientBridge(username)
                
                # KHỞI CHẠY LUỒNG NỀN TRỰC TIẾP, KHÔNG CHẠY CLI LOOP
                if not new_client.start_background():
                    raise ConnectionError("Không thể xác thực hoặc username đã tồn tại.")

                session_id = str(uuid.uuid4())
                with sessions_lock:
                    active_sessions[session_id] = new_client

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "session_id": session_id}).encode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": str(e)}).encode("utf-8"))
            return

        elif path == "/api/logout":
            session_id = self.headers.get('X-Session-ID')
            if not session_id and body:
                try:
                    body_data = json.loads(body.decode("utf-8"))
                    session_id = body_data.get("session_id")
                except Exception:
                    pass

            if session_id:
                with sessions_lock:
                    client = active_sessions.pop(session_id, None)
                    if client:
                        client.stop()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return

        client = self.get_client_session()
        if not client or not client.is_running:
            self.send_response(401)
            self.end_headers()
            return

        if path == "/api/send":
            try:
                data = json.loads(body.decode("utf-8"))
                target = data.get("target")
                message = data.get("message")

                client.send_chat_message(target, message)

                if target != client.username:
                    with client.history_lock:
                        client.message_history.append({
                            "sender": client.username,
                            "target": target,
                            "content": message,
                            "type": "broadcast" if target.lower() == "all" else "unicast",
                            "time": time.strftime("%H:%M")
                        })

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        elif path == "/api/upload":
            try:
                data = json.loads(body.decode("utf-8"))
                target = data.get("target")
                original_filename = data.get("filename")
                filedata_b64 = data.get("filedata")
                task_id = str(uuid.uuid4())

                temp_dir = "temp_uploads"
                os.makedirs(temp_dir, exist_ok=True)
                temp_path = os.path.join(temp_dir, f"tmp_{task_id}.bin")

                with open(temp_path, "wb") as f:
                    f.write(base64.b64decode(filedata_b64))

                with client.transfers_lock:
                    client.file_transfers[task_id] = {
                        "progress": 0,
                        "status": "transferring",
                        "filename": original_filename
                    }

                def update_progress(sent_chunks, total_chunks):
                    pct = int((sent_chunks / total_chunks) * 100)
                    with client.transfers_lock:
                        if task_id in client.file_transfers:
                            client.file_transfers[task_id]["progress"] = pct

                def upload_worker():
                    # Truyền original_filename làm custom_filename
                    ok = client.send_file(
                        target_user=target,
                        file_path=temp_path,
                        custom_filename=original_filename,
                        progress_callback=update_progress
                    )
                    with client.transfers_lock:
                        if task_id in client.file_transfers:
                            client.file_transfers[task_id]["status"] = "completed" if ok else "failed"
                            client.file_transfers[task_id]["progress"] = 100 if ok else 0
                    try:
                        os.remove(temp_path)
                    except OSError:
                        pass

                threading.Thread(target=upload_worker, daemon=True).start()

                if target != client.username:
                    with client.history_lock:
                        client.message_history.append({
                            "sender": client.username,
                            "target": target,
                            "content": f"📎 Đã gửi tệp: {original_filename}",
                            "type": "file",
                            "filename": original_filename,
                            "time": time.strftime("%H:%M")
                        })

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"success": True, "task_id": task_id}).encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

    def translate_path(self, path):
        root = os.path.dirname(os.path.abspath(__file__))
        path = super().translate_path(path)
        relpath = os.path.relpath(path, os.getcwd())
        return os.path.join(root, relpath)


def run_web_server(http_port: int = 5000):
    local_ip = get_local_ip()
    httpd = ThreadingHTTPServer(('0.0.0.0', http_port), HTTPRequestHandler)
    print(f"[WEB PORTAL] Sẵn sàng tại: http://{local_ip}:{http_port}\n", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[WEB PORTAL] Dừng máy chủ...")
        with sessions_lock:
            for c in active_sessions.values():
                c.stop()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    run_web_server(port)