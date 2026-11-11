"""Application requests over reliable UDP streams; never blocks the socket reader."""
import json
import queue
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field

MAGIC = b'COLLAB1\0'
MAX_HEADER = 8192


def encode(header, body=b''):
    # Đóng gói header JSON và dữ liệu thành bản tin có dấu nhận diện và độ dài header.
    metadata = json.dumps(header, ensure_ascii=True).encode('utf-8')
    if len(metadata) > MAX_HEADER:
        raise ValueError('Application header too large')
    return MAGIC + struct.pack('!I', len(metadata)) + metadata + body


def decode(data):
    # Kiểm tra định dạng, mã yêu cầu và loại bản tin, rồi tách header khỏi dữ liệu.
    if not data.startswith(MAGIC) or len(data) < len(MAGIC) + 4:
        raise ValueError('Invalid application envelope')
    size = struct.unpack_from('!I', data, len(MAGIC))[0]
    start = len(MAGIC) + 4
    if size > MAX_HEADER or len(data) < start + size:
        raise ValueError('Invalid application header length')
    header = json.loads(data[start:start + size].decode('utf-8'))
    if not isinstance(header, dict):
        raise ValueError('Application header must be an object')
    request_id = header.get('id')
    if (not isinstance(request_id, str) or len(request_id) != 32
            or any(c not in '0123456789abcdef' for c in request_id)):
        raise ValueError('Invalid request ID')
    if header.get('kind') not in ('request', 'result'):
        raise ValueError('Invalid application envelope kind')
    return header, data[start + size:]


class ApplicationError(Exception):
    pass


class ReceivedQueue(queue.Queue):
    """Raw-message consumers release the transport's memory reservation on get()."""
    def __init__(self, transport):
        # Tạo hàng đợi tối đa 16 bản tin và lưu transport để giải phóng bộ nhớ khi lấy tin.
        super().__init__(maxsize=16)
        self.transport = transport

    def _get(self):
        # Lấy bản tin khỏi hàng đợi và trả lại phần bộ nhớ transport đã giữ cho bản tin đó.
        item = super()._get()
        self.transport.release_received(item[0])
        return item


@dataclass
class PendingRequest:
    event: threading.Event = field(default_factory=threading.Event)
    error: Exception | None = None
    result: object = None


class Endpoint:
    """Ordered requests and independent result dispatch.

    Clients use a reader/worker pair. Servers supply a shared executor and call
    poll() from their UDP shard, creating no per-session application threads.

    request() runs on application callers/workers, never a socket thread. Requests
    are not automatically retried: transport deduplication provides one dispatch
    per stream, and a lost final response can leave delivery status uncertain.
    """
    def __init__(self, transport, handler, maintenance=lambda: None, *, executor=None):
        # Khởi tạo phiên; nếu không có executor dùng chung thì tạo luồng đọc và xử lý riêng.
        self.transport = transport
        self.handler = handler
        self.maintenance = maintenance
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.poll_lock = threading.RLock()
        self.pending: dict[str, PendingRequest] = {}
        self.requests = queue.Queue(maxsize=32)
        self.raw_messages = ReceivedQueue(transport)
        self.executor = executor
        self.scheduled = False
        self.held_raw = None
        self.queued_bytes = 0
        self.reader = self.worker = None
        if executor is None:
            self.reader = threading.Thread(target=self._read, daemon=True)
            self.worker = threading.Thread(target=self._work, daemon=True)
            self.reader.start()
            self.worker.start()

    def request(self, op, body=b'', timeout=15, **fields):
        # Gửi yêu cầu có ID riêng và chờ kết quả; báo lỗi nếu gửi thất bại, hết hạn hoặc phiên đóng.
        request_id = uuid.uuid4().hex
        item = PendingRequest()
        with self.lock:
            if self.stop.is_set():
                raise ConnectionError('Application session closed')
            if len(self.pending) >= 32:
                raise BufferError('Too many pending application requests')
            self.pending[request_id] = item
        try:
            receipt = self.transport.send(encode(
                {**fields, 'kind': 'request', 'id': request_id, 'op': op}, body))
            deadline = time.monotonic() + timeout
            while not item.event.wait(0.02):
                if receipt.done.is_set() and receipt.error is not None:
                    raise receipt.error
                if time.monotonic() >= deadline:
                    raise TimeoutError('Application response timed out; delivery may be uncertain')
            if item.error is not None:
                raise item.error
            return item.result
        finally:
            with self.lock:
                self.pending.pop(request_id, None)

    def _reply(self, request_id, result=None, error=None):
        # Gửi kết quả hoặc thông báo lỗi về phía gửi yêu cầu, dùng ID để ghép đúng phản hồi.
        header = {'kind': 'result', 'id': request_id, 'ok': error is None}
        if error is None:
            header['result'] = result
        else:
            header['error'] = str(error)[:512]
        try:
            self.transport.send(encode(header))
        except (OSError, ValueError, BufferError, OverflowError):
            pass  # Originating request gets a timeout / session-closed error.

    def _read(self):
        # Liên tục nhận dữ liệu: đưa bản tin thô vào hàng đợi, chuyển bản tin ứng dụng đi phân loại.
        while not self.stop.is_set():
            try:
                sid, data = self.transport.receive(timeout=0.1, retain=True)
            except queue.Empty:
                continue
            if not data.startswith(MAGIC):
                while not self.stop.is_set():
                    try:
                        self.raw_messages.put((sid, data), timeout=0.1)
                        break
                    except queue.Full:
                        continue
                else:
                    self.transport.release_received(sid)
                continue
            self._dispatch(sid, data)

    def _dispatch(self, sid, data):
        # Đánh thức yêu cầu đang chờ khi có kết quả, hoặc xếp yêu cầu nhận được vào hàng đợi xử lý.
        try:
            header, body = decode(data)
        except (ValueError, UnicodeError):
            self.transport.release_received(sid)
            return
        if header['kind'] == 'result':
            with self.lock:
                item = self.pending.get(header['id'])
                if item is not None:
                    if header.get('ok') is True:
                        item.result = header.get('result')
                    else:
                        item.error = ApplicationError(str(header.get('error', 'Request rejected')))
                    item.event.set()
            self.transport.release_received(sid)
        else:
            try:
                with self.lock:
                    if self.queued_bytes + len(body) > 2 * 1024 * 1024:
                        raise queue.Full
                    if self.stop.is_set():
                        raise queue.Full
                    self.requests.put_nowait((header, body, sid))
                    self.queued_bytes += len(body)
            except queue.Full:
                self._reply(header['id'], error='Recipient request queue is full')
                self.transport.release_received(sid)
            self._schedule()

    def poll(self, limit=32):
        """Nonblocking result dispatch for server UDP shards; no per-peer reader."""
        # Khóa lượt nhận để máy chủ đọc dữ liệu không chặn mà không cần luồng đọc riêng cho mỗi phiên.
        with self.poll_lock:
            self._poll(limit)

    def _poll(self, limit):
        # Nhận tối đa limit bản tin; tạm giữ bản tin thô nếu hàng đợi chưa có chỗ trống.
        for _ in range(limit):
            if self.stop.is_set():
                return
            if self.held_raw is not None:
                try:
                    self.raw_messages.put_nowait(self.held_raw)
                    self.held_raw = None
                except queue.Full:
                    return
            try:
                sid, data = self.transport.receive(timeout=0, retain=True)
            except queue.Empty:
                return
            if data.startswith(MAGIC):
                self._dispatch(sid, data)
            else:
                self.held_raw = (sid, data)

    def _schedule(self):
        # Đăng ký một lượt xử lý trên executor, tránh chạy đồng thời nhiều lượt trong cùng phiên.
        if self.executor is None:
            return
        with self.lock:
            if self.scheduled or self.stop.is_set() or self.requests.empty():
                return
            self.scheduled = True
        try:
            self.executor.submit(self._run_one)
        except RuntimeError:
            self.close()

    def _run_one(self):
        # Xử lý một yêu cầu rồi lên lịch lượt tiếp theo để giữ thứ tự và chia đều lượt chạy giữa các phiên.
        try:
            if not self.stop.is_set():
                header, body, sid = self.requests.get_nowait()
                self._handle(header, body, sid)
        except queue.Empty:
            pass
        finally:
            with self.lock:
                self.scheduled = False
            self._schedule()  # One request per turn preserves session order and fairness.

    def _handle(self, header, body, sid):
        # Gọi hàm xử lý nghiệp vụ, gửi phản hồi, giải phóng bộ nhớ nhận rồi chạy tác vụ bảo trì.
        with self.lock:
            self.queued_bytes -= len(body)
        try:
            result = self.handler(header, body)
            self._reply(header['id'], result=result)
        except (ApplicationError, OSError, ValueError, TypeError, BufferError, OverflowError, RuntimeError) as exc:
            self._reply(header['id'], error=exc)
        finally:
            self.transport.release_received(sid)
        self.maintenance()

    def _work(self):
        # Luồng xử lý riêng lần lượt lấy yêu cầu trong hàng đợi và chạy bảo trì khi chờ việc.
        while not self.stop.is_set():
            try:
                header, body, sid = self.requests.get(timeout=0.1)
            except queue.Empty:
                self.maintenance()
                continue
            self._handle(header, body, sid)

    def close(self):
        # Dừng phiên, báo lỗi cho các yêu cầu đang chờ và giải phóng dữ liệu nhận còn tồn đọng.
        self.stop.set()
        with self.lock:
            for item in self.pending.values():
                item.error = ConnectionError('Application session closed')
                item.event.set()
            while True:
                try:
                    _, body, sid = self.requests.get_nowait()
                except queue.Empty:
                    break
                self.queued_bytes -= len(body)
                self.transport.release_received(sid)
        while True:
            try:
                self.raw_messages.get_nowait()
            except queue.Empty:
                break
        with self.poll_lock:
            if self.held_raw is not None:
                self.transport.release_received(self.held_raw[0])
                self.held_raw = None

    def join(self):
        # Chờ các luồng riêng kết thúc tối đa một giây mỗi luồng và dọn dữ liệu nếu phiên đã đóng.
        for thread in (self.reader, self.worker):
            if thread is not None and thread is not threading.current_thread():
                thread.join(1)
        if self.stop.is_set():
            self.close()
