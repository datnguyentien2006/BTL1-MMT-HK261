"""Repeatable localhost load check; server metrics exclude the load-generator process.

Example: python scripts/benchmark_clients.py --clients 40 --file-mib 1 --output docs/performance/40-clients.json
Only standard library and the backend's runtime dependencies are required.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import platform
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def peak_rss_bytes():
    if sys.platform == 'win32':
        from ctypes import wintypes
        class Counters(ctypes.Structure):
            _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                        ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                        ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                        ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                        ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
        get_process = ctypes.windll.kernel32.GetCurrentProcess
        get_process.restype = wintypes.HANDLE
        read = ctypes.windll.psapi.GetProcessMemoryInfo
        read.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        if not read(get_process(), ctypes.byref(counters), counters.cb):
            raise ctypes.WinError()
        return counters.PeakWorkingSetSize
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == 'darwin' else peak * 1024


def serve(backend_root, cert, key, pipe):
    sys.path.insert(0, backend_root)
    from security import server_context
    from server import CollaborationServer
    errors = []
    threading.excepthook = lambda info: errors.append(repr(info.exc_value))
    server = CollaborationServer('127.0.0.1', 0, 0, tls_context=server_context(cert, key))
    thread = threading.Thread(target=server.start, name='collab-io')
    thread.start()
    if not server.ready.wait(10):
        pipe.send({'error': 'server failed to start', 'errors': errors})
        return
    pipe.send({'port': server.tcp_port})
    start_cpu = time.process_time()
    peak_threads = 0
    peak_peers = 0
    while thread.is_alive():
        peak_threads = max(peak_threads, threading.active_count())
        with server.peers_lock:
            peak_peers = max(peak_peers, len(server.active_peers))
        if pipe.poll(0.02):
            pipe.recv()
            break
    budget = getattr(server, 'buffer_budget', None)
    stats = {'server_peak_threads': peak_threads, 'server_peak_clients': peak_peers,
             'server_cpu_seconds': round(time.process_time() - start_cpu, 3),
             'server_peak_rss_mib': round(peak_rss_bytes() / 2 ** 20, 2),
             'transport_reserved_peak_mib': round(budget.peak / 2 ** 20, 2) if budget else None,
             'udp_queue_peak': getattr(server, 'udp_queue_peak', None),
             'udp_queue_drops': getattr(server, 'udp_dropped', None)}
    server.stop()
    thread.join(15)
    stats.update(server_stopped=not thread.is_alive(), thread_errors=errors)
    pipe.send(stats)
    pipe.close()


def percentile(values, fraction):
    return round(sorted(values)[min(len(values) - 1, int(len(values) * fraction))] * 1000, 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--clients', type=int, default=40)
    parser.add_argument('--file-mib', type=float, default=1)
    parser.add_argument('--backend-root', type=Path, default=ROOT / 'btl_btlmmt',
                        help='Optional isolated baseline checkout to compare')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not 2 <= args.clients <= 64 or not 0 < args.file_mib <= 32:
        parser.error('Use 2..64 clients and 0 < file-mib <= 32')
    sys.path.insert(0, str(args.backend_root.resolve()))
    from client import CollaborationClient
    from security import create_identity, client_context
    ctx = multiprocessing.get_context('spawn')
    with tempfile.TemporaryDirectory(prefix='collab-load-') as directory:
        temp = Path(directory)
        cert, key = create_identity(temp / 'keys')
        parent, child = ctx.Pipe()
        process = ctx.Process(target=serve, args=(str(args.backend_root.resolve()), cert, key, child))
        process.start()
        child.close()
        clients = []
        failure = None
        report = {'clients': args.clients, 'file_mib_each': args.file_mib,
                  'platform': platform.platform(), 'python': platform.python_version(),
                  'cpu_logical_count': os.cpu_count(), 'network': 'localhost',
                  'backend_root': str(args.backend_root.resolve())}
        try:
            if not parent.poll(15):
                raise TimeoutError('Server startup deadline')
            ready = parent.recv()
            if 'error' in ready:
                raise RuntimeError(ready)
            tls = client_context(cert)
            clients = [CollaborationClient(f'load{i:02d}', server_tcp_port=ready['port'], tls_context=tls,
                                           download_dir=temp / f'recv{i:02d}') for i in range(args.clients)]
            size = int(args.file_mib * 2 ** 20)
            content = (bytes(range(256)) * ((size + 255) // 256))[:size]
            source = temp / 'load.bin'
            source.write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            barrier = threading.Barrier(len(clients))
            with ThreadPoolExecutor(max_workers=len(clients)) as pool:
                list(pool.map(lambda client: client.connect_and_authenticate(), clients))
                deadline = time.monotonic() + 10
                while any(len(client.get_peers()) != len(clients) for client in clients):
                    if time.monotonic() > deadline:
                        raise AssertionError('Peers failed to converge')
                    time.sleep(0.02)
                def transfer(index):
                    client = clients[index]
                    target = clients[(index + 1) % len(clients)].username
                    barrier.wait(10)
                    start = time.monotonic()
                    result = client.send_chat(f'load-message-{index}', target, timeout=30)
                    if result['delivered'] != [target] or result['failed']:
                        raise AssertionError(result)
                    chat_latency = time.monotonic() - start
                    start = time.monotonic()
                    sent = client.send_file(source, target, timeout=30)
                    if sent['sha256'] != digest:
                        raise AssertionError('Sender result hash mismatch')
                    return chat_latency, time.monotonic() - start
                start = time.monotonic()
                timings = list(pool.map(transfer, range(len(clients))))
                elapsed = time.monotonic() - start
                for i, client in enumerate(clients):
                    chat = client.receive_chat(5)
                    if chat['text'] != f'load-message-{(i - 1) % len(clients)}':
                        raise AssertionError('Misrouted chat')
                    event = client.receive_file(5)
                    if hashlib.sha256(Path(event['path']).read_bytes()).hexdigest() != digest:
                        raise AssertionError('Received file hash mismatch')
                result = clients[0].send_chat('load broadcast', timeout=30)
                if len(result['delivered']) != len(clients) - 1 or result['failed']:
                    raise AssertionError(result)
                for client in clients[1:]:
                    if client.receive_chat(5)['text'] != 'load broadcast':
                        raise AssertionError('Broadcast missing')
                report.update(passed=True, file_hashes_verified=len(clients),
                              broadcast_delivered=len(clients) - 1, transfer_seconds=round(elapsed, 3),
                              useful_file_mib_per_second=round(len(clients) * size / 2 ** 20 / elapsed, 3),
                              chat_p50_ms=percentile([row[0] for row in timings], 0.5),
                              chat_p95_ms=percentile([row[0] for row in timings], 0.95),
                              file_p95_ms=percentile([row[1] for row in timings], 0.95))
        except Exception as exc:
            failure = exc
            report.update(passed=False, error=repr(exc))
        finally:
            with ThreadPoolExecutor(max_workers=16) as pool:
                list(pool.map(lambda client: client.close(), clients))
            if process.is_alive():
                parent.send('stop')
                if parent.poll(20):
                    report.update(parent.recv())
                process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
                report['server_stopped'] = False
            parent.close()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2))
        if failure or not report.get('server_stopped') or report.get('thread_errors'):
            raise SystemExit(1)


if __name__ == '__main__':
    main()
