# Backend and Web UI verification

Run from the repository root after `python -m pip install -r requirements.txt`:

```powershell
python -B -m unittest discover -s tests -v
npm exec --yes --package=pyright -- pyright btl_btlmmt
```

Python tests use ephemeral localhost ports, temporary directories and temporary
TLS certificates. They neither rely on a running server nor read production keys.
No external network service or admin packet-filter rule is needed. The test runner
captures uncaught worker-thread exceptions as failures in integration tests.

Latest local verification (10 November 2026): **52/52 tests passed** on Windows / Python 3.12 with
cryptography 50.0.2. Pyright reported **0 errors, 0 warnings** for `btl_btlmmt`;
`git diff --check` passed. CLI help for certificate setup, server and client was
also checked. These results describe this implementation, not a WAN benchmark.

## Coverage

| Area | Scenarios |
| --- | --- |
| Framing | Split/coalesced TCP frames, CRC corruption, length limits, extra bytes, malformed JSON |
| Sessions | Handshake ordering, duplicate login, reauthentication, ownership cleanup, live join/leave, heartbeat expiry |
| Concurrent clients | Paged snapshots; 20 and 40 concurrent TLS logins and ring-chat sends |
| Chat/files | Private/global routing, identity stamping, offline/full inbox, >8 MiB binary file, empty file, no overwrite, invalid path/offset/hash |
| Disconnects | Server shutdown, sender/recipient disconnect, partial-file deletion and idle expiry |
| Reliability | Dropped DATA/ACK/final ACK, reordered and duplicate packets, selective retries, independent streams, retry exhaustion, receive backpressure |
| Encryption | Max datagram size, plaintext absence, valid decrypt, changed header/tag rejection, wrong secret/session/direction |
| Key lifecycle | Counter uniqueness across retransmission, automatic epoch rotation, old epoch reordering, replay rejection, nonce budget, key expiry/close |
| TLS trust | Untrusted certificate and mismatched hostname rejected; real TLS 1.3 sessions |
| Congestion | cwnd growth/loss/recovery, RTT/RTO estimate, Karn sampling, pacing, aggregate budget across streams |
| HTTP bridge | Duplicate login, concurrent DM, broadcast under DATA/ACK loss, no CLI input, subprocess with closed stdin |
| Web file transfer | Real acknowledged-byte progress, original filename/hash, session-scoped download, invalid uploads and static paths |
| Multiplexed I/O | Silent TLS client, partial TCP frame, oversized header rejection, partial batched writes, bounded worker count |
| Memory/backpressure | Shared byte budget, retained application/raw queues, expiry/close cleanup, temporary send-buffer pressure, burst cap |

`test_security_congestion.py` includes a deterministic encrypted bidirectional
network simulation, seed 731: 6% probabilistic datagram loss, shuffled batches,
20% duplicate injection, and an intentionally corrupted ciphertext with a valid
CRC. It asserts identical complete messages, no duplicate delivery, successful
receipts, exercised drops/duplicates/authentication failures and loss response.
`test_backend.py` also drops actual UDP DATA/ACK datagrams while sending chat and
files through the real server. Loss tests validate correctness, not a benchmark.

The core unit simulator advances a fake clock; socket integration uses real time.
Integration heartbeat/expiry intervals are shortened to keep tests fast. The
production defaults remain 5-second heartbeats and 20-second liveness timeout.

## Browser smoke test

With Microsoft Edge installed, run this optional check from the repository root:

```powershell
python -m pip install playwright
python -B scripts/smoke_web_ui.py
```

The script launches headless Edge (`channel="msedge"`), a temporary TLS backend
and HTTP bridge, and two isolated browser sessions. It checks login, live peers,
unicast/broadcast, safe rendering of HTML-like message text, a 1 MiB upload with
real completion status, download filename/content, and logout/peer removal.
This browser check passed locally. The screenshot is
[web-ui-smoke.png](images/web-ui-smoke.png). Playwright is optional tooling, not
a runtime dependency. This is separate from the 52 unittest cases above.

For a manual test, follow the root README and open two independently logged-in
tabs at `http://127.0.0.1:5000`. Send a DM, a broadcast and a file; log out one tab
and verify the other peer list updates. A backend shutdown must return both tabs
to login after the bridge observes the disconnect. No CLI input is required.

## 20/40-client load checks

```powershell
python -B scripts/benchmark_clients.py --clients 20 --file-mib 1 --output docs/performance/20-clients.json
python -B scripts/benchmark_clients.py --clients 40 --file-mib 1 --output docs/performance/40-clients.json
```

Each client sends a private chat and a 1 MiB file to the next client in a ring.
All senders start together. The script checks every file hash, one broadcast to
all other peers, convergence of peer lists and clean shutdown. The server runs
in a separate process; its peak thread count/RSS and CPU time exclude the client
load generator. Client processes still share the same host and network stack.
`--backend-root PATH` can run the same check against an isolated baseline checkout.
See [PERFORMANCE.md](PERFORMANCE.md) for results and limits. These are separate
from the unit/integration suite; no timing thresholds are asserted in unittest.

## Rebuild the technical report

```powershell
python -m pip install -r requirements-docs.txt
python scripts/build_report.py
```

This renders `report/REPORT.md` plus vector architecture/sequence diagrams to
`report/Technical_Report.pdf` (five pages, including Challenges & Solutions).
The builder embeds Windows Arial for Vietnamese text. On other systems, set
`REPORT_FONT_DIR` to a directory containing `DejaVuSans.ttf` and
`DejaVuSans-Bold.ttf`. The generated PDF was rendered and inspected locally.

## Scope and limits

Validation is on Windows localhost with Python 3.12. Cross-platform code paths
are present, but macOS/Linux, real LAN/VPN/NAT and WAN bandwidth/fairness have not
been measured here. No claim of full RFC 9438 conformance, independent cryptographic
audit or sustained production load capacity follows from these tests.

Use the README's certificate provisioning steps for separate-machine testing.
Do not disable trust verification to make a connection succeed; the server IP/DNS
must be in its certificate and the client must trust that certificate explicitly.
