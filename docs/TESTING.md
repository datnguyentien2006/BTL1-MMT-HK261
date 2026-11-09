# Backend verification

Run from the repository root after `python -m pip install -r requirements.txt`:

```powershell
python -B -m unittest discover -s tests -v
npm exec --yes --package=pyright -- pyright btl_btlmmt
```

Python tests use ephemeral localhost ports, temporary directories and temporary
TLS certificates. They neither rely on a running server nor read production keys.
No external network service or admin packet-filter rule is needed. The test runner
captures uncaught worker-thread exceptions as failures in integration tests.

Latest local verification: **40/40 tests passed** on Windows / Python 3.12 with
cryptography 50.0.2. Pyright reported **0 errors, 0 warnings** for `btl_btlmmt`;
`git diff --check` passed. CLI help for certificate setup, server and client was
also checked. These results describe this implementation, not a WAN benchmark.

## Coverage

| Area | Scenarios |
| --- | --- |
| Framing | Split/coalesced TCP frames, CRC corruption, length limits, extra bytes, malformed JSON |
| Sessions | Handshake ordering, duplicate login, reauthentication, ownership cleanup, live join/leave, heartbeat expiry |
| Concurrent clients | 20 online peers and paged snapshots; 20 concurrent TLS logins and ring-chat sends |
| Chat/files | Private/global routing, identity stamping, offline/full inbox, >8 MiB binary file, empty file, no overwrite, invalid path/offset/hash |
| Disconnects | Server shutdown, sender/recipient disconnect, partial-file deletion and idle expiry |
| Reliability | Dropped DATA/ACK/final ACK, reordered and duplicate packets, selective retries, independent streams, retry exhaustion, receive backpressure |
| Encryption | Max datagram size, plaintext absence, valid decrypt, changed header/tag rejection, wrong secret/session/direction |
| Key lifecycle | Counter uniqueness across retransmission, automatic epoch rotation, old epoch reordering, replay rejection, nonce budget, key expiry/close |
| TLS trust | Untrusted certificate and mismatched hostname rejected; real TLS 1.3 sessions |
| Congestion | cwnd growth/loss/recovery, RTT/RTO estimate, Karn sampling, pacing, aggregate budget across streams |

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

## Scope and limits

Validation is on Windows localhost with Python 3.12. Cross-platform code paths
are present, but macOS/Linux, real LAN/VPN/NAT and WAN bandwidth/fairness have not
been measured here. No claim of full RFC 9438 conformance, independent cryptographic
audit or sustained production load capacity follows from these tests.

Use the README's certificate provisioning steps for separate-machine testing.
Do not disable trust verification to make a connection succeed; the server IP/DNS
must be in its certificate and the client must trust that certificate explicitly.
