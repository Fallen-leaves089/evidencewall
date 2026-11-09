# EvidenceWall

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Status](https://img.shields.io/badge/status-public%20preview-orange.svg)

English | [中文](README.md)

> An independent, out-of-band, multi-endpoint (multi-IP, multi-port), evidence-first deception and traffic-attribution sensor.

EvidenceWall listens on decoy endpoints, records probing and scanning behavior, and uses signatures, hash chains, Legal Hold records, and Evidence Packages to support human review and later evidence preservation. It is designed for human-led handling: it does **not** auto-ban, actively scan, counter-attack, or take over production traffic.

## Project status

`0.4.0` adds a reliability-hardening pass on top of the first public release. The 39 automated tests pass on Python 3.10; CI is configured to cover Python 3.11 and 3.13 on Linux as well.

This is a **usable but not production-hardened public preview**. A real multi-IP, multi-port T0/T1 deployment has not yet been accepted. Current tests cover real local sockets, synthetic event correlation, and the Collector API; they do not prove that public-network topology, NAT, or proxy behavior has been validated.

## Features

- HTTP/1.1 decoy listener with bounded request parsing, request metadata, body hashing, socket addresses, header fingerprints, and tarpit timing.
- Generic TCP metadata listener with bounded first-payload capture and hashing instead of full payload retention.
- Built-in Profiles: `admin-panel`, `ollama`, `comfyui`, and `tcp-metadata`. Profiles are constrained JSON data, not executable plugins.
- Canary Groups with rotation, cross-endpoint deployment, matching, and signed incremental synchronization.
- Deterministic correlation across sources, endpoints, Canaries, fingerprints, targeted services, and a 24-hour sliding window.
- Manual case review (`new`, `reviewing`, `confirmed`, `dismissed`) with custody records.
- Legal Hold records, query, and explicit confirmation before release.
- Evidence Package directory/ZIP export with offline verification of file hashes, Collector and Sensor signatures, and the event hash chain.
- Optional Highwall audit-event import as supporting evidence only.
- Signed Sensor health reports with queue depth, buffer and disk usage, version, endpoint listening state, and Collector-side clock-skew detection.
- Fail-closed local buffering: event-count, byte, and free-disk limits pause decoy listeners instead of silently dropping older evidence. Acknowledged events retain only bounded local history.
- Fail-closed Collector identity loading: missing, incomplete, or mismatched Collector keys stop startup instead of silently creating a new identity.
- Evidence Package snapshots use one SQLite read transaction and reject inconsistent case summaries before export.
- Independent Collector Ed25519 identity; private keys are never placed in Evidence Packages.
- CLI and Collector API for enrollment, buffering, replay, cases, review, holds, export, verification, Canaries, and Highwall import.

## Quick start

The examples below set `--home` explicitly for local development. When omitted, the default data root is platform-specific and does not depend on the current project or a Codex workspace: `%LOCALAPPDATA%\EvidenceWall` on Windows, `$XDG_DATA_HOME/evidencewall` (or `~/.local/share/evidencewall`) on Linux, and `~/Library/Application Support/EvidenceWall` on macOS. Set `EVIDENCEWALL_HOME` to override the root; production deployments should pin `--home` explicitly.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .

evidencewall collector init --home .\evidencewall-data\collector
evidencewall collector run --home .\evidencewall-data\collector --host 127.0.0.1 --port 8787
```

On Linux/macOS, use `.venv/bin/python` for installation. In a second terminal, initialize the Sensor and an HTTP decoy:

```powershell
evidencewall sensor init --home .\evidencewall-data\sensor
evidencewall endpoint add --home .\evidencewall-data\sensor `
  --listen-ip 127.0.0.1 --listen-port 18080 `
  --advertised-ip 203.0.113.10 --advertised-port 18080 `
  --transport http1 --profile admin-panel --exposure nat
evidencewall canary create --home .\evidencewall-data\sensor --type admin-token
```

Read the one-time enrollment token printed by `collector init`, then enroll and run the Sensor:

```powershell
$enrollToken = Read-Host "Paste the one-time enrollment token"
$enrollToken | evidencewall sensor enroll --home .\evidencewall-data\sensor `
  --collector-url http://127.0.0.1:8787 --token-stdin
Remove-Variable enrollToken
evidencewall sensor run --home .\evidencewall-data\sensor
```

`sensor run --once` and `sensor run --flush-only` both perform one flush pass and exit without starting listeners. Sensors periodically send a signed health snapshot to `POST /v1/sensors/health`. The Collector reports `clock_skew_ms = sensor_sent_at - collector_now` and sets `clock_skew_exceeded` when the absolute value exceeds 60000 ms. Default buffer limits are 100000 unsent events, 512 MiB of buffer files, and 128 MiB of free disk. When SQLite retains a high-water file after deletion, the Sensor attempts safe compaction once the queue drops and continues blocking with a visible reason if compaction fails.

Verify the local decoy:

```powershell
curl.exe -i -H "Host: evil.example" http://127.0.0.1:18080/api/config
```

`203.0.113.10` is a documentation address. Replace it with the address actually exposed by your router or reverse proxy.

## Security boundaries

- The Collector binds to `127.0.0.1` by default. Binding a non-loopback address requires the explicit `--allow-remote` flag. The management API has no built-in administrator authentication; keep it on loopback or put it behind an authenticated, TLS-terminating proxy with source restrictions.
- The Highwall import endpoint is part of the management surface. Do not expose it without authentication and source restrictions.
- Collector transport is plain HTTP/1.1 and the code does not terminate TLS. Remote deployment must be protected by a controlled HTTPS reverse proxy.
- HTTP decoys do not terminate TLS. Trusted proxy headers are not treated as direct-source evidence.
- Sensor health reports must be signed by a registered Sensor key; unknown endpoints, matrix mismatches, and bad signatures are rejected and counted. Health data is operational telemetry, not case evidence.
- Buffer limits use fail-closed behavior: new events are rejected and listeners are paused at the limit, then resumed automatically after recovery. Acknowledged events are pruned to a bounded local retention window.
- Legal Hold currently records, audits, and requires explicit confirmation for release. **This release has no retention-deletion worker, so it does not claim that automatic deletion is reliably blocked.** Do not manually delete active held cases, events, or evidence packages; a future deletion worker must check active holds first.
- Real multi-IP, multi-port, NAT, and proxy topology has not yet been accepted. Do not treat local tests as public-network validation.
- Full request bodies, Cookies, Authorization headers, and real secrets are not retained; only bounded metadata and hashes are stored.
- EvidenceWall does not auto-ban, actively scan, counter-attack, or perform hack-back. Canary hits create evidence and alerts only.
- No UI, tray application, production traffic mirroring, or inline proxy is included.
- Highwall integration is optional and independent. Imported events do not create cases by themselves, do not write back blocking rules, and are not covered by an upstream Highwall signature.
- A Collector public key embedded in an Evidence Package only proves internal consistency. Adversarial or third-party verification must pin an external trusted key.
- On Windows, `os.chmod` cannot enforce a complete ACL. Atomic writes avoid torn files but do not replace directory ACLs; restrict the data directory to the intended service account.

## Development and testing

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
$env:PYTHONPATH = "src"
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution rules and [SECURITY.md](SECURITY.md) for private vulnerability reporting. Never paste real credentials, private keys, case data, or unredacted evidence packages into a public issue.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
