"""
encoder_decoder.py — Multi-Format Encode/Decode Utility
Supports: Base64, Hex, URL encoding, ROT13, HTML entities, Binary, MD5/SHA hashing.

Usage:
    python encoder_decoder.py encode base64 "Hello World"
    python encoder_decoder.py decode hex "48656c6c6f"
    python encoder_decoder.py hash md5 "password"
"""

import sys
import argparse
import base64
import binascii
import hashlib
import html
import codecs
from urllib.parse import quote, unquote

from rich.console import Console
from rich.panel import Panel

console = Console()


# ─── Encoders ────────────────────────────────────────────────

def encode_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def decode_base64(text: str) -> str:
    missing = len(text) % 4
    if missing:
        text += "=" * (4 - missing)
    return base64.b64decode(text).decode(errors="replace")

def encode_hex(text: str) -> str:
    return text.encode().hex()

def decode_hex(text: str) -> str:
    return bytes.fromhex(text.replace(" ", "")).decode(errors="replace")

def encode_url(text: str) -> str:
    return quote(text, safe="")

def decode_url(text: str) -> str:
    return unquote(text)

def encode_url_double(text: str) -> str:
    return quote(quote(text, safe=""), safe="")

def encode_rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")

def encode_html(text: str) -> str:
    return html.escape(text)

def decode_html(text: str) -> str:
    return html.unescape(text)

def encode_binary(text: str) -> str:
    return " ".join(format(ord(c), "08b") for c in text)

def decode_binary(text: str) -> str:
    bits = text.split()
    return "".join(chr(int(b, 2)) for b in bits)

def encode_base32(text: str) -> str:
    return base64.b32encode(text.encode()).decode()

def decode_base32(text: str) -> str:
    missing = len(text) % 8
    if missing:
        text += "=" * (8 - missing)
    return base64.b32decode(text.upper()).decode(errors="replace")

# ─── Hashing ─────────────────────────────────────────────────

_HASHERS = {
    "md5":    lambda t: hashlib.md5(t.encode()).hexdigest(),
    "sha1":   lambda t: hashlib.sha1(t.encode()).hexdigest(),
    "sha256": lambda t: hashlib.sha256(t.encode()).hexdigest(),
    "sha512": lambda t: hashlib.sha512(t.encode()).hexdigest(),
    "sha3":   lambda t: hashlib.sha3_256(t.encode()).hexdigest(),
}

# ─── Dispatch table ──────────────────────────────────────────

ENCODERS = {
    "base64":      (encode_base64, decode_base64),
    "hex":         (encode_hex,    decode_hex),
    "url":         (encode_url,    decode_url),
    "url2":        (encode_url_double, None),
    "rot13":       (encode_rot13,  encode_rot13),   # ROT13 is its own inverse
    "html":        (encode_html,   decode_html),
    "binary":      (encode_binary, decode_binary),
    "base32":      (encode_base32, decode_base32),
}


# ─── CLI ─────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description="Multi-format Encode/Decode/Hash Utility")
    p.add_argument("operation", choices=["encode", "decode", "hash", "all"],
                   help="Operation to perform")
    p.add_argument("format",   nargs="?", default=None,
                   help="Format: base64, hex, url, url2, rot13, html, binary, base32 | Hash: md5, sha1, sha256, sha512, sha3")
    p.add_argument("text",     nargs="?", help="Text to process (or pipe via stdin)")
    args = p.parse_args()

    # Accept piped input
    if args.text:
        text = args.text
    elif not sys.stdin.isatty():
        text = sys.stdin.read().rstrip("\n")
    else:
        console.print("[red]❌ Provide text as argument or pipe it in.[/red]")
        sys.exit(1)

    # ── All-encodings mode ────────────────────────────────────
    if args.operation == "all":
        console.print(Panel(f"[bold]Input:[/bold] {text}", border_style="cyan"))
        for name, (enc, dec) in ENCODERS.items():
            try:
                result = enc(text)
                console.print(f"  [bold cyan]{name:12}[/bold cyan] encode → [green]{result}[/green]")
            except Exception as e:
                console.print(f"  [bold cyan]{name:12}[/bold cyan] [red]error: {e}[/red]")
        for name, fn in _HASHERS.items():
            console.print(f"  [bold yellow]{name:12}[/bold yellow] hash   → [yellow]{fn(text)}[/yellow]")
        return

    # ── Hash mode ─────────────────────────────────────────────
    if args.operation == "hash":
        fmt = (args.format or "sha256").lower()
        if fmt not in _HASHERS:
            console.print(f"[red]Unknown hash: {fmt}. Choose: {', '.join(_HASHERS)}[/red]")
            sys.exit(1)
        result = _HASHERS[fmt](text)
        console.print(f"[bold]{fmt.upper()}[/bold] → [yellow]{result}[/yellow]")
        return

    # ── Encode/Decode ─────────────────────────────────────────
    fmt = (args.format or "base64").lower()
    if fmt not in ENCODERS:
        console.print(f"[red]Unknown format: {fmt}. Choose: {', '.join(ENCODERS)}[/red]")
        sys.exit(1)

    enc_fn, dec_fn = ENCODERS[fmt]

    if args.operation == "encode":
        result = enc_fn(text)
        console.print(f"[bold]{fmt} encode[/bold] → [green]{result}[/green]")
    elif args.operation == "decode":
        if dec_fn is None:
            console.print(f"[red]{fmt} does not support decoding.[/red]")
            sys.exit(1)
        result = dec_fn(text)
        console.print(f"[bold]{fmt} decode[/bold] → [green]{result}[/green]")


if __name__ == "__main__":
    main()
