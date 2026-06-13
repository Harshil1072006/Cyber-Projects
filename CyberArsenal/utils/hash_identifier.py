"""
hash_identifier.py — Hash Type Identifier
Identifies the likely algorithm behind a given hash string by its length and character set.

Usage:
    python hash_identifier.py 5f4dcc3b5aa765d61d8327deb882cf99
    python hash_identifier.py --file hashes.txt
"""

import sys
import re
import argparse
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()


# ─── Hash Pattern Database ───────────────────────────────────

HASH_SIGNATURES = [
    # Format: (name, bit_length, regex_pattern, notes)
    ("MD5",              128, r"^[a-f0-9]{32}$",                      "Very common, easily cracked"),
    ("MD5 (uppercase)",  128, r"^[A-F0-9]{32}$",                      "Uppercase MD5"),
    ("SHA-1",            160, r"^[a-f0-9]{40}$",                      "Common but deprecated"),
    ("SHA-224",          224, r"^[a-f0-9]{56}$",                      "SHA-2 family"),
    ("SHA-256",          256, r"^[a-f0-9]{64}$",                      "Widely used, secure"),
    ("SHA-384",          384, r"^[a-f0-9]{96}$",                      "SHA-2 family"),
    ("SHA-512",          512, r"^[a-f0-9]{128}$",                     "SHA-2 family, very strong"),
    ("SHA3-256",         256, r"^[a-f0-9]{64}$",                      "Possible SHA3-256 (same length as SHA-256)"),
    ("SHA3-512",         512, r"^[a-f0-9]{128}$",                     "Possible SHA3-512 (same length as SHA-512)"),
    ("NTLM",             128, r"^[a-f0-9]{32}$",                      "Windows NTLM hash"),
    ("MySQL 3.x",        48,  r"^[a-f0-9]{16}$",                      "Old MySQL password hash"),
    ("MySQL 4.1+",       160, r"^\*[A-F0-9]{40}$",                    "MySQL 4.1+ password hash"),
    ("bcrypt",           None,r"^\$2[abxy]\$\d{2}\$.{53}$",           "bcrypt — very strong"),
    ("Argon2",           None,r"^\$argon2",                            "Argon2 — winner of PHC"),
    ("scrypt",           None,r"^\$s0\$",                              "scrypt"),
    ("MD5 Crypt (Unix)", None,r"^\$1\$.{0,8}\$.+",                    "Unix MD5-crypt"),
    ("SHA-256 Crypt",    None,r"^\$5\$.+",                            "Unix SHA-256-crypt"),
    ("SHA-512 Crypt",    None,r"^\$6\$.+",                            "Unix SHA-512-crypt"),
    ("PBKDF2 SHA-256",   None,r"^pbkdf2_sha256\$",                    "Django / PBKDF2"),
    ("CRC32",            32,  r"^[a-f0-9]{8}$",                       "CRC32 checksum"),
    ("Adler-32",         32,  r"^[a-f0-9]{8}$",                       "Possible Adler-32"),
    ("MD4",              128, r"^[a-f0-9]{32}$",                      "MD4 (very weak, used in NTLM)"),
    ("RIPEMD-128",       128, r"^[a-f0-9]{32}$",                      "RIPEMD-128"),
    ("RIPEMD-160",       160, r"^[a-f0-9]{40}$",                      "RIPEMD-160"),
    ("Whirlpool",        512, r"^[a-f0-9]{128}$",                     "Whirlpool"),
    ("Base64",           None,r"^[A-Za-z0-9+/]+=*$",                  "Possibly Base64-encoded (not a hash)"),
    ("LM Hash",          128, r"^[A-F0-9]{32}$",                      "Windows LM Hash (very weak)"),
]


def identify_hash(hash_str: str) -> list[dict]:
    """Identify possible hash types for a given hash string."""
    hash_str = hash_str.strip()
    matches = []
    for name, bits, pattern, notes in HASH_SIGNATURES:
        if re.match(pattern, hash_str, re.IGNORECASE):
            matches.append({
                "name":  name,
                "bits":  str(bits) if bits else "variable",
                "notes": notes,
            })
    return matches


def print_results(hash_str: str, matches: list[dict]) -> None:
    console.print(f"\n[bold]Hash:[/bold] [cyan]{hash_str}[/cyan]")
    console.print(f"[dim]Length: {len(hash_str)} characters[/dim]\n")

    if not matches:
        console.print("[red]❌ No matching hash type found.[/red]")
        return

    table = Table(title="Possible Hash Types", box=box.ROUNDED, border_style="cyan")
    table.add_column("Algorithm",   style="bold cyan", min_width=20)
    table.add_column("Bit Length",  style="green",     min_width=12)
    table.add_column("Notes",       style="dim",       overflow="fold")
    for m in matches:
        table.add_row(m["name"], m["bits"], m["notes"])
    console.print(table)


def main() -> None:
    p = argparse.ArgumentParser(description="Hash Type Identifier")
    p.add_argument("hash",    nargs="?", help="Hash string to identify")
    p.add_argument("--file",  help="File with one hash per line")
    args = p.parse_args()

    if args.file:
        try:
            with open(args.file) as f:
                hashes = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            console.print(f"[red]File not found: {args.file}[/red]")
            sys.exit(1)
        for h in hashes:
            matches = identify_hash(h)
            print_results(h, matches)
            console.print()
    elif args.hash:
        matches = identify_hash(args.hash)
        print_results(args.hash, matches)
    elif not sys.stdin.isatty():
        h = sys.stdin.read().strip()
        matches = identify_hash(h)
        print_results(h, matches)
    else:
        p.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
