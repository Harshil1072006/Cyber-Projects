"""
packet_parser.py — Protocol Decoder
Parses raw Scapy packets into structured, human-readable dictionaries.
"""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime


@dataclass
class ParsedPacket:
    """A structured representation of a captured network packet."""
    timestamp:    str
    protocol:     str          # TCP, UDP, ICMP, ARP, DNS, OTHER
    src_ip:       Optional[str] = None
    dst_ip:       Optional[str] = None
    src_mac:      Optional[str] = None
    dst_mac:      Optional[str] = None
    src_port:     Optional[int] = None
    dst_port:     Optional[int] = None
    flags:        Optional[str] = None   # TCP flags: S, A, F, R, P, U
    payload:      bytes = field(default_factory=lambda: b"")
    payload_text: str = ""
    size:         int = 0
    # ARP-specific
    arp_op:       Optional[str] = None
    arp_src_ip:   Optional[str] = None
    arp_dst_ip:   Optional[str] = None
    arp_src_mac:  Optional[str] = None
    # DNS-specific
    dns_query:    Optional[str] = None
    dns_type:     Optional[str] = None
    # ICMP-specific
    icmp_type:    Optional[int] = None
    icmp_code:    Optional[int] = None


def parse_packet(pkt) -> Optional[ParsedPacket]:
    """
    Parse a raw Scapy packet into a ParsedPacket.
    Returns None if the packet cannot be decoded.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.l2 import Ether, ARP
        from scapy.layers.dns import DNS, DNSQR

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        size = len(pkt)

        # ── Ethernet header ──────────────────────────────────
        src_mac = dst_mac = None
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        # ── ARP ──────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            op = "request" if arp.op == 1 else "reply"
            return ParsedPacket(
                timestamp=ts,
                protocol="ARP",
                src_mac=arp.hwsrc,
                dst_mac=arp.hwdst,
                arp_op=op,
                arp_src_ip=arp.psrc,
                arp_dst_ip=arp.pdst,
                arp_src_mac=arp.hwsrc,
                size=size,
            )

        # ── IP layer ─────────────────────────────────────────
        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        # ── DNS ──────────────────────────────────────────────
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
            qtype = pkt[DNSQR].qtype
            type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 2: "NS"}
            return ParsedPacket(
                timestamp=ts,
                protocol="DNS",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=pkt[UDP].sport if pkt.haslayer(UDP) else None,
                dst_port=pkt[UDP].dport if pkt.haslayer(UDP) else None,
                dns_query=query,
                dns_type=type_map.get(qtype, str(qtype)),
                size=size,
            )

        # ── ICMP ─────────────────────────────────────────────
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            return ParsedPacket(
                timestamp=ts,
                protocol="ICMP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac=src_mac,
                dst_mac=dst_mac,
                icmp_type=icmp.type,
                icmp_code=icmp.code,
                size=size,
            )

        # ── TCP ──────────────────────────────────────────────
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            flags = _decode_tcp_flags(tcp.flags)
            raw_payload = bytes(tcp.payload)
            payload_text = _safe_decode(raw_payload)
            return ParsedPacket(
                timestamp=ts,
                protocol="TCP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                flags=flags,
                payload=raw_payload,
                payload_text=payload_text,
                size=size,
            )

        # ── UDP ──────────────────────────────────────────────
        if pkt.haslayer(UDP):
            udp = pkt[UDP]
            raw_payload = bytes(udp.payload)
            payload_text = _safe_decode(raw_payload)
            return ParsedPacket(
                timestamp=ts,
                protocol="UDP",
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_port=udp.sport,
                dst_port=udp.dport,
                payload=raw_payload,
                payload_text=payload_text,
                size=size,
            )

        return None

    except Exception:
        return None


def _decode_tcp_flags(flags) -> str:
    """Decode numeric TCP flags into a human-readable string."""
    flag_map = {
        0x01: "F",  # FIN
        0x02: "S",  # SYN
        0x04: "R",  # RST
        0x08: "P",  # PSH
        0x10: "A",  # ACK
        0x20: "U",  # URG
    }
    # Scapy uses a FlagValue object — safely cast to int
    try:
        flag_int = int(flags)
    except (TypeError, ValueError):
        return "."
    result = ""
    for bit, char in flag_map.items():
        if flag_int & bit:
            result += char
    return result or "."


def _safe_decode(data: bytes, max_len: int = 512) -> str:
    """Safely decode bytes to a printable string."""
    try:
        return data[:max_len].decode("utf-8", errors="replace")
    except Exception:
        return repr(data[:max_len])
