"""
Protocol Anomaly Simulation.
Generates packets with malformed headers or invalid states to test IDS protocol parsing engines.
"""

from typing import Dict, Any, List
import random
from scapy.all import IP, TCP, UDP, Raw, send # type: ignore

from .base_attack import BaseAttack

class ProtocolAnomaly(BaseAttack):
    """Simulates protocol anomalies and malformed packets."""

    def build_packets(self, parameters: Dict[str, Any]) -> Any:
        """
        Builds anomaly packets.
        
        Args:
            parameters: Can contain 'anomaly_type'
        """
        target_ip = parameters.get("target_ip", self.config.network.target_ip)
        anomaly_type = parameters.get("anomaly_type", "BAD_TCP_FLAGS").upper()
        
        self.logger.debug(f"Building anomaly packet type: {anomaly_type}")
        
        packets = []
        sport = random.randint(1024, 65535)
        
        if anomaly_type == "BAD_TCP_FLAGS":
            # SYN and FIN set together (impossible state, commonly dropped or flagged)
            packet = IP(dst=target_ip) / TCP(sport=sport, dport=80, flags="SF")
        elif anomaly_type == "BAD_CHECKSUM":
            # Intentionally corrupt checksum (Scapy calculates automatically, so we disable it)
            packet = IP(dst=target_ip) / TCP(sport=sport, dport=80, chksum=0x1234)
        elif anomaly_type == "OVERSIZED_ICMP":
            # Ping of death simulation (oversized packet)
            # Not fully realistic without fragmentation logic, but enough for some basic rules
            from scapy.all import ICMP # type: ignore
            packet = IP(dst=target_ip) / ICMP() / Raw(load=b"X" * 65500)
        else:
            self.logger.warning(f"Unknown anomaly type {anomaly_type}")
            packet = IP(dst=target_ip) / TCP(sport=sport, dport=80, flags="SF")
            
        packets.append(packet)
            
        return packets

    def send_packets(self, packets: Any, parameters: Dict[str, Any]) -> None:
        """Standard sending mechanism."""
        interface = self.config.network.interface
        self.logger.info(f"Sending anomalous packets on {interface}")
        send(packets, iface=interface, verbose=False)
