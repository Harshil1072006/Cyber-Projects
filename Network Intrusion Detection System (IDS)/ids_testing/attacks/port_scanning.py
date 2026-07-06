"""
Port Scanning Simulation.
Simulates TCP SYN scans and connect scans.
"""

from typing import Dict, Any, List
from scapy.all import IP, TCP, send # type: ignore

from .base_attack import BaseAttack

class PortScanning(BaseAttack):
    """Simulates port scanning techniques."""

    def build_packets(self, parameters: Dict[str, Any]) -> Any:
        """
        Builds port scan packets.
        
        Args:
            parameters: Can contain 'ports', 'scan_type'
        """
        target_ip = parameters.get("target_ip", self.config.network.target_ip)
        ports: List[int] = parameters.get("ports", [21, 22, 23, 80, 443, 3306, 8080])
        scan_type = parameters.get("scan_type", "SYN")

        self.logger.debug(f"Building {scan_type} scan packets targeting {target_ip} on ports {ports}")
        
        # 'S' is SYN flag
        flags = "S" if scan_type == "SYN" else "S"
        
        packets = []
        for dport in ports:
            packet = IP(dst=target_ip) / TCP(dport=dport, flags=flags)
            packets.append(packet)
            
        return packets

    def send_packets(self, packets: Any, parameters: Dict[str, Any]) -> None:
        """Override to add some basic inter-packet delay to avoid overwhelming simple filters unless configured to."""
        inter_delay = parameters.get("delay", 0.05)
        interface = self.config.network.interface
        
        self.logger.info(f"Sending port scan packets with {inter_delay}s delay on {interface}")
        send(packets, iface=interface, inter=inter_delay, verbose=False)
